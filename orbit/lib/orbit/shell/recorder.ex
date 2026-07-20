defmodule Orbit.Shell.Recorder do
  @moduledoc """
  Optional recording of a root-terminal session to an asciicast v2 file
  (`DASH_SHELL_RECORD_DIR`), the last piece of the terminal hardening the
  retired dashboard shipped and orbit had not carried over.

  Off unless the directory is configured. When it is, every shell session
  writes one file named after the instance, the operator and the start time,
  replayable with `asciinema play`.

  ## What is recorded, and what deliberately is not

  **PTY output only** — never keystrokes. An operator types passwords, sudo
  prompts and API tokens into this socket, and the terminal does not echo
  them; recording input would create a plaintext password log on the
  dashboard host, which is a worse problem than the one recording solves.
  Output is what a shoulder-surfer would have seen anyway, and it still
  contains every command (the shell echoes it) and every result.

  Two consequences of that choice worth knowing when reading a recording:
  a password typed at a prompt is absent (correct), and so is a command the
  shell chose not to echo.

  ## Caps

  A session that runs `cat /dev/urandom` must not fill the disk, so a byte
  cap applies per session; once reached the file is closed with a note and
  the session continues unrecorded. Failures never touch the session — a
  full disk closes the recording, not the operator's shell.
  """

  require Logger

  @cap_bytes 8 * 1024 * 1024

  defstruct [:io, :started_at, written: 0, capped: false]

  @type t :: %__MODULE__{} | nil

  @doc """
  Delete recordings older than the configured retention, and report how many.

  Recordings are the only thing orbit writes that is not a database row, so
  nothing pruned them: a busy fleet with recording enabled filled its volume
  with .cast files forever. Deliberately conservative about WHAT it deletes —
  only files matching the name this module writes, only inside the configured
  directory, and it never follows the directory anywhere else.

  Returns `{deleted, failed}`. Never raises: a scheduled cleanup that cannot
  read a directory logs and moves on.
  """
  @spec prune() :: {non_neg_integer(), non_neg_integer()}
  def prune do
    with recdir when is_binary(recdir) <- dir(),
         {:ok, names} <- File.ls(recdir) do
      days = Orbit.Settings.effective("shell_recording_retention_days")
      cutoff = System.os_time(:second) - days * 86_400

      {deleted, failed} =
        names
        |> Enum.filter(&recording?/1)
        |> Enum.reduce({0, 0}, fn name, {ok, bad} ->
          path = Path.join(recdir, name)

          case stale?(path, cutoff) and File.rm(path) == :ok do
            true -> {ok + 1, bad}
            false -> {ok, bad}
          end
        end)

      if deleted > 0, do: Logger.info("shell.recordings_pruned deleted=#{deleted} days=#{days}")
      {deleted, failed}
    else
      nil ->
        {0, 0}

      {:error, reason} ->
        Logger.warning("shell.recording_prune_failed error=#{inspect(reason)}")
        {0, 0}
    end
  rescue
    error ->
      Logger.warning("shell.recording_prune_failed error=#{Exception.message(error)}")
      {0, 0}
  end

  # Only our own files: a misconfigured directory pointing at something else
  # must not turn a retention job into a delete-everything job.
  defp recording?(name),
    do: String.starts_with?(name, "orbit-") and String.ends_with?(name, ".cast")

  defp stale?(path, cutoff) do
    case File.stat(path, time: :posix) do
      {:ok, %{mtime: mtime}} -> mtime < cutoff
      _ -> false
    end
  end

  @doc "Configured recording directory, or nil when the feature is off."
  @spec dir() :: String.t() | nil
  def dir do
    case Application.get_env(:orbit, :shell_record_dir, "") do
      d when is_binary(d) and d != "" -> d
      _ -> nil
    end
  end

  @doc """
  Open a recording for one session, or return nil when the feature is off or
  the file cannot be created. Never raises: recording is an extra, and the
  shell must open either way.
  """
  @spec open(integer(), integer() | nil, String.t()) :: t()
  def open(instance_id, user_id, kind) do
    with recdir when is_binary(recdir) <- dir(),
         :ok <- File.mkdir_p(recdir),
         path = Path.join(recdir, filename(instance_id, user_id, kind)),
         {:ok, io} <- File.open(path, [:write, :binary]) do
      started = DateTime.utc_now()

      header =
        Jason.encode!(%{
          version: 2,
          width: 80,
          height: 24,
          timestamp: DateTime.to_unix(started),
          title: "orbit instance #{instance_id} user #{user_id || "-"}",
          env: %{"TERM" => "xterm-256color"}
        })

      IO.binwrite(io, [header, "\n"])
      Logger.info("shell.record_started instance_id=#{instance_id} path=#{path}")
      %__MODULE__{io: io, started_at: started}
    else
      nil ->
        nil

      other ->
        Logger.warning(
          "shell.record_open_failed instance_id=#{instance_id} error=#{inspect(other)}"
        )

        nil
    end
  end

  @doc """
  Append PTY output. Returns the (possibly capped) recorder.

  Only ever called with bytes coming FROM the box — see the module note on
  why keystrokes are not recorded.
  """
  @spec write(t(), binary()) :: t()
  def write(nil, _bytes), do: nil
  def write(%__MODULE__{capped: true} = rec, _bytes), do: rec

  def write(%__MODULE__{} = rec, bytes) when is_binary(bytes) do
    if rec.written + byte_size(bytes) > @cap_bytes do
      note(
        rec,
        "\r\n[orbit: recording stopped, #{div(@cap_bytes, 1024 * 1024)} MB cap reached]\r\n"
      )

      close_io(rec)
      %{rec | capped: true, io: nil}
    else
      event(rec, bytes)
      %{rec | written: rec.written + byte_size(bytes)}
    end
  end

  def write(rec, _bytes), do: rec

  @doc "Flush and close. Safe on nil and on an already-capped recording."
  @spec close(t()) :: :ok
  def close(nil), do: :ok
  def close(%__MODULE__{io: nil}), do: :ok

  def close(%__MODULE__{} = rec) do
    close_io(rec)
    :ok
  end

  defp event(%__MODULE__{io: io, started_at: started}, bytes) do
    elapsed = DateTime.diff(DateTime.utc_now(), started, :millisecond) / 1000
    line = Jason.encode!([Float.round(elapsed, 3), "o", safe_utf8(bytes)])
    IO.binwrite(io, [line, "\n"])
  rescue
    _ -> :ok
  end

  defp note(rec, text), do: event(rec, text)

  defp close_io(%__MODULE__{io: io}) when not is_nil(io) do
    File.close(io)
  rescue
    _ -> :ok
  end

  defp close_io(_), do: :ok

  # asciicast events are JSON strings, so the payload must be valid UTF-8. A
  # PTY emits raw bytes and a multi-byte character can be split across two
  # frames, which would make Jason raise mid-session and lose the recording.
  defp safe_utf8(bytes) do
    if String.valid?(bytes), do: bytes, else: scrub(bytes)
  end

  defp scrub(bytes) do
    for <<b <- bytes>>, into: "" do
      if b < 0x80, do: <<b>>, else: "�"
    end
  end

  defp filename(instance_id, user_id, kind) do
    stamp = DateTime.utc_now() |> DateTime.to_iso8601(:basic) |> String.replace(~r/[^0-9TZ]/, "")
    "orbit-#{kind}-i#{instance_id}-u#{user_id || 0}-#{stamp}.cast"
  end
end
