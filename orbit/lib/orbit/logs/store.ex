defmodule Orbit.Logs.Store do
  @moduledoc """
  Persist + prune agent-pushed logfile snapshots and refresh the extracted
  critical events. Mirror of backend/src/app/logs/store.py.

  Only the newest `keep_per_name/0` snapshots per (instance_id, name) survive a
  write. The pure helpers (`clamp/1`, `sanitize/1`, `surplus/1`) carry the logic
  and are unit-tested; the DB path is verified live (the test DB is schemaless
  under the Alembic monopoly).
  """

  import Ecto.Query

  alias Orbit.Logs.{Events, LogEvent, Logfile}
  alias Orbit.Repo

  @keep_per_name 3
  @max_bytes 1_000_000
  @name_max 64

  @doc "Newest-snapshots-per-name retention window."
  def keep_per_name, do: @keep_per_name

  @doc "Keep only the last `max` characters (newest log lines)."
  @spec clamp(String.t(), pos_integer()) :: String.t()
  def clamp(content, max \\ @max_bytes) do
    if String.length(content) > max, do: String.slice(content, -max, max), else: content
  end

  @doc "Clean an agent `logfiles` payload into `{name, content}` pairs (drop empty)."
  @spec sanitize([map()]) :: [{String.t(), String.t()}]
  def sanitize(raw) when is_list(raw) do
    for entry <- raw,
        name =
          entry
          |> Map.get("name", "")
          |> to_string()
          |> String.trim()
          |> String.slice(0, @name_max),
        content = to_string(Map.get(entry, "content", "")),
        name != "" and content != "" do
      {name, clamp(content)}
    end
  end

  def sanitize(_), do: []

  @doc "Given ids newest-first, the ones beyond the keep window (to delete)."
  @spec surplus([integer()], pos_integer()) :: [integer()]
  def surplus(ordered_ids, keep \\ @keep_per_name), do: Enum.drop(ordered_ids, keep)

  @doc """
  Insert pushed snapshots, prune each touched name to the keep window, and
  refresh the extracted events. Returns the number of stored snapshots.
  """
  @spec ingest(integer(), [map()]) :: non_neg_integer()
  def ingest(instance_id, raw) do
    case sanitize(raw) do
      [] ->
        0

      pairs ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        Enum.each(pairs, fn {name, content} ->
          Repo.insert!(%Logfile{
            instance_id: instance_id,
            name: name,
            bytes: String.length(content),
            content: content,
            collected_at: now
          })
        end)

        pairs |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.each(&prune(instance_id, &1))

        Enum.each(pairs, fn {name, content} ->
          replace_events(instance_id, name, Events.extract_events(name, content), now)
        end)

        length(pairs)
    end
  end

  defp prune(instance_id, name) do
    ids =
      Repo.all(
        from(l in Logfile,
          where: l.instance_id == ^instance_id and l.name == ^name,
          order_by: [desc: l.collected_at, desc: l.id],
          select: l.id
        )
      )

    case surplus(ids) do
      [] -> :ok
      extra -> Repo.delete_all(from(l in Logfile, where: l.id in ^extra))
    end
  end

  defp replace_events(instance_id, log_name, events, now) do
    Repo.delete_all(
      from(e in LogEvent, where: e.instance_id == ^instance_id and e.log_name == ^log_name)
    )

    Enum.each(events, fn e ->
      Repo.insert!(%LogEvent{
        instance_id: instance_id,
        log_name: log_name,
        severity: e.severity,
        program: e.program,
        pattern: e.pattern,
        sample: e.sample,
        count: e.count,
        last_ts: e.last_ts,
        updated_at: now
      })
    end)
  end

  @doc "Newest snapshot per name for an instance (metadata; content dropped)."
  @spec latest_per_name(integer()) :: [map()]
  def latest_per_name(instance_id) do
    Repo.all(
      from(l in Logfile,
        where: l.instance_id == ^instance_id,
        order_by: [asc: l.name, desc: l.collected_at, desc: l.id],
        select: %{id: l.id, name: l.name, collected_at: l.collected_at, bytes: l.bytes}
      )
    )
    |> Enum.uniq_by(& &1.name)
  end

  @doc "One snapshot (with content) for an instance, or nil. Scope is the caller's."
  @spec get_logfile(integer(), integer()) :: Logfile.t() | nil
  def get_logfile(instance_id, logfile_id) do
    Repo.one(from(l in Logfile, where: l.instance_id == ^instance_id and l.id == ^logfile_id))
  end

  @doc "All extracted events for an instance, worst-first (severity, then count)."
  @spec list_events(integer()) :: [LogEvent.t()]
  def list_events(instance_id) do
    Repo.all(
      from(e in LogEvent,
        where: e.instance_id == ^instance_id,
        order_by: [asc: e.severity, desc: e.count, asc: e.program]
      )
    )
  end
end
