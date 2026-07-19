defmodule Orbit.ConfigBackup.Store do
  @moduledoc """
  Persist agent-pushed config-backup snapshots, Fernet-encrypted at rest, keeping
  the newest `keep_per_instance/0` per instance. Mirror of
  backend/src/app/configbackup/store.py.

  `decode_payload/1` is pure and unit-tested; the DB path (encrypt + dedup +
  prune) is verified live (the test DB is schemaless under the Alembic monopoly).
  """

  import Ecto.Query

  alias Orbit.ConfigBackup.Backup
  alias Orbit.Repo

  @keep_per_instance 30
  @max_bytes 8_000_000

  @doc "Newest-versions-per-instance retention window."
  def keep_per_instance, do: @keep_per_instance

  @doc """
  Validate an agent config push into `{:ok, {sha256, xml_text}}`. Rejects a
  non-dict, missing/blank fields, bad base64, over-cap or corrupt gzip, and
  content whose sha256 doesn't match the agent's claim (truncated transfer).
  """
  @spec decode_payload(term()) :: {:ok, {String.t(), binary()}} | :error
  def decode_payload(%{"content_gz_b64" => b64, "sha256" => claimed})
      when is_binary(b64) and is_binary(claimed) and b64 != "" and claimed != "" do
    with {:ok, gz} <- Base.decode64(b64),
         {:ok, raw} <- gunzip_capped(gz),
         ^claimed <- Base.encode16(:crypto.hash(:sha256, raw), case: :lower) do
      {:ok, {claimed, raw}}
    else
      _ -> :error
    end
  end

  def decode_payload(_), do: :error

  # Post-gunzip length cap. A streaming cap (reject before full inflate) is a
  # documented hardening seam; the agent is signed + trusted and this runs off
  # the hub loop in a Task.
  defp gunzip_capped(gz) do
    raw = :zlib.gunzip(gz)
    if byte_size(raw) > @max_bytes, do: :error, else: {:ok, raw}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @doc """
  Store one pushed config version, deduped against the newest stored sha.
  Returns true when a new version row was created.
  """
  @spec record(integer(), term(), String.t()) :: boolean()
  def record(instance_id, payload, source \\ "agent") do
    with {:ok, {sha, text}} <- decode_payload(payload),
         false <- latest_sha(instance_id) == sha do
      Repo.insert!(%Backup{
        instance_id: instance_id,
        sha256: sha,
        bytes: byte_size(text),
        source: source,
        content_enc: Orbit.Crypto.encrypt(text),
        collected_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

      prune(instance_id)
      true
    else
      _ -> false
    end
  end

  defp prune(instance_id) do
    ids =
      Repo.all(
        from(b in Backup,
          where: b.instance_id == ^instance_id,
          order_by: [desc: b.collected_at, desc: b.id],
          select: b.id
        )
      )

    case Enum.drop(ids, @keep_per_instance) do
      [] -> :ok
      extra -> Repo.delete_all(from(b in Backup, where: b.id in ^extra))
    end
  end

  @doc "Newest stored sha for an instance, or nil."
  @spec latest_sha(integer()) :: String.t() | nil
  def latest_sha(instance_id) do
    Repo.one(
      from(b in Backup,
        where: b.instance_id == ^instance_id,
        order_by: [desc: b.collected_at, desc: b.id],
        limit: 1,
        select: b.sha256
      )
    )
  end

  @doc "Version metadata for an instance, newest-first (no content)."
  @spec list(integer()) :: [map()]
  def list(instance_id) do
    Repo.all(
      from(b in Backup,
        where: b.instance_id == ^instance_id,
        order_by: [desc: b.collected_at, desc: b.id],
        select: %{
          id: b.id,
          collected_at: b.collected_at,
          sha256: b.sha256,
          bytes: b.bytes,
          source: b.source
        }
      )
    )
  end

  @diff_max_lines 4000
  @diff_max_input_lines 150_000

  @doc """
  Line diff of one version against the chronologically previous one for the same
  instance. `{:ok, text, truncated?}` when both exist, `:no_previous` when the
  version is the oldest, `:error` when a version is missing/undecryptable.

  CPU-bound (Myers is ~O(n*m) on line counts) — callers run it off the loop.
  """
  @spec diff_against_previous(integer(), integer()) ::
          {:ok, String.t(), boolean()} | :no_previous | :error
  def diff_against_previous(instance_id, backup_id) do
    prev_id =
      Repo.one(
        from(b in Backup,
          where: b.instance_id == ^instance_id and b.id < ^backup_id,
          order_by: [desc: b.id],
          limit: 1,
          select: b.id
        )
      )

    cond do
      is_nil(prev_id) -> :no_previous
      true -> do_diff(get_content(instance_id, prev_id), get_content(instance_id, backup_id))
    end
  end

  @doc "Diff two arbitrary stored versions (inline viewer). Same bounds as above."
  def diff_between(instance_id, id_a, id_b) do
    do_diff(get_content(instance_id, id_a), get_content(instance_id, id_b))
  end

  defp do_diff(a, b) when is_binary(a) and is_binary(b) do
    a_lines = String.split(a, "\n")
    b_lines = String.split(b, "\n")

    if max(length(a_lines), length(b_lines)) > @diff_max_input_lines do
      {:ok, "(versions too large to diff — download both and compare locally)", true}
    else
      lines =
        a_lines
        |> List.myers_difference(b_lines)
        |> Enum.flat_map(&diff_chunk/1)

      {kept, truncated} = Enum.split(lines, @diff_max_lines)
      {:ok, Enum.join(kept, "\n"), truncated != []}
    end
  end

  defp do_diff(_, _), do: :error

  defp diff_chunk({:eq, _lines}), do: []
  defp diff_chunk({:del, lines}), do: Enum.map(lines, &("-" <> &1))
  defp diff_chunk({:ins, lines}), do: Enum.map(lines, &("+" <> &1))

  @doc "Decrypted XML for one version (scoped to the instance), or nil."
  @spec get_content(integer(), integer()) :: String.t() | nil
  def get_content(instance_id, id) do
    enc =
      Repo.one(
        from(b in Backup,
          where: b.instance_id == ^instance_id and b.id == ^id,
          select: b.content_enc
        )
      )

    case enc && Orbit.Crypto.decrypt(enc) do
      {:ok, text} -> text
      _ -> nil
    end
  end
end
