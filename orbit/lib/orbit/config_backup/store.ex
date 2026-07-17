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
