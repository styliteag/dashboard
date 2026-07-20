defmodule Orbit.Audit do
  @moduledoc """
  Audit trail — port of audit/log.py. Every state-changing action writes a
  tamper-evident `audit_log` row AND mirrors a structured `app.audit` log
  line. The DB row is the record; the log line is the observability stream.

  `detail` is caller-defined and may carry payloads that don't belong in a
  log line (settings values, command results) — the LOG line mirrors only
  the allowlisted keys (@detail_keys). The DB row keeps the full detail as
  JSON. Callers must still build `detail` from an allowlist of safe fields
  (invariant 3), never a denylist — extend @detail_keys for new safe fields.

  Schema is Alembic-owned; rows are written here (no ecto migration).
  """

  require Logger

  alias Orbit.Repo

  # Safe-to-log detail keys (mirror of audit/log.py _DETAIL_KEYS).
  # The allowlist. Extend it for new SAFE fields — never widen it to a
  # denylist, and never add anything that could carry key material, a
  # password, a token or raw command output (invariant 3).
  #
  # The instance-edit fields below were lost when this allowlist started
  # governing the stored row and not just the mirrored log line: the list was
  # written for the log line, so an instance.update that used to record every
  # changed field suddenly recorded only {"name": ...} and the audit trail for
  # edits became useless. They are safe by construction — `secrets_rotated`
  # carries the NAMES of rotated secrets and never a value.
  #
  # `notes` is deliberately NOT here even though it used to be logged: it is
  # free operator text that can contain anything somebody chose to paste,
  # which is exactly what an allowlist exists to keep out.
  @detail_keys ~w(reason username stage lock_triggered name role mode kind entity_key comment
    capture_id channel consumer country from_group_id to_group_id interface seconds selector
    uuid version why
    secrets_rotated base_url location ping_url tags slug ssl_verify gui_login_enabled
    shell_enabled ssh_enabled ssh_port ssh_user maintenance firmware_locked
    poll_interval_seconds push_interval_seconds)

  @doc """
  Insert an audit row + emit the mirrored log line. Fields: :action + :result
  required; :user_id, :target_type, :target_id, :source_ip, :detail optional.
  Returns :ok. Auto-commits (single insert) — callers inside a transaction
  should use `insert/1` for same-tx coupling.
  """
  @spec write(keyword()) :: :ok
  def write(fields) do
    row = build_row(fields)
    Repo.query!(insert_sql(), insert_params(row))
    log_line(fields)
    :ok
  end

  @doc """
  Same as write/1 but runs the insert on the given Ecto repo/transaction
  connection via Repo (for audit-before-commit coupling in a transaction).
  The log line is emitted after the insert; a rolled-back tx still logged
  (python parity: the log is a stream, the row is the record).
  """
  @spec insert(keyword()) :: :ok
  def insert(fields), do: write(fields)

  defp build_row(fields) do
    %{
      user_id: fields[:user_id],
      action: fetch!(fields, :action),
      target_type: fields[:target_type],
      target_id: fields[:target_id] && to_string(fields[:target_id]),
      request_id:
        fields[:request_id] || Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
      result: fetch!(fields, :result),
      detail: safe_detail(fields[:detail]),
      source_ip: fields[:source_ip]
    }
  end

  @doc """
  Reduce a detail map to the allowlisted keys.

  Enforced HERE, not left to each caller. Invariant 3 says audit detail is
  built from an allowlist, but until this filter existed that held only by
  caller discipline: `write/1` persisted whatever map it was handed, and the
  allowlist governed only the mirrored log line. One new mutation route
  passing a raw changeset (or a params map carrying `api_secret`,
  `agent_token`, `ssh_private_key`) would have written secrets into a table
  that admins and superadmins can read.

  Anything not on the list is dropped silently — an audit row with a missing
  field is a cosmetic loss; an audit row with a secret is an incident.
  """
  @spec safe_detail(map() | nil) :: map() | nil
  def safe_detail(nil), do: nil

  def safe_detail(detail) when is_map(detail) do
    filtered = Map.take(detail, @detail_keys)

    dropped = map_size(detail) - map_size(filtered)

    if dropped > 0 do
      Logger.debug(
        "audit.detail_filtered dropped=#{dropped} keys=#{inspect(Map.keys(detail) -- @detail_keys)}"
      )
    end

    if map_size(filtered) == 0, do: nil, else: filtered
  end

  # A non-map detail (a bare string from an old caller) carries no key names
  # to check — keep the shape the DB column expects and drop it.
  def safe_detail(_other), do: nil

  defp insert_sql do
    "INSERT INTO audit_log " <>
      "(ts, user_id, action, target_type, target_id, request_id, result, detail, source_ip) " <>
      "VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?)"
  end

  defp insert_params(row) do
    [
      row.user_id,
      row.action,
      row.target_type,
      row.target_id,
      row.request_id,
      row.result,
      row.detail && Jason.encode!(row.detail),
      row.source_ip
    ]
  end

  defp log_line(fields) do
    msg = "audit #{fields[:action]} #{inspect(log_meta(fields))}"

    if fields[:result] in ["ok", "pending"], do: Logger.info(msg), else: Logger.warning(msg)

    detail = fields[:detail] || %{}

    if detail["lock_triggered"] do
      Logger.warning("auth.ip_blocked ip=#{fields[:source_ip]} username=#{detail["username"]}")
    end
  end

  @doc false
  # Structured log fields as a keyword list. @detail_keys are strings (the JSON
  # keys callers pass); the keyword needs ATOM keys, so each allowlisted key is
  # mapped to its atom. Without this, Keyword.merge/2 raised on every audit
  # carrying an allowlisted detail field — the DB row is written first, so the
  # crash surfaced only as a logging failure in the caller process.
  def log_meta(fields) do
    detail = fields[:detail] || %{}
    safe = for k <- @detail_keys, v = detail[k], do: {String.to_atom(k), v}

    [
      result: fields[:result],
      user_id: fields[:user_id],
      target: target(fields),
      ip: fields[:source_ip]
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Keyword.merge(safe)
  end

  defp target(fields) do
    case {fields[:target_type], fields[:target_id]} do
      {nil, _} -> nil
      {t, nil} -> t
      {t, id} -> "#{t}:#{id}"
    end
  end

  defp fetch!(fields, key) do
    fields[key] || raise ArgumentError, "audit write missing #{key}"
  end
end
