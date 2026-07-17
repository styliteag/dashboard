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
  @detail_keys ~w(reason username stage lock_triggered name role mode)

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
      detail: fields[:detail],
      source_ip: fields[:source_ip]
    }
  end

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
    detail = fields[:detail] || %{}
    safe = for k <- @detail_keys, v = detail[k], into: %{}, do: {k, v}

    meta =
      [
        result: fields[:result],
        user_id: fields[:user_id],
        target: target(fields),
        ip: fields[:source_ip]
      ]
      |> Enum.reject(fn {_, v} -> is_nil(v) end)
      |> Keyword.merge(Map.to_list(safe))

    msg = "audit #{fields[:action]} #{inspect(meta)}"

    if fields[:result] in ["ok", "pending"], do: Logger.info(msg), else: Logger.warning(msg)

    if detail["lock_triggered"] do
      Logger.warning("auth.ip_blocked ip=#{fields[:source_ip]} username=#{detail["username"]}")
    end
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
