defmodule OrbitWeb.AuditLive do
  @moduledoc """
  Audit-log viewer (admin-only) — the read side of the audit trail. Shows the
  most recent audit_log rows (action, result, actor, target, ip, time) with a
  colour-coded result. Read-only forensic surface; the alembic-owned table is
  queried directly.

  Gate is on_mount(:require_admin) (audit is admin/superadmin in the python
  app; superadmin rights-management viewing lands with the users surface).
  """

  use OrbitWeb, :live_view

  @limit 100

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, rows: load_rows())}
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    {:noreply, assign(socket, rows: load_rows())}
  end

  defp load_rows do
    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT ts, action, result, user_id, target_type, target_id, source_ip " <>
          "FROM audit_log ORDER BY id DESC LIMIT #{@limit}"
      )

    for [ts, action, result, user_id, ttype, tid, ip] <- rows do
      %{
        ts: ts,
        action: action,
        result: result,
        user_id: user_id,
        target: target(ttype, tid),
        ip: ip
      }
    end
  end

  defp target(nil, _), do: "—"
  defp target(t, nil), do: t
  defp target(t, id), do: "#{t}:#{id}"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <nav class="flex gap-3 text-sm text-slate-400">
            <a href={~p"/instances"} class="hover:text-slate-200">Instances</a>
            <a href={~p"/settings"} class="hover:text-slate-200">Settings</a>
            <a href={~p"/audit"} class="text-slate-200">Audit</a>
          </nav>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">Audit log</h1>
          <button
            phx-click="refresh"
            class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
          >
            Refresh
          </button>
          <span class="text-sm text-slate-500">last {length(@rows)}</span>
        </div>

        <table class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Time (UTC)</th>
              <th class="py-2 pr-4 font-medium">Action</th>
              <th class="py-2 pr-4 font-medium">Result</th>
              <th class="py-2 pr-4 font-medium">User</th>
              <th class="py-2 pr-4 font-medium">Target</th>
              <th class="py-2 pr-4 font-medium">IP</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4 font-mono text-xs text-slate-500">{fmt_ts(r.ts)}</td>
              <td class="py-2 pr-4 text-slate-300">{r.action}</td>
              <td class="py-2 pr-4">
                <span class={["rounded px-1.5 py-0.5 text-xs", result_class(r.result)]}>
                  {r.result}
                </span>
              </td>
              <td class="py-2 pr-4 text-slate-400">{r.user_id || "—"}</td>
              <td class="py-2 pr-4 text-slate-400">{r.target}</td>
              <td class="py-2 pr-4 text-slate-500">{r.ip || "—"}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp fmt_ts(%NaiveDateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(%DateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(other), do: to_string(other)

  defp result_class("ok"), do: "bg-emerald-900/50 text-emerald-300"
  defp result_class("pending"), do: "bg-slate-700 text-slate-300"
  defp result_class("denied"), do: "bg-red-900/60 text-red-300"
  defp result_class(_), do: "bg-amber-900/50 text-amber-300"
end
