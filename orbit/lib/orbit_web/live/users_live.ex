defmodule OrbitWeb.UsersLive do
  @moduledoc """
  Superadmin rights-management: read-only overview of every account — role,
  superadmin/bootstrap flags, 2FA state, group memberships, disabled state and
  last successful login (ip/country/when). Mutations (create/role change/
  delete/reset-2fa) reimplement the change-frozen admin-count + bootstrap
  retirement invariants and land in a later, reviewed slice.

  Superadmin-gated via on_mount :require_superadmin (rights management only —
  superadmin has no instance access). No hub/scope needed: this is the account
  table, not instance data.
  """

  use OrbitWeb, :live_view

  alias Orbit.Accounts

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, users: Accounts.list_users())}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:users} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Users <span class="ml-2 text-sm text-slate-500">({length(@users)})</span>
        </h1>

        <table class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">User</th>
              <th class="py-2 pr-4 font-medium">Role</th>
              <th class="py-2 pr-4 font-medium">2FA</th>
              <th class="py-2 pr-4 font-medium">Groups</th>
              <th class="py-2 pr-4 font-medium">Status</th>
              <th class="py-2 pr-4 font-medium">Last login</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={u <- @users} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class="text-slate-200">{u.username}</span>
                <span
                  :if={u.is_superadmin}
                  class="ml-2 rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300"
                >
                  superadmin
                </span>
                <span
                  :if={u.is_bootstrap}
                  class="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400"
                >
                  bootstrap
                </span>
              </td>
              <td class="py-2 pr-4 text-slate-300">{u.role}</td>
              <td class="py-2 pr-4">
                <span class={twofa_class(u.totp_enabled)}>{if u.totp_enabled, do: "on", else: "off"}</span>
              </td>
              <td class="py-2 pr-4 text-slate-400">{groups_text(u.groups)}</td>
              <td class="py-2 pr-4">
                <span
                  :if={u.disabled}
                  class="rounded bg-red-900/60 px-1.5 py-0.5 text-xs text-red-300"
                >
                  disabled
                </span>
                <span :if={not u.disabled} class="text-slate-500">active</span>
              </td>
              <td class="py-2 pr-4 text-slate-400">{last_login_text(u)}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp twofa_class(true), do: "rounded bg-emerald-900/50 px-1.5 py-0.5 text-xs text-emerald-300"
  defp twofa_class(_), do: "rounded bg-amber-900/50 px-1.5 py-0.5 text-xs text-amber-300"

  defp groups_text([]), do: "—"
  defp groups_text(groups), do: groups |> Enum.map(& &1.name) |> Enum.sort() |> Enum.join(", ")

  defp last_login_text(%{last_login_at: nil}), do: "never"

  defp last_login_text(%{last_login_at: at} = u) do
    where =
      [u.last_login_country, u.last_login_ip]
      |> Enum.reject(&(&1 in [nil, ""]))
      |> Enum.join(" · ")

    stamp = Calendar.strftime(at, "%Y-%m-%d %H:%M UTC")
    if where == "", do: stamp, else: "#{stamp} (#{where})"
  end
end
