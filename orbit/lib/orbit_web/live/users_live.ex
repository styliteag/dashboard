defmodule OrbitWeb.UsersLive do
  @moduledoc """
  Superadmin rights management — read overview PLUS the users/routes.py
  mutations (create, role/superadmin/groups/password update, delete,
  reset-2fa) via Orbit.Accounts.Admin, which carries the python-parity
  guards: never yourself, never the last admin/superadmin, bootstrap seeds
  auto-retire when supplanted. Every mutation audits.

  Superadmin-gated via on_mount :require_superadmin (rights management only
  — superadmin has no instance access).
  """

  use OrbitWeb, :live_view

  alias Orbit.Accounts
  alias Orbit.Accounts.Admin
  alias Orbit.Audit

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(editing: nil, error: nil, show_create: false) |> reload()}
  end

  defp reload(socket) do
    assign(socket, users: Accounts.list_users(), groups: Orbit.Repo.all(Orbit.Accounts.Group))
  end

  @impl true
  def handle_event("toggle_create", _p, socket) do
    {:noreply, assign(socket, show_create: not socket.assigns.show_create, error: nil)}
  end

  def handle_event("edit", %{"id" => raw}, socket) do
    id = String.to_integer(raw)

    {:noreply,
     assign(socket, editing: if(socket.assigns.editing == id, do: nil, else: id), error: nil)}
  end

  def handle_event("create_user", %{"user" => params}, socket) do
    params = Map.put(params, "group_ids", checked_ids(params))

    case Admin.create_user(params) do
      {:ok, user} ->
        audit(socket, "user.create", user.id, %{
          "username" => user.username,
          "role" => user.role,
          "is_superadmin" => user.is_superadmin
        })

        {:noreply, socket |> assign(show_create: false, error: nil) |> reload()}

      {:error, reason} ->
        {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("update_user", %{"user_id" => raw, "user" => params}, socket) do
    params = Map.put(params, "group_ids", checked_ids(params))

    with %Accounts.User{} = target <- find_user(socket, raw),
         {:ok, _} <- Admin.update_user(target, params, socket.assigns.current_user) do
      audit(socket, "user.update", target.id, %{
        "role" => params["role"],
        "password_reset" => params["new_password"] not in [nil, ""]
      })

      {:noreply, socket |> assign(editing: nil, error: nil) |> reload()}
    else
      nil -> {:noreply, socket}
      {:error, reason} -> {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("delete_user", %{"id" => raw}, socket) do
    with %Accounts.User{} = target <- find_user(socket, raw),
         {:ok, _} <- Admin.delete_user(target, socket.assigns.current_user) do
      audit(socket, "user.delete", target.id, %{"username" => target.username})
      {:noreply, socket |> assign(error: nil) |> reload()}
    else
      nil -> {:noreply, socket}
      {:error, reason} -> {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("reset_2fa", %{"id" => raw}, socket) do
    with %Accounts.User{} = target <- find_user(socket, raw),
         {:ok, _} <- Admin.reset_2fa(target) do
      audit(socket, "user.reset_2fa", target.id, nil)
      {:noreply, socket |> assign(error: nil) |> reload()}
    else
      _ -> {:noreply, socket}
    end
  end

  defp find_user(socket, raw_id) do
    id = String.to_integer(raw_id)
    Enum.find(socket.assigns.users, &(&1.id == id))
  end

  defp checked_ids(params) do
    for {"group_" <> gid, "true"} <- params, do: gid
  end

  defp audit(socket, action, target_id, detail) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "user",
      target_id: target_id,
      detail: detail
    )
  end

  defp error_text(:username_required), do: "username is required"
  defp error_text(:password_too_short), do: "password needs at least 8 characters"
  defp error_text(:conflict), do: "username already exists"
  defp error_text(:bad_role), do: "unknown role"
  defp error_text(:unknown_groups), do: "unknown group ids"
  defp error_text(:cannot_demote_self), do: "cannot demote your own admin account"
  defp error_text(:last_admin), do: "cannot demote/delete the last admin"
  defp error_text(:cannot_revoke_own_superadmin), do: "cannot revoke your own superadmin flag"
  defp error_text(:last_superadmin), do: "cannot revoke/delete the last superadmin"
  defp error_text(:cannot_delete_self), do: "cannot delete your own account"
  defp error_text(_), do: "operation failed"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:users} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:users} class="h-5 w-5 text-base-content/60" /> Users
            <span class="ml-2 text-sm text-base-content/60">({length(@users)})</span>
          </h1>
          <button
            phx-click="toggle_create"
            class="rounded bg-primary px-2 py-1 text-xs text-white hover:bg-primary/80"
          >
            {if @show_create, do: "Cancel", else: "New user"}
          </button>
        </div>

        <div
          :if={@error}
          class="mb-4 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form
          :if={@show_create}
          phx-submit="create_user"
          class="mb-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <div class="grid gap-3 md:grid-cols-3">
            <label class="block text-sm">
              <span class="mb-1 block text-xs text-base-content/60">Username</span>
              <input name="user[username]" required class={input_cls()} />
            </label>
            <label class="block text-sm">
              <span class="mb-1 block text-xs text-base-content/60">Password (min 8)</span>
              <input
                name="user[password]"
                type="password"
                autocomplete="new-password"
                required
                class={input_cls()}
              />
            </label>
            <label class="block text-sm">
              <span class="mb-1 block text-xs text-base-content/60">Role</span>
              <select name="user[role]" class={input_cls()}>
                <option :for={r <- Admin.roles()} value={r}>{r}</option>
              </select>
            </label>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-4 text-sm text-base-content/80">
            <label class="flex items-center gap-2">
              <input type="hidden" name="user[is_superadmin]" value="false" />
              <input
                type="checkbox"
                name="user[is_superadmin]"
                value="true"
                class="accent-indigo-600"
              /> superadmin
            </label>
            <.group_checks groups={@groups} member_ids={MapSet.new()} />
          </div>
          <button
            type="submit"
            class="mt-3 rounded bg-primary px-3 py-1 text-xs text-white hover:bg-primary/80"
          >
            Create user
          </button>
        </form>

        <table class="w-full text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-2 pr-4 font-medium">User</th>
              <th class="py-2 pr-4 font-medium">Role</th>
              <th class="py-2 pr-4 font-medium">2FA</th>
              <th class="py-2 pr-4 font-medium">Groups</th>
              <th class="py-2 pr-4 font-medium">Status</th>
              <th class="py-2 pr-4 font-medium">Last login</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <%= for u <- @users do %>
              <tr class="border-b border-base-300/50">
                <td class="py-2 pr-4">
                  <span class="text-base-content">{u.username}</span>
                  <span
                    :if={u.is_superadmin}
                    class="ml-2 rounded bg-indigo-900/50 px-1.5 py-0.5 text-xs text-indigo-300"
                  >
                    superadmin
                  </span>
                  <span
                    :if={u.is_bootstrap}
                    class="ml-2 rounded bg-base-300 px-1.5 py-0.5 text-xs text-base-content/70"
                  >
                    bootstrap
                  </span>
                </td>
                <td class="py-2 pr-4 text-base-content/80">{u.role}</td>
                <td class="py-2 pr-4">
                  <span class={twofa_class(u.totp_enabled)}>
                    {if u.totp_enabled, do: "on", else: "off"}
                  </span>
                </td>
                <td class="py-2 pr-4 text-base-content/70">{groups_text(u.groups)}</td>
                <td class="py-2 pr-4">
                  <span
                    :if={u.disabled}
                    class="rounded bg-error/20 px-1.5 py-0.5 text-xs text-error"
                  >
                    disabled
                  </span>
                  <span :if={not u.disabled} class="text-base-content/60">active</span>
                </td>
                <td class="py-2 pr-4 text-base-content/70">{last_login_text(u)}</td>
                <td class="py-2 text-right">
                  <button
                    phx-click="edit"
                    phx-value-id={u.id}
                    class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
                  >
                    {if @editing == u.id, do: "close", else: "edit"}
                  </button>
                </td>
              </tr>
              <tr :if={@editing == u.id} class="border-b border-base-300/50 bg-base-200/60">
                <td colspan="7" class="p-4">
                  <form phx-submit="update_user" class="space-y-3">
                    <input type="hidden" name="user_id" value={u.id} />
                    <div class="flex flex-wrap items-end gap-4 text-sm">
                      <label class="block">
                        <span class="mb-1 block text-xs text-base-content/60">Role</span>
                        <select name="user[role]" class={input_cls()}>
                          <option :for={r <- Admin.roles()} value={r} selected={u.role == r}>
                            {r}
                          </option>
                        </select>
                      </label>
                      <label class="flex items-center gap-2 pb-1 text-base-content/80">
                        <input type="hidden" name="user[is_superadmin]" value="false" />
                        <input
                          type="checkbox"
                          name="user[is_superadmin]"
                          value="true"
                          checked={u.is_superadmin}
                          class="accent-indigo-600"
                        /> superadmin
                      </label>
                      <label class="block">
                        <span class="mb-1 block text-xs text-base-content/60">
                          New password (blank = keep)
                        </span>
                        <input
                          name="user[new_password]"
                          type="password"
                          autocomplete="new-password"
                          class={input_cls()}
                        />
                      </label>
                    </div>
                    <div class="flex flex-wrap items-center gap-4 text-sm text-base-content/80">
                      <.group_checks groups={@groups} member_ids={MapSet.new(u.groups, & &1.id)} />
                    </div>
                    <div class="flex items-center gap-2">
                      <button
                        type="submit"
                        class="rounded bg-primary px-3 py-1 text-xs text-white hover:bg-primary/80"
                      >
                        Save
                      </button>
                      <button
                        type="button"
                        phx-click="reset_2fa"
                        phx-value-id={u.id}
                        data-confirm={"Reset 2FA for #{u.username}? TOTP and passkeys are wiped; their sessions die."}
                        class="rounded border border-warning/40 px-2 py-1 text-xs text-warning hover:bg-warning/10"
                      >
                        Reset 2FA
                      </button>
                      <button
                        type="button"
                        phx-click="delete_user"
                        phx-value-id={u.id}
                        data-confirm={"Delete user #{u.username}?"}
                        class="rounded border border-error/40 px-2 py-1 text-xs text-error hover:bg-error/15"
                      >
                        Delete
                      </button>
                    </div>
                  </form>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  attr :groups, :list, required: true
  attr :member_ids, :any, required: true

  defp group_checks(assigns) do
    ~H"""
    <label :for={g <- Enum.sort_by(@groups, & &1.name)} class="flex items-center gap-1.5">
      <input
        type="checkbox"
        name={"user[group_#{g.id}]"}
        value="true"
        checked={MapSet.member?(@member_ids, g.id)}
        class="accent-primary"
      />
      {g.name}
    </label>
    """
  end

  defp input_cls do
    "rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end

  defp twofa_class(true), do: "rounded bg-primary/20 px-1.5 py-0.5 text-xs text-primary"
  defp twofa_class(_), do: "rounded bg-warning/20 px-1.5 py-0.5 text-xs text-warning"

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
