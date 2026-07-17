defmodule OrbitWeb.GroupsLive do
  @moduledoc """
  Superadmin rights management for scoping groups — overview plus the
  groups/routes.py mutations: create, rename, delete. The delete guards
  are security-load-bearing (Orbit.Accounts.Admin): instances (incl.
  soft-deleted) block it, and so does an active api key bound to only
  this group (its CASCADE would make the key GLOBAL). Every mutation
  audits. Superadmin-gated via on_mount :require_superadmin.
  """

  use OrbitWeb, :live_view

  alias Orbit.Accounts
  alias Orbit.Accounts.Admin
  alias Orbit.Audit

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(error: nil, renaming: nil) |> reload()}
  end

  defp reload(socket), do: assign(socket, groups: Accounts.list_groups())

  @impl true
  def handle_event("create_group", %{"group" => %{"name" => name}}, socket) do
    case Admin.create_group(name) do
      {:ok, group} ->
        audit(socket, "group.create", group.id, %{"name" => group.name})
        {:noreply, socket |> assign(error: nil) |> reload()}

      {:error, reason} ->
        {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("rename_toggle", %{"group_id" => raw}, socket) do
    id = String.to_integer(raw)
    {:noreply, assign(socket, renaming: if(socket.assigns.renaming == id, do: nil, else: id))}
  end

  def handle_event("rename_group", %{"group_id" => raw, "group" => %{"name" => name}}, socket) do
    with %Accounts.Group{} = group <- get_group(raw),
         {:ok, renamed} <- Admin.rename_group(group, name) do
      audit(socket, "group.update", renamed.id, %{
        "name" => renamed.name,
        "old_name" => group.name
      })

      {:noreply, socket |> assign(error: nil, renaming: nil) |> reload()}
    else
      nil -> {:noreply, socket}
      {:error, reason} -> {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("delete_group", %{"group_id" => raw}, socket) do
    with %Accounts.Group{} = group <- get_group(raw),
         {:ok, _} <- Admin.delete_group(group) do
      audit(socket, "group.delete", group.id, %{"name" => group.name})
      {:noreply, socket |> assign(error: nil) |> reload()}
    else
      nil -> {:noreply, socket}
      {:error, reason} -> {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  defp get_group(raw_id) do
    Orbit.Repo.get(Accounts.Group, String.to_integer(raw_id))
  end

  defp audit(socket, action, target_id, detail) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "group",
      target_id: target_id,
      detail: detail
    )
  end

  defp error_text(:name_required), do: "group name is required"
  defp error_text(:conflict), do: "group name already exists"

  defp error_text(:has_instances),
    do: "group still contains instances (including soft-deleted) — move them first"

  defp error_text({:sole_apikey_binding, key}),
    do: "API key \"#{key}\" is bound to this group only — revoke or re-mint it first"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:groups} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Groups <span class="ml-2 text-sm text-slate-500">({length(@groups)})</span>
        </h1>

        <div
          :if={@error}
          class="mb-4 max-w-2xl rounded border border-red-800 bg-red-950/50 p-2 text-sm text-red-300"
        >
          {@error}
        </div>

        <form phx-submit="create_group" class="mb-4 flex max-w-2xl items-center gap-2">
          <input
            name="group[name]"
            placeholder="new group name"
            required
            class="flex-1 rounded border border-slate-700 bg-slate-950 p-1.5 text-sm text-slate-200"
          />
          <button
            type="submit"
            class="rounded bg-emerald-700 px-3 py-1.5 text-xs text-white hover:bg-emerald-600"
          >
            Create group
          </button>
        </form>

        <table class="w-full max-w-2xl text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Group</th>
              <th class="py-2 pr-4 text-right font-medium">Members</th>
              <th class="py-2 pr-4 text-right font-medium">Instances</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <%= for g <- @groups do %>
              <tr class="border-b border-slate-800/50">
                <td class="py-2 pr-4 text-slate-200">{g.name}</td>
                <td class="py-2 pr-4 text-right text-slate-300">{g.user_count}</td>
                <td class="py-2 pr-4 text-right text-slate-300">{g.instance_count}</td>
                <td class="py-2 text-right">
                  <button
                    phx-click="rename_toggle"
                    phx-value-group_id={g.id}
                    class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-400 hover:bg-slate-800"
                  >
                    rename
                  </button>
                  <button
                    phx-click="delete_group"
                    phx-value-group_id={g.id}
                    data-confirm={"Delete group #{g.name}?"}
                    class="ml-1 rounded border border-red-900 px-2 py-0.5 text-xs text-red-400 hover:bg-red-950"
                  >
                    delete
                  </button>
                </td>
              </tr>
              <tr :if={@renaming == g.id} class="border-b border-slate-800/50 bg-slate-900/60">
                <td colspan="4" class="p-3">
                  <form phx-submit="rename_group" class="flex items-center gap-2">
                    <input type="hidden" name="group_id" value={g.id} />
                    <input
                      name="group[name]"
                      value={g.name}
                      required
                      class="flex-1 rounded border border-slate-700 bg-slate-950 p-1.5 text-sm text-slate-200"
                    />
                    <button
                      type="submit"
                      class="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600"
                    >
                      Save
                    </button>
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
end
