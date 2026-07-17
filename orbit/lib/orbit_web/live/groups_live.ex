defmodule OrbitWeb.GroupsLive do
  @moduledoc """
  Superadmin rights-management: read-only overview of every scoping group with
  its member count and (non-deleted) instance count. Group create/rename/delete
  and membership edits land in the later mutating slice.

  Superadmin-gated via on_mount :require_superadmin.
  """

  use OrbitWeb, :live_view

  alias Orbit.Accounts

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, groups: Accounts.list_groups())}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:groups} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Groups <span class="ml-2 text-sm text-slate-500">({length(@groups)})</span>
        </h1>

        <table class="w-full max-w-2xl text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Group</th>
              <th class="py-2 pr-4 text-right font-medium">Members</th>
              <th class="py-2 pr-4 text-right font-medium">Instances</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={g <- @groups} class="border-b border-slate-800/50">
              <td class="py-2 pr-4 text-slate-200">{g.name}</td>
              <td class="py-2 pr-4 text-right text-slate-300">{g.user_count}</td>
              <td class="py-2 pr-4 text-right text-slate-300">{g.instance_count}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end
end
