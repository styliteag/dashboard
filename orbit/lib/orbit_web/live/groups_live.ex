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
  alias Orbit.Groups.Channels

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(
       error: nil,
       renaming: nil,
       channels_for: nil,
       group_channels: %{},
       channel_error: nil
     )
     |> reload()}
  end

  defp reload(socket) do
    assign(socket,
      groups: Accounts.list_groups(),
      assignments: list_assignments()
    )
  end

  # Superadmin-only surface: the assignment table deliberately reads ALL
  # live instances without scope — moving instances between groups is
  # rights management (python move_group passes a None principal for
  # superadmins for exactly this reason). The page is on_mount
  # :require_superadmin, so no other role can reach this query.
  defp list_assignments do
    Orbit.Repo.query!(
      "SELECT id, name, slug, group_id FROM instances WHERE deleted_at IS NULL ORDER BY name"
    ).rows
    |> Enum.map(fn [id, name, slug, group_id] ->
      %{id: id, name: name, slug: slug, group_id: group_id}
    end)
  rescue
    _ -> []
  end

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

  # Per-group notification channels (GroupChannelsEditor parity): toggle
  # panel per group; save/remove per channel. Secrets render as the mask
  # and the mask round-trips as "keep stored".
  def handle_event("channels_toggle", %{"group_id" => raw}, socket) do
    id = String.to_integer(raw)

    if socket.assigns.channels_for == id do
      {:noreply, assign(socket, channels_for: nil, channel_error: nil)}
    else
      {:noreply,
       assign(socket, channels_for: id, group_channels: Channels.list(id), channel_error: nil)}
    end
  end

  def handle_event("channel_save", %{"group_id" => raw, "channel" => channel} = params, socket) do
    with %Accounts.Group{} = group <- get_group(raw),
         {:ok, _masked} <-
           Channels.upsert(
             group.id,
             channel,
             params["config"] || %{},
             socket.assigns.current_user
           ) do
      {:noreply, assign(socket, channel_error: nil, group_channels: Channels.list(group.id))}
    else
      nil -> {:noreply, socket}
      {:error, msg} -> {:noreply, assign(socket, channel_error: "#{channel}: #{msg}")}
    end
  end

  def handle_event("move_instance", %{"instance_id" => raw_iid, "group_id" => raw_gid}, socket) do
    with {iid, ""} <- Integer.parse(raw_iid),
         {gid, ""} <- Integer.parse(raw_gid),
         %Accounts.Group{} <- Orbit.Repo.get(Accounts.Group, gid),
         %Orbit.Instances.Instance{} = inst <- Orbit.Repo.get(Orbit.Instances.Instance, iid),
         {:ok, moved} <- Orbit.Instances.move_group(inst, gid) do
      Audit.write(
        action: "instance.move_group",
        result: "ok",
        user_id: socket.assigns.current_user.id,
        target_type: "instance",
        target_id: moved.id,
        detail: %{"from_group_id" => inst.group_id, "to_group_id" => gid}
      )

      {:noreply, socket |> assign(error: nil) |> reload()}
    else
      _ -> {:noreply, assign(socket, error: "move failed — unknown instance or group")}
    end
  end

  def handle_event("channel_remove", %{"group_id" => raw, "channel" => channel}, socket) do
    with %Accounts.Group{} = group <- get_group(raw) do
      :ok = Channels.delete(group.id, channel, socket.assigns.current_user)

      {:noreply, assign(socket, channel_error: nil, group_channels: Channels.list(group.id))}
    else
      nil -> {:noreply, socket}
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
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:groups} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-base-content">
          Groups <span class="ml-2 text-sm text-base-content/60">({length(@groups)})</span>
        </h1>

        <div
          :if={@error}
          class="mb-4 max-w-2xl rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form phx-submit="create_group" class="mb-4 flex max-w-2xl items-center gap-2">
          <input
            name="group[name]"
            placeholder="new group name"
            required
            class="flex-1 rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
          />
          <button
            type="submit"
            class="rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/80"
          >
            Create group
          </button>
        </form>

        <table class="w-full max-w-2xl text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-2 pr-4 font-medium">Group</th>
              <th class="py-2 pr-4 text-right font-medium">Members</th>
              <th class="py-2 pr-4 text-right font-medium">Instances</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <%= for g <- @groups do %>
              <tr class="border-b border-base-300/50">
                <td class="py-2 pr-4 text-base-content">{g.name}</td>
                <td class="py-2 pr-4 text-right text-base-content/80">{g.user_count}</td>
                <td class="py-2 pr-4 text-right text-base-content/80">{g.instance_count}</td>
                <td class="py-2 text-right">
                  <button
                    phx-click="channels_toggle"
                    phx-value-group_id={g.id}
                    title="Per-group notification channels"
                    class={[
                      "rounded border border-base-content/20 px-2 py-0.5 text-xs hover:bg-base-300",
                      if(@channels_for == g.id, do: "text-primary", else: "text-base-content/70")
                    ]}
                  >
                    channels
                  </button>
                  <button
                    phx-click="rename_toggle"
                    phx-value-group_id={g.id}
                    class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
                  >
                    rename
                  </button>
                  <button
                    phx-click="delete_group"
                    phx-value-group_id={g.id}
                    data-confirm={"Delete group #{g.name}?"}
                    class="ml-1 rounded border border-error/40 px-2 py-0.5 text-xs text-error hover:bg-error/15"
                  >
                    delete
                  </button>
                </td>
              </tr>
              <tr :if={@renaming == g.id} class="border-b border-base-300/50 bg-base-200/60">
                <td colspan="4" class="p-3">
                  <form phx-submit="rename_group" class="flex items-center gap-2">
                    <input type="hidden" name="group_id" value={g.id} />
                    <input
                      name="group[name]"
                      value={g.name}
                      required
                      class="flex-1 rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
                    />
                    <button
                      type="submit"
                      class="rounded bg-primary px-3 py-1 text-xs text-white hover:bg-primary/80"
                    >
                      Save
                    </button>
                  </form>
                </td>
              </tr>
              <tr :if={@channels_for == g.id} class="border-b border-base-300/50 bg-base-200/60">
                <td colspan="4" class="p-3">
                  <p class="mb-2 text-xs text-base-content/60">
                    A configured channel replaces the global target for this group's
                    instances; removing it falls back to the global channel.
                  </p>
                  <div
                    :if={@channel_error}
                    class="mb-2 rounded border border-error/40 bg-error/10 p-2 text-xs text-error"
                  >
                    {@channel_error}
                  </div>
                  <div class="grid gap-3 lg:grid-cols-3">
                    <.channel_card
                      :for={channel <- Channels.channels()}
                      group_id={g.id}
                      channel={channel}
                      configured={@group_channels[channel]}
                    />
                  </div>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <%!-- Instance assignment (GroupsPage parity) — the one place to move
             instances between groups; the move applies immediately. --%>
        <div class="mt-8 max-w-2xl rounded-lg border border-base-300 bg-base-200 p-4">
          <h2 class="text-sm font-medium text-base-content/80">Instance assignment</h2>
          <p class="mt-1 text-xs text-base-content/60">
            Pick a group per instance — the move applies immediately.
          </p>
          <p :if={@assignments == []} class="mt-3 text-sm text-base-content/60">No instances yet.</p>
          <table :if={@assignments != []} class="mt-3 w-full text-left text-sm">
            <thead class="text-xs text-base-content/60">
              <tr class="border-b border-base-300">
                <th class="py-1 pr-4 font-medium">Instance</th>
                <th class="py-1 font-medium">Group</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={a <- @assignments} class="border-b border-base-300/50 last:border-0">
                <td class="py-2 pr-4 text-base-content">
                  {a.name} <span class="ml-1 text-xs text-base-content/60">{a.slug}</span>
                </td>
                <td class="py-2">
                  <form phx-change="move_instance">
                    <input type="hidden" name="instance_id" value={a.id} />
                    <select
                      name="group_id"
                      disabled={length(@groups) < 2}
                      title={if length(@groups) < 2, do: "Create a second group first"}
                      class="rounded border border-base-content/20 bg-base-300 px-2 py-1 text-xs text-base-content/80 disabled:opacity-50"
                    >
                      <option :for={g <- @groups} value={g.id} selected={g.id == a.group_id}>
                        {g.name}
                      </option>
                    </select>
                  </form>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  attr :group_id, :integer, required: true
  attr :channel, :string, required: true
  attr :configured, :any, required: true, doc: "masked config map | nil"

  defp channel_card(assigns) do
    ~H"""
    <form
      phx-submit="channel_save"
      class="rounded-lg border border-base-300 bg-base-100/40 p-3"
    >
      <input type="hidden" name="group_id" value={@group_id} />
      <input type="hidden" name="channel" value={@channel} />
      <div class="flex items-center justify-between">
        <h5 class="text-xs font-semibold capitalize text-base-content">{@channel}</h5>
        <span
          :if={@configured}
          class="rounded bg-primary/20 px-1.5 py-0.5 text-[10px] text-primary"
        >
          configured — replaces global
        </span>
        <span
          :if={is_nil(@configured)}
          class="rounded bg-base-300 px-1.5 py-0.5 text-[10px] text-base-content/60"
        >
          using global
        </span>
      </div>
      <div class="mt-2 space-y-2">
        <div :for={f <- Channels.fields(@channel)} class="space-y-0.5">
          <label class="text-[10px] text-base-content/60">
            {f.name}{if f.required, do: " *"}
          </label>
          <input
            type={if f.secret, do: "password", else: "text"}
            name={"config[#{f.name}]"}
            value={(@configured || %{})[f.name] || ""}
            class="w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-xs text-base-content focus:border-primary focus:outline-none"
          />
        </div>
      </div>
      <div class="mt-2 flex items-center justify-end gap-1">
        <button
          :if={@configured}
          type="button"
          phx-click="channel_remove"
          phx-value-group_id={@group_id}
          phx-value-channel={@channel}
          data-confirm={"Remove the #{@channel} override? Alerts fall back to the global channel."}
          class="rounded border border-error/40 px-2 py-1 text-xs text-error hover:bg-error/15"
        >
          Remove
        </button>
        <button
          type="submit"
          class="rounded bg-primary px-3 py-1 text-xs text-white hover:bg-primary/80"
        >
          Save
        </button>
      </div>
    </form>
    """
  end
end
