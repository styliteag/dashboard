defmodule OrbitWeb.InstanceCreateLive do
  @moduledoc """
  New-instance form — instances/routes.py POST port. Write role required
  at mount AND re-checked on submit. Group targeting mirrors
  _resolve_create_group: exactly-one-membership is implied, superadmins
  may target any group, others only their own. Push-only device types
  (linux) reject a base_url (DR-9). After creation the user lands on the
  detail page, where the agent card mints the enroll code.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.TagPicker, only: [tag_picker: 1]

  alias Orbit.Audit
  alias Orbit.Instances
  alias OrbitWeb.Components.TagPicker

  @write_roles ~w(admin user)

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    if user.role in @write_roles do
      groups = selectable_groups(user)

      {:ok,
       assign(socket,
         groups: groups,
         error: nil,
         tags: [],
         known_tags: Instances.known_tags(user),
         tag_query: "",
         tag_open: false
       )}
    else
      {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  defp selectable_groups(user) do
    if user.is_superadmin do
      Orbit.Repo.all(Orbit.Accounts.Group)
    else
      user.groups
    end
    |> Enum.sort_by(& &1.name)
  end

  @impl true
  def handle_event("create", %{"instance" => params}, socket) do
    user = socket.assigns.current_user
    params = Map.put(params, "tags", submitted_tags(socket))

    with true <- user.role in @write_roles,
         {:ok, group_id} <- Instances.resolve_create_group(user, params["group_id"]),
         {:ok, inst} <- Instances.create_instance(params, group_id) do
      Audit.write(
        action: "instance.create",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: inst.id,
        detail: %{"name" => inst.name}
      )

      {:noreply, push_navigate(socket, to: ~p"/instances/#{inst.id}")}
    else
      false -> {:noreply, socket}
      {:error, reason} -> {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  # -- tag picker ------------------------------------------------------------
  # Clauses stay grouped with "create" above: a second `def handle_event`
  # block further down the module is a compile warning, and warnings are
  # errors here.

  def handle_event("tag_key", %{"key" => key, "value" => value}, socket) do
    case key do
      k when k in ["Enter", ","] ->
        {:noreply, commit_tag(socket, value)}

      "Escape" ->
        {:noreply, assign(socket, tag_open: false)}

      "Backspace" when value == "" ->
        {:noreply, assign(socket, tags: TagPicker.drop_last(socket.assigns.tags))}

      _ ->
        {:noreply, assign(socket, tag_query: value, tag_open: true)}
    end
  end

  def handle_event("tag_add", %{"tag" => tag}, socket) do
    {:noreply, commit_tag(socket, tag)}
  end

  def handle_event("tag_remove", %{"tag" => tag}, socket) do
    {:noreply, assign(socket, tags: TagPicker.remove(socket.assigns.tags, tag))}
  end

  def handle_event("tag_focus", _params, socket) do
    {:noreply, assign(socket, tag_open: true)}
  end

  # Closing only — never committing. A blur commit fired on focus changes
  # nobody made (a lone keystroke became a chip, seen in the browser); the
  # typed leftover is folded in at submit time instead.
  def handle_event("tag_close", _params, socket) do
    {:noreply, assign(socket, tag_open: false)}
  end

  # Picked chips plus whatever sits half-typed in the filter field, as the
  # comma-separated string Instances.coerce(:tags, …) parses. Submitting with
  # text still in the field is a normal way to fill a form — that tag counts.
  # The text comes from the assigns, not the form: the filter input carries no
  # form name (see TagPicker), so phx-keyup is what the server knows it by.
  defp submitted_tags(socket) do
    socket.assigns.tags
    |> TagPicker.add(socket.assigns.tag_query, socket.assigns.known_tags)
    |> Enum.join(",")
  end

  defp commit_tag(socket, text) do
    socket
    |> assign(
      tags: TagPicker.add(socket.assigns.tags, text, socket.assigns.known_tags),
      tag_query: ""
    )
    |> push_event("tag_picker_clear", %{})
  end

  defp error_text(:name_required), do: "name is required"
  defp error_text(:bad_device_type), do: "pick a device type"
  defp error_text(:push_only_no_base_url), do: "push-only device types have no base url"
  defp error_text(:slug_invalid), do: "slug must be a valid dns label"
  defp error_text(:slug_taken), do: "slug is already in use"
  defp error_text(:conflict), do: "instance name or slug already exists"
  defp error_text(:group_required), do: "pick a group (you are in more than one)"
  defp error_text(:unknown_group), do: "unknown group"
  defp error_text(:not_a_member), do: "not a member of the target group"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="max-w-2xl p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:instances} class="h-5 w-5 text-base-content/60" /> New instance
        </h1>

        <div
          :if={@error}
          class="mb-4 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form phx-submit="create" class="space-y-4">
          <div class="rounded-lg border border-base-300 bg-base-200 p-4">
            <div class="grid gap-3 md:grid-cols-2">
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Name</span>
                <input name="instance[name]" required class={input_cls()} />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Group</span>
                <select name="instance[group_id]" class={input_cls()}>
                  <option :for={g <- @groups} value={g.id}>{g.name}</option>
                </select>
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Device type</span>
                <select name="instance[device_type]" class={input_cls()}>
                  <option :for={t <- Orbit.Instances.device_types()} value={t}>{t}</option>
                </select>
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Transport</span>
                <select name="instance[transport]" class={input_cls()}>
                  <option value="push">push (agent)</option>
                  <option value="direct">direct (API poll)</option>
                </select>
              </label>
              <label class="block text-sm md:col-span-2">
                <span class="mb-1 block text-xs text-base-content/60">
                  Base URL (direct API; leave empty for push-only)
                </span>
                <input name="instance[base_url]" class={input_cls()} />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">API key (direct only)</span>
                <input name="instance[api_key]" autocomplete="off" class={input_cls()} />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">API secret</span>
                <input
                  name="instance[api_secret]"
                  type="password"
                  autocomplete="new-password"
                  class={input_cls()}
                />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Location</span>
                <input name="instance[location]" class={input_cls()} />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">Slug (optional)</span>
                <input name="instance[slug]" class={input_cls()} />
              </label>
              <.tag_picker
                tags={@tags}
                known={@known_tags}
                query={@tag_query}
                open={@tag_open}
              />
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">
                  Ping URL (availability probe)
                </span>
                <input name="instance[ping_url]" class={input_cls()} />
              </label>
              <label class="block text-sm">
                <span class="mb-1 block text-xs text-base-content/60">
                  Push interval (s) — blank = global default
                </span>
                <input
                  name="instance[push_interval_seconds]"
                  inputmode="numeric"
                  class={input_cls()}
                />
              </label>
              <label class="block text-sm md:col-span-2">
                <span class="mb-1 block text-xs text-base-content/60">Notes</span>
                <input name="instance[notes]" class={input_cls()} />
              </label>
            </div>
            <label class="mt-3 flex items-center gap-2 text-sm text-base-content/80">
              <input type="hidden" name="instance[ssl_verify]" value="false" />
              <input
                type="checkbox"
                name="instance[ssl_verify]"
                value="true"
                class="accent-primary"
              /> Verify TLS
            </label>
            <%!-- Only meaningful on the poll path: in agent mode the box
                 collects locally and pushes, so the dashboard makes no
                 outbound HTTPS call to verify (2.1.5 parity). --%>
            <label class="mt-3 block text-sm">
              <span class="mb-1 block text-xs text-base-content/60">
                CA bundle (PEM, direct only) — lets TLS verification succeed against a
                firewall's own CA instead of turning verification off
              </span>
              <textarea
                name="instance[ca_bundle]"
                rows="4"
                spellcheck="false"
                placeholder="-----BEGIN CERTIFICATE-----"
                class={[input_cls(), "font-mono text-xs"]}
              ></textarea>
            </label>
          </div>

          <button
            type="submit"
            class="rounded bg-primary px-4 py-1.5 text-sm text-primary-content hover:bg-primary/80"
          >
            Create instance
          </button>
        </form>
      </section>
    </main>
    """
  end

  defp input_cls do
    "w-full rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end
end
