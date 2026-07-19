defmodule OrbitWeb.InstanceEditLive do
  @moduledoc """
  Instance settings editor — the write side of the instance record
  (instances/routes.py PATCH/DELETE port). Scoped via get_instance
  (invariant 1: out-of-scope ids bounce to /instances, never revealing
  existence). Write role re-checked in every handler (never trust hidden
  UI); arming the root shell (shell_enabled) is admin-gated ABOVE the
  write role — real blast radius (routes.py parity).

  Secrets follow invariant 3: fields render empty, empty submit keeps the
  stored value, a non-empty one rotates (fernet-encrypted); the audit
  detail is allowlisted and records rotations by NAME only. Delete is a
  soft delete (slug freed for the GUI proxy).
  """

  use OrbitWeb, :live_view

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Instances

  @write_roles ~w(admin user)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         true <- user.role in @write_roles do
      {:ok, assign(socket, instance: inst, admin: user.role == "admin", error: nil)}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  @impl true
  def handle_event("save", %{"instance" => params}, socket) do
    user = socket.assigns.current_user
    inst = socket.assigns.instance

    cond do
      user.role not in @write_roles ->
        {:noreply, socket}

      # shell_enabled: admin-only, above the write role (blast radius).
      Map.has_key?(params, "shell_enabled") and not socket.assigns.admin ->
        {:noreply, assign(socket, error: "admin role required to change terminal access")}

      true ->
        save(socket, inst, params)
    end
  end

  def handle_event("delete", _params, socket) do
    user = socket.assigns.current_user
    inst = socket.assigns.instance

    if user.role in @write_roles do
      {:ok, _} = Instances.soft_delete(inst)

      Audit.write(
        action: "instance.delete",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: inst.id,
        detail: %{"name" => inst.name}
      )

      {:noreply, push_navigate(socket, to: ~p"/instances")}
    else
      {:noreply, socket}
    end
  end

  defp save(socket, inst, params) do
    case Instances.update_instance(inst, params) do
      {:ok, updated} ->
        Audit.write(
          action: "instance.update",
          result: "ok",
          user_id: socket.assigns.current_user.id,
          target_type: "instance",
          target_id: inst.id,
          detail: Instances.safe_audit_detail(params)
        )

        {:noreply, push_navigate(socket, to: ~p"/instances/#{updated.id}")}

      {:error, :slug_invalid} ->
        {:noreply, assign(socket, error: "slug must be a valid dns label (a-z, 0-9, -)")}

      {:error, :slug_taken} ->
        {:noreply, assign(socket, error: "slug is already in use")}

      {:error, %Ecto.Changeset{}} ->
        {:noreply, assign(socket, error: "could not save — check the field values")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="mx-auto max-w-2xl p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/60" />
            Edit {@instance.name}
          </h1>
          <a
            href={~p"/instances/#{@instance.id}"}
            class="text-xs text-base-content/60 hover:text-base-content/80"
          >
            back to detail
          </a>
        </div>

        <div
          :if={@error}
          class="mb-4 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form phx-submit="save" class="space-y-4">
          <div class="rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">General</h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="Name">
                <input name="instance[name]" value={@instance.name} required class={input_cls()} />
              </.field>
              <.field label="Slug (GUI vhost label)">
                <input name="instance[slug]" value={@instance.slug} class={input_cls()} />
              </.field>
              <.field label="Base URL">
                <input name="instance[base_url]" value={@instance.base_url} class={input_cls()} />
              </.field>
              <.field label="Location">
                <input name="instance[location]" value={@instance.location} class={input_cls()} />
              </.field>
              <.field label="Ping URL (availability probe)">
                <input name="instance[ping_url]" value={@instance.ping_url} class={input_cls()} />
              </.field>
              <.field label="Notes">
                <input name="instance[notes]" value={@instance.notes} class={input_cls()} />
              </.field>
            </div>
          </div>

          <div class="rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">
              Intervals (blank = global default)
            </h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="Poll interval (s)">
                <input
                  name="instance[poll_interval_seconds]"
                  value={@instance.poll_interval_seconds}
                  inputmode="numeric"
                  class={input_cls()}
                />
              </.field>
              <.field label="Push interval (s) — live-applied to a connected agent">
                <input
                  name="instance[push_interval_seconds]"
                  value={@instance.push_interval_seconds}
                  inputmode="numeric"
                  class={input_cls()}
                />
              </.field>
            </div>
          </div>

          <div class="rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">
              Credentials <span class="text-base-content/60">(blank = keep existing)</span>
            </h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="API key">
                <input name="instance[api_key]" value="" autocomplete="off" class={input_cls()} />
              </.field>
              <.field label="API secret">
                <input
                  name="instance[api_secret]"
                  value=""
                  type="password"
                  autocomplete="new-password"
                  class={input_cls()}
                />
              </.field>
            </div>
          </div>

          <div class="rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Flags</h2>
            <div class="grid gap-2 md:grid-cols-2">
              <.flag name="instance[ssl_verify]" checked={@instance.ssl_verify} label="Verify TLS" />
              <.flag
                name="instance[gui_login_enabled]"
                checked={@instance.gui_login_enabled}
                label="GUI login"
              />
              <.flag
                :if={@admin}
                name="instance[shell_enabled]"
                checked={@instance.shell_enabled}
                label="Terminal (root shell) — admin only"
              />
              <.flag
                name="instance[maintenance]"
                checked={@instance.maintenance}
                label="Maintenance (checks capped)"
              />
              <.flag
                name="instance[firmware_locked]"
                checked={@instance.firmware_locked}
                label="Lock firmware updates"
              />
            </div>
          </div>

          <div class="flex items-center gap-3">
            <button
              type="submit"
              class="rounded bg-primary px-4 py-1.5 text-sm text-white hover:bg-primary/80"
            >
              Save
            </button>
            <button
              type="button"
              phx-click="delete"
              data-confirm={"Delete instance #{@instance.name}? The agent will be orphaned; the record is soft-deleted."}
              class="rounded border border-error/40 px-3 py-1.5 text-sm text-error hover:bg-error/15"
            >
              Delete instance
            </button>
          </div>
        </form>
      </section>
    </main>
    """
  end

  attr :label, :string, required: true
  slot :inner_block, required: true

  defp field(assigns) do
    ~H"""
    <label class="block text-sm">
      <span class="mb-1 block text-xs text-base-content/60">{@label}</span>
      {render_slot(@inner_block)}
    </label>
    """
  end

  attr :name, :string, required: true
  attr :checked, :boolean, default: false
  attr :label, :string, required: true

  defp flag(assigns) do
    ~H"""
    <label class="flex items-center gap-2 text-sm text-base-content/80">
      <input type="hidden" name={@name} value="false" />
      <input type="checkbox" name={@name} value="true" checked={@checked} class="accent-primary" />
      {@label}
    </label>
    """
  end

  defp input_cls do
    "w-full rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end
end
