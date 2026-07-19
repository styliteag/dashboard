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
      {:ok,
       assign(socket,
         instance: inst,
         admin: user.role == "admin",
         error: nil,
         pinning: false,
         pin_result: nil,
         ssh_testing: false,
         ssh_result: nil
       )}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  # Trust-on-first-use host-key capture. This is the ONLY place that connects
  # unpinned (Orbit.Securepoint.SSH.probe_host_key/1); every other SSH path
  # refuses without a pin. Explicit and audited rather than silently trusting
  # whatever answers — the operator confirms the box by pressing this.
  # Prove the saved settings work, end to end (login + swanctl), before anyone
  # relies on the enrichment. Read-only on the box.
  @impl true
  def handle_event("ssh_test", _params, socket) do
    inst = socket.assigns.instance

    if socket.assigns.ssh_testing do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(ssh_testing: true, ssh_result: nil)
       |> start_async(:ssh_test, fn ->
         case Orbit.Securepoint.SSH.config_for(inst) do
           {:ok, cfg} -> Orbit.Securepoint.SSH.test_access(cfg)
           _ -> {:error, "no SSH key stored yet — save one first"}
         end
       end)}
    end
  end

  def handle_event("ssh_pin_host_key", _params, socket) do
    inst = socket.assigns.instance

    if socket.assigns.pinning do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(pinning: true, pin_result: nil)
       |> start_async(:pin_host_key, fn ->
         with {:ok, cfg} <- Orbit.Securepoint.SSH.config_for(inst) do
           Orbit.Securepoint.SSH.probe_host_key(cfg)
         else
           _ -> {:error, "no SSH key stored yet — save one first"}
         end
       end)}
    end
  end

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

          <%!-- SSH enrichment: only Securepoint has no agent, so only it needs
               the dashboard to log in for swanctl and the ping monitors. --%>
          <div
            :if={@instance.device_type == "securepoint"}
            class="rounded-lg border border-base-300 bg-base-200 p-4"
          >
            <h2 class="mb-1 text-sm font-medium text-base-content/70">SSH access</h2>
            <p class="mb-3 text-xs text-base-content/60">
              A Securepoint has no agent. With SSH the dashboard reads rich IPsec state
              via swanctl (SPIs, IKE cookies, byte counters), runs the ping monitors on
              the box and can open a terminal. See docs/securepoint-ssh.md.
            </p>

            <.flag
              name="instance[ssh_enabled]"
              checked={@instance.ssh_enabled}
              label="SSH enrichment (rich IPsec via swanctl — SPIs, cookies, byte counters)"
            />

            <div class="mt-3 grid gap-3 md:grid-cols-2">
              <label class="block text-xs text-base-content/60">
                SSH port
                <input
                  name="instance[ssh_port]"
                  value={@instance.ssh_port || 22}
                  class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
                />
              </label>
              <label class="block text-xs text-base-content/60">
                SSH user
                <input
                  name="instance[ssh_user]"
                  value={@instance.ssh_user || "root"}
                  class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
                />
              </label>
            </div>

            <label class="mt-3 block text-xs text-base-content/60">
              SSH private key (ed25519 PEM) — leave empty to keep the stored one <textarea
                name="instance[ssh_key]"
                rows="4"
                placeholder={if @instance.ssh_key_enc, do: "unchanged", else: "just gen-ssh-key"}
                class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-xs text-base-content"
              ></textarea>
            </label>

            <%!-- Host-key pinning is trust-on-first-use and FAIL-CLOSED: without a
                 pinned key the transport refuses to connect at all, so a fresh key
                 (which clears the pin) leaves SSH dead until this is captured. --%>
            <div class="mt-3 flex flex-wrap items-center gap-3 text-xs">
              <span :if={present?(@instance.ssh_host_key)} class="text-primary">
                Host key pinned — {String.slice(@instance.ssh_host_key, 0, 28)}…
              </span>
              <span :if={not present?(@instance.ssh_host_key)} class="text-warning">
                No host key pinned — SSH will refuse to connect until it is captured.
              </span>
              <button
                type="button"
                phx-click="ssh_test"
                disabled={@ssh_testing or @pinning}
                class="rounded border border-info/40 px-2 py-1 text-info hover:bg-info/15 disabled:opacity-50"
              >
                {if @ssh_testing, do: "Testing…", else: "Test"}
              </button>
              <button
                type="button"
                phx-click="ssh_pin_host_key"
                disabled={@pinning}
                class="rounded border border-base-content/20 px-2 py-1 text-base-content/80 hover:bg-base-300 disabled:opacity-50"
              >
                {if @pinning, do: "Connecting…", else: "Capture host key"}
              </button>
              <span :if={@pin_result} class={pin_class(@pin_result)}>{elem(@pin_result, 1)}</span>
            </div>
            <p :if={@ssh_result} class={["mt-2 text-xs", pin_class(@ssh_result)]}>
              {elem(@ssh_result, 1)}
            </p>
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

  @impl true
  def handle_async(:ssh_test, {:ok, result}, socket) do
    {:noreply, assign(socket, ssh_testing: false, ssh_result: result)}
  end

  def handle_async(:ssh_test, {:exit, reason}, socket) do
    {:noreply, assign(socket, ssh_testing: false, ssh_result: {:error, inspect(reason)})}
  end

  def handle_async(:pin_host_key, {:ok, {:ok, line}}, socket) do
    inst = socket.assigns.instance

    case Orbit.Instances.pin_ssh_host_key(inst, line) do
      {:ok, updated} ->
        Orbit.Audit.write(
          action: "instance.ssh_host_key.pin",
          result: "ok",
          user_id: socket.assigns.current_user.id,
          target_type: "instance",
          target_id: inst.id
        )

        {:noreply,
         assign(socket,
           instance: updated,
           pinning: false,
           pin_result: {:ok, "pinned #{String.slice(line, 0, 24)}…"}
         )}

      _ ->
        {:noreply,
         assign(socket, pinning: false, pin_result: {:error, "could not store the key"})}
    end
  end

  def handle_async(:pin_host_key, {:ok, {:error, msg}}, socket) do
    {:noreply, assign(socket, pinning: false, pin_result: {:error, msg})}
  end

  def handle_async(:pin_host_key, {:exit, reason}, socket) do
    {:noreply, assign(socket, pinning: false, pin_result: {:error, inspect(reason)})}
  end

  defp pin_class({:ok, _}), do: "text-primary"
  defp pin_class(_), do: "text-error"

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: true

  defp input_cls do
    "w-full rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end
end
