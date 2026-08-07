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

  Form state lives in a `@form` map (seeded from the instance, secrets
  seeded empty), merged on every phx-change: without it any re-render —
  an inline error, an SSH test result — reset unfocused inputs to their
  server values, silently discarding edits. Inline validation shares
  `OrbitWeb.InstanceForm` with the create form (UI/UX review U-M4).
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.TagPicker, only: [tag_picker: 1]

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Instances
  alias OrbitWeb.Components.TagPicker
  alias OrbitWeb.InstanceForm

  @write_roles ~w(admin user)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         true <- user.role in @write_roles do
      {:ok,
       socket
       |> assign(
         instance: inst,
         admin: user.role == "admin",
         error: nil,
         form: form_from(inst),
         touched: MapSet.new(),
         errors: %{},
         pinning: false,
         pin_result: nil,
         ssh_testing: false,
         ssh_result: nil,
         api_testing: false,
         api_result: nil
       )
       |> TagPicker.init(inst.tags, Instances.known_tags(user))}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  # Secrets (api_key, api_secret, ssh_key) seed EMPTY on purpose: rendering
  # them would put decrypted material in the DOM; empty submit = keep stored
  # (invariant 3). Everything else mirrors the record so typed edits survive
  # re-renders.
  defp form_from(inst) do
    %{
      "name" => inst.name,
      "slug" => inst.slug,
      "base_url" => inst.base_url,
      "location" => inst.location,
      "ping_url" => inst.ping_url,
      "notes" => inst.notes,
      "poll_interval_seconds" => num_str(inst.poll_interval_seconds),
      "push_interval_seconds" => num_str(inst.push_interval_seconds),
      "api_key" => "",
      "api_secret" => "",
      "ca_bundle" => inst.ca_bundle,
      "ssl_verify" => to_string(inst.ssl_verify),
      "gui_login_enabled" => to_string(inst.gui_login_enabled),
      "shell_enabled" => to_string(inst.shell_enabled),
      "maintenance" => to_string(inst.maintenance),
      "firmware_locked" => to_string(inst.firmware_locked),
      "ssh_enabled" => to_string(inst.ssh_enabled),
      "ssh_port" => to_string(inst.ssh_port || 22),
      "ssh_user" => inst.ssh_user || "root",
      "ssh_key" => ""
    }
  end

  defp num_str(nil), do: nil
  defp num_str(n), do: to_string(n)

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

  # Generic connection test for direct-API boxes (UI/UX review U-M4; the
  # Securepoint SSH Test button is the model). Probes the SAVED record —
  # unsaved edits are deliberately not testable, the button says so.
  # Read-only against the box (status endpoints only).
  def handle_event("api_test", _params, socket) do
    inst = socket.assigns.instance

    if socket.assigns.api_testing or not direct_api?(inst) do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(api_testing: true, api_result: nil)
       |> start_async(:api_test, fn -> probe_api(inst) end)}
    end
  end

  def handle_event("save", %{"instance" => params}, socket) do
    user = socket.assigns.current_user
    inst = socket.assigns.instance
    # Submitted values refresh the form state (autofill can land values no
    # change event saw), mirroring the create form.
    socket = assign(socket, form: Map.merge(socket.assigns.form, params))
    params = Map.put(params, "tags", TagPicker.submitted_tags(socket))

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

  # Tag picker state lives in TagPicker, shared with the create form.
  def handle_event("tag_" <> _ = event, params, socket) do
    {:noreply, TagPicker.on_event(event, params, socket)}
  end

  # Merge + inline-validate on every change so edits survive re-renders and
  # mistakes surface at the field (UI/UX review U-M4).
  def handle_event("form_change", %{"instance" => params} = payload, socket) do
    form = Map.merge(socket.assigns.form, params)
    touched = InstanceForm.touch(socket.assigns.touched, payload)

    {:noreply,
     assign(socket, form: form, touched: touched, errors: InstanceForm.errors(form, touched))}
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

  # Direct-API boxes the dashboard polls itself — Securepoint has its own
  # SSH test above, push-only types have no API to test.
  defp direct_api?(inst) do
    inst.transport == "direct" and inst.device_type != "securepoint" and
      not Instances.push_only_type?(inst.device_type)
  end

  # fetch_status is best-effort per section (a failing endpoint yields an
  # empty section, never a raise) — so "no sections at all" IS the failure
  # signal: nothing answered under those credentials at that URL.
  defp probe_api(inst) do
    case Orbit.Poller.OpnsenseClient.new(inst) do
      {:ok, client} ->
        status = Orbit.Poller.OpnsenseClient.fetch_status(client)

        if map_size(status) > 0 do
          {:ok, "API reachable — #{map_size(status)} status sections fetched"}
        else
          {:error, "no API response — check base URL, credentials and TLS settings"}
        end

      {:error, reason} ->
        {:error, "cannot build the API client: #{inspect(reason)}"}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main id="main" class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="max-w-2xl p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/70" />
            Edit {@instance.name}
          </h1>
          <a
            href={~p"/instances/#{@instance.id}"}
            class="text-xs text-base-content/70 hover:text-base-content/80"
          >
            back to detail
          </a>
        </div>

        <div
          :if={@error}
          role="alert"
          class="mb-4 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form phx-change="form_change" phx-submit="save" class="space-y-4">
          <div class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">General</h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="Name" required error={@errors["name"]}>
                <input
                  name="instance[name]"
                  value={@form["name"]}
                  required
                  aria-required="true"
                  class={input_cls()}
                />
              </.field>
              <.field label="Slug (GUI vhost label)" error={@errors["slug"]}>
                <input name="instance[slug]" value={@form["slug"]} class={input_cls()} />
              </.field>
              <.field label="Base URL" error={@errors["base_url"]}>
                <input name="instance[base_url]" value={@form["base_url"]} class={input_cls()} />
              </.field>
              <.field label="Location">
                <input name="instance[location]" value={@form["location"]} class={input_cls()} />
              </.field>
              <.field label="Ping URL (availability probe)" error={@errors["ping_url"]}>
                <input name="instance[ping_url]" value={@form["ping_url"]} class={input_cls()} />
              </.field>
              <.field label="Notes">
                <input name="instance[notes]" value={@form["notes"]} class={input_cls()} />
              </.field>
              <%!-- The schema carried tags and the fleet page filters by
                   them, but no form ever wrote one — the filter chips could
                   never be populated. Same picker as the create form; the
                   value still reaches the context comma-separated. --%>
              <.tag_picker
                tags={@tags}
                known={@known_tags}
                query={@tag_query}
                open={@tag_open}
              />
            </div>
          </div>

          <div class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">
              Intervals (blank = global default)
            </h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="Poll interval (s)" error={@errors["poll_interval_seconds"]}>
                <input
                  name="instance[poll_interval_seconds]"
                  value={@form["poll_interval_seconds"]}
                  inputmode="numeric"
                  class={input_cls()}
                />
              </.field>
              <.field
                label="Push interval (s) — live-applied to a connected agent"
                error={@errors["push_interval_seconds"]}
              >
                <input
                  name="instance[push_interval_seconds]"
                  value={@form["push_interval_seconds"]}
                  inputmode="numeric"
                  class={input_cls()}
                />
              </.field>
            </div>
          </div>

          <div class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">
              Credentials <span class="text-base-content/70">(blank = keep existing)</span>
            </h2>
            <div class="grid gap-3 md:grid-cols-2">
              <.field label="API key">
                <input
                  name="instance[api_key]"
                  value={@form["api_key"]}
                  autocomplete="off"
                  class={input_cls()}
                />
              </.field>
              <.field label="API secret">
                <input
                  name="instance[api_secret]"
                  value={@form["api_secret"]}
                  type="password"
                  autocomplete="new-password"
                  class={input_cls()}
                />
              </.field>
            </div>
            <%!-- Shown with its value, unlike the credentials above it: a CA
                 bundle is public certificate material, so hiding it would
                 only stop an operator checking WHICH CA a box is pinned to.
                 That also makes submitting it empty a deliberate removal. --%>
            <.field label="CA bundle (PEM) — blank removes it; verification then falls back to the system trust store">
              <textarea
                name="instance[ca_bundle]"
                rows="4"
                spellcheck="false"
                placeholder="-----BEGIN CERTIFICATE-----"
                class={[input_cls(), "font-mono text-xs"]}
              >{@form["ca_bundle"]}</textarea>
            </.field>
            <%!-- Prove the SAVED record polls before anyone waits for the
                 next cycle to find out (UI/UX review U-M4; the Securepoint
                 SSH Test is the model). --%>
            <div :if={direct_api?(@instance)} class="mt-3 flex flex-wrap items-center gap-3 text-xs">
              <button
                type="button"
                phx-click="api_test"
                disabled={@api_testing}
                class="rounded border border-info/40 px-2 py-1 text-info hover:bg-info/15 disabled:opacity-50"
              >
                {if @api_testing, do: "Testing…", else: "Test connection"}
              </button>
              <span class="text-base-content/70">tests the saved values — save changes first</span>
              <span :if={@api_result} class={pin_class(@api_result)}>{elem(@api_result, 1)}</span>
            </div>
          </div>

          <div class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Flags</h2>
            <div class="grid gap-2 md:grid-cols-2">
              <.flag
                name="instance[ssl_verify]"
                checked={@form["ssl_verify"] == "true"}
                label="Verify TLS"
              />
              <.flag
                name="instance[gui_login_enabled]"
                checked={@form["gui_login_enabled"] == "true"}
                label="Autologin GUI"
              />
              <.flag
                :if={@admin}
                name="instance[shell_enabled]"
                checked={@form["shell_enabled"] == "true"}
                label="Terminal (root shell) — admin only"
              />
              <.flag
                name="instance[maintenance]"
                checked={@form["maintenance"] == "true"}
                label="Maintenance (checks capped)"
              />
              <.flag
                name="instance[firmware_locked]"
                checked={@form["firmware_locked"] == "true"}
                label="Lock firmware updates"
              />
            </div>
          </div>

          <%!-- SSH enrichment: only Securepoint has no agent, so only it needs
               the dashboard to log in for swanctl and the ping monitors. --%>
          <div
            :if={@instance.device_type == "securepoint"}
            class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4"
          >
            <h2 class="mb-1 text-sm font-medium text-base-content/70">SSH access</h2>
            <p class="mb-3 text-xs text-base-content/70">
              A Securepoint has no agent. With SSH the dashboard reads rich IPsec state
              via swanctl (SPIs, IKE cookies, byte counters), runs the ping monitors on
              the box and can open a terminal. See docs/securepoint-ssh.md.
            </p>

            <.flag
              name="instance[ssh_enabled]"
              checked={@form["ssh_enabled"] == "true"}
              label="SSH enrichment (rich IPsec via swanctl — SPIs, cookies, byte counters)"
            />

            <div class="mt-3 grid gap-3 md:grid-cols-2">
              <label class="block text-xs text-base-content/70">
                SSH port
                <input
                  name="instance[ssh_port]"
                  value={@form["ssh_port"]}
                  class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
                />
              </label>
              <label class="block text-xs text-base-content/70">
                SSH user
                <input
                  name="instance[ssh_user]"
                  value={@form["ssh_user"]}
                  class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
                />
              </label>
            </div>

            <label class="mt-3 block text-xs text-base-content/70">
              SSH private key (ed25519 PEM) — leave empty to keep the stored one <textarea
                name="instance[ssh_key]"
                rows="4"
                placeholder={if @instance.ssh_key_enc, do: "unchanged", else: "just gen-ssh-key"}
                class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-xs text-base-content"
              >{@form["ssh_key"]}</textarea>
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
            <.btn type="submit" variant={:primary} size={:md}>
              Save
            </.btn>
            <%!-- Second way out next to Save: the "back to detail" link in the
                 header is ~600px from where the eyes are at submit time
                 (UI/UX review U-Q3). --%>
            <a
              href={~p"/instances/#{@instance.id}"}
              class="rounded border border-base-content/20 px-3 py-1.5 text-sm text-base-content/80 hover:bg-base-300"
            >
              Cancel
            </a>
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

  def handle_async(:api_test, {:ok, result}, socket) do
    {:noreply, assign(socket, api_testing: false, api_result: result)}
  end

  def handle_async(:api_test, {:exit, reason}, socket) do
    {:noreply, assign(socket, api_testing: false, api_result: {:error, inspect(reason)})}
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
