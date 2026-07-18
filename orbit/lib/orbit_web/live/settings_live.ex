defmodule OrbitWeb.SettingsLive do
  @moduledoc """
  Editable settings (admin-only, config surface). Shows every whitelisted key
  with its effective value + env default; a form per key writes a DB override
  via Orbit.Settings.set_override (validated by the registry), or clears it
  back to the default. First mutating LiveView — the form pattern the rest of
  the admin surfaces reuse.

  Admin gate is the on_mount hook (require_admin); the write itself is
  re-validated in the context, so a crafted request can't set a bad value.
  """

  use OrbitWeb, :live_view

  alias Orbit.Settings
  alias Orbit.Settings.Registry

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       rows: load_rows(),
       flash_key: nil,
       test_busy: false,
       test_results: nil,
       llm_busy: nil,
       llm_result: nil
     )}
  end

  @impl true
  def handle_event("save", %{"key" => key, "value" => value}, socket) do
    secret? = match?({:ok, %{is_secret: true}}, Registry.fetch(key))

    cond do
      # Empty submit on a secret keeps the stored value (invariant 3 shape —
      # the field renders blank, so an untouched form must not wipe it).
      secret? and String.trim(value) == "" ->
        {:noreply, put_flash(socket, :info, "#{key} unchanged (blank keeps the stored value)")}

      true ->
        case Settings.set_override(key, value) do
          {:ok, _} ->
            audit(socket, "settings.update", "ok", %{"name" => key})
            {:noreply, socket |> assign(rows: load_rows()) |> put_flash(:info, "#{key} saved")}

          {:error, msg} ->
            {:noreply, put_flash(socket, :error, msg)}
        end
    end
  end

  # Connectivity test to every configured channel — bypasses routing/mutes
  # (notifier.send_test parity); channel sends block up to 10s each, so async.
  def handle_event("notify_test", _params, socket) do
    if socket.assigns.test_busy do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(test_busy: true, test_results: nil)
       |> start_async(:notify_test, fn -> Orbit.Notifier.send_test() end)}
    end
  end

  # One-off provider ping (SettingsPage LLM test-button parity): a tiny
  # prompt through the real analyze path proves key+base_url+model.
  def handle_event("llm_test", %{"provider" => provider}, socket) do
    {:noreply,
     socket
     |> assign(llm_busy: provider, llm_result: nil)
     |> start_async(:llm_test, fn ->
       case Orbit.LLM.Analyze.analyze_logs(provider, "ping — reply with the single word: pong") do
         {:ok, text} -> {:ok, provider, String.slice(text, 0, 120)}
         {:error, msg} -> {:error, provider, String.slice(to_string(msg), 0, 200)}
       end
     end)}
  end

  def handle_event("clear", %{"key" => key}, socket) do
    Settings.clear_override(key)
    audit(socket, "settings.clear", "ok", %{"name" => key})
    {:noreply, socket |> assign(rows: load_rows()) |> put_flash(:info, "#{key} reset to default")}
  end

  @impl true
  def handle_async(:notify_test, {:ok, results}, socket) do
    {:noreply, assign(socket, test_busy: false, test_results: results)}
  end

  def handle_async(:notify_test, {:exit, _}, socket) do
    {:noreply, assign(socket, test_busy: false, test_results: [])}
  end

  # LiveView has no conn; source_ip is a documented seam (peer_data via
  # get_connect_info lands with the access-log port). user_id is the record.
  @impl true
  def handle_async(:llm_test, {:ok, outcome}, socket) do
    result =
      case outcome do
        {:ok, provider, text} -> {:ok, "#{provider}: #{text}"}
        {:error, provider, msg} -> {:error, "#{provider}: #{msg}"}
      end

    {:noreply, assign(socket, llm_busy: nil, llm_result: result)}
  end

  def handle_async(:llm_test, {:exit, _}, socket) do
    {:noreply, assign(socket, llm_busy: nil, llm_result: {:error, "test crashed"})}
  end

  defp audit(socket, action, result, detail) do
    Orbit.Audit.write(
      action: action,
      result: result,
      user_id: socket.assigns.current_user.id,
      detail: detail
    )
  end

  defp load_rows do
    Registry.editable()
    |> Map.values()
    |> Enum.sort_by(& &1.key)
    |> Enum.map(fn defn ->
      effective = to_string(Settings.effective(defn.key))

      %{
        key: defn.key,
        type: defn.type,
        secret: defn.is_secret,
        # Secrets never render by value (invariant 3): set/not-set only.
        default: if(defn.is_secret, do: "", else: System.get_env(defn.env, defn.default)),
        effective: if(defn.is_secret, do: secret_state(effective), else: effective),
        input: if(defn.is_secret, do: "", else: effective),
        group: group_for(defn.key)
      }
    end)
  end

  # Section grouping by key prefix (SettingsPage tabs, condensed to headed
  # sections — python's registry carries an explicit group, the orbit key
  # names encode the same information).
  @group_order ["Polling & agents", "Retention", "Notifications", "AI providers", "Other"]

  def group_order, do: @group_order

  defp group_for("notify_" <> _), do: "Notifications"
  defp group_for("llm_" <> _), do: "AI providers"

  defp group_for(key) do
    cond do
      String.ends_with?(key, "_retention_days") -> "Retention"
      String.starts_with?(key, "poll") or String.starts_with?(key, "push") -> "Polling & agents"
      String.starts_with?(key, "agent_") -> "Polling & agents"
      true -> "Other"
    end
  end

  defp secret_state(""), do: "(not set)"
  defp secret_state(_), do: "•••• (set)"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:settings} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-base-content">Settings</h1>
          <button
            phx-click="notify_test"
            disabled={@test_busy}
            class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {if @test_busy, do: "Sending…", else: "Send test notification"}
          </button>
          <a href={~p"/selection"} class="text-xs text-base-content/60 hover:text-base-content/80">
            selection rules
          </a>
          <a href={~p"/apikeys"} class="text-xs text-base-content/60 hover:text-base-content/80">
            api keys
          </a>
        </div>

        <div
          :if={@test_results}
          class="mb-4 rounded-lg border border-base-300 bg-base-200 p-3 text-sm"
        >
          <div :for={r <- @test_results} class="flex items-center gap-2">
            <span class="w-24 text-base-content/70">{r.channel}</span>
            <span class={[
              r.status == "sent" && "text-primary",
              r.status == "failed" && "text-error",
              r.status == "skipped" && "text-base-content/60"
            ]}>
              {r.status}{if r.detail != "", do: " — #{r.detail}"}
            </span>
          </div>
        </div>

        <p
          :if={@flash[:info]}
          class="mb-3 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-sm text-primary"
        >
          {@flash[:info]}
        </p>
        <p
          :if={@flash[:error]}
          class="mb-3 rounded-md border border-error/40 bg-error/10 px-3 py-2 text-sm text-error"
        >
          {@flash[:error]}
        </p>

        <div
          :if={@llm_result}
          class={[
            "mb-4 rounded px-3 py-2 text-sm",
            case @llm_result do
              {:ok, _} -> "bg-primary/15 text-primary"
              _ -> "bg-error/15 text-error"
            end
          ]}
        >
          {elem(@llm_result, 1)}
        </div>

        <section
          :for={group <- group_order()}
          :if={Enum.any?(@rows, &(&1.group == group))}
          class="mb-8"
        >
          <div class="mb-2 flex items-center gap-3">
            <h2 class="text-sm font-semibold text-base-content/70">{group}</h2>
            <div :if={group == "AI providers"} class="flex gap-1">
              <button
                :for={p <- Orbit.LLM.Analyze.providers()}
                phx-click="llm_test"
                phx-value-provider={p.id}
                disabled={@llm_busy != nil}
                class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300 disabled:opacity-50"
              >
                {if @llm_busy == p.id, do: "Testing…", else: "Test #{p.label}"}
              </button>
            </div>
          </div>
          <table class="w-full text-left text-sm">
            <thead class="text-base-content/60">
              <tr class="border-b border-base-300">
                <th class="py-2 pr-4 font-medium">Key</th>
                <th class="py-2 pr-4 font-medium">Effective</th>
                <th class="py-2 pr-4 font-medium">Default</th>
                <th class="py-2 pr-4 font-medium">Set</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @rows} :if={r.group == group} class="border-b border-base-300/50">
                <td class="py-2 pr-4 text-base-content">{r.key}</td>
                <td class="py-2 pr-4 text-primary">{r.effective}</td>
                <td class="py-2 pr-4 text-base-content/60">{r.default}</td>
                <td class="py-2 pr-4">
                  <%!-- Bool settings (the notify mutes) save on click. --%>
                  <form :if={r.type == :bool} phx-submit="save" class="flex items-center gap-2">
                    <input type="hidden" name="key" value={r.key} />
                    <input
                      type="hidden"
                      name="value"
                      value={if r.effective in ["true", "1"], do: "false", else: "true"}
                    />
                    <button
                      type="submit"
                      class={[
                        "rounded px-2 py-1 text-xs",
                        if(r.effective in ["true", "1"],
                          do: "bg-warning text-white hover:bg-warning/80",
                          else: "border border-base-content/20 text-base-content/80 hover:bg-base-300"
                        )
                      ]}
                    >
                      {if r.effective in ["true", "1"], do: "muted — unmute", else: "mute"}
                    </button>
                    <button
                      type="button"
                      phx-click="clear"
                      phx-value-key={r.key}
                      class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
                    >
                      Reset
                    </button>
                  </form>
                  <form :if={r.type != :bool} phx-submit="save" class="flex items-center gap-2">
                    <input type="hidden" name="key" value={r.key} />
                    <input
                      type={if r.secret, do: "password", else: "text"}
                      name="value"
                      value={r.input}
                      placeholder={if r.secret, do: "blank = keep", else: nil}
                      autocomplete="off"
                      class="w-24 rounded border border-base-content/20 bg-base-100 px-2 py-1 text-base-content focus:border-primary focus:outline-none"
                    />
                    <button
                      type="submit"
                      class="rounded bg-primary px-2 py-1 text-xs text-white hover:bg-primary/80"
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      phx-click="clear"
                      phx-value-key={r.key}
                      class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
                    >
                      Reset
                    </button>
                  </form>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </section>
    </main>
    """
  end
end
