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
       tab: "general",
       flash_key: nil,
       llm_busy: nil,
       llm_result: nil,
       restart_armed: false,
       restarting: false
     )}
  end

  @impl true
  def handle_event("set_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, tab: tab, llm_result: nil)}
  end

  # Click-driven saves (switches/checkboxes) carry the new value as "val":
  # on click events LiveView merges the element's DOM `value` attribute into
  # the params as "value" (empty string for a bare <button>), CLOBBERING a
  # phx-value-value — so the click path must use a different param name.
  # This clause must come first: click params contain both "val" and "value".
  @impl true
  def handle_event("save", %{"key" => key, "val" => value}, socket) do
    save_setting(key, value, socket)
  end

  def handle_event("save", %{"key" => key, "value" => value}, socket) do
    save_setting(key, value, socket)
  end

  # One-off provider ping (SettingsPage LLM test-button parity): a tiny
  # prompt through the real analyze path proves key+base_url+model.
  def handle_event("llm_test", %{"provider" => provider}, socket) do
    {:noreply,
     socket
     |> assign(llm_busy: provider, llm_result: nil)
     |> start_async(:llm_test, fn ->
       case Orbit.LLM.Analyze.analyze_logs(provider, "ping — reply with the single word: pong") do
         # analyze_logs returns {:ok, %{findings: text, ...}} — slicing the
         # whole map (and non-binary error terms) crashed the async task.
         {:ok, %{findings: text}} ->
           {:ok, provider, String.slice(to_string(text), 0, 120)}

         {:error, msg} ->
           {:error, provider, String.slice(to_string(msg), 0, 200)}
       end
     end)}
  end

  def handle_event("clear", %{"key" => key}, socket) do
    Settings.clear_override(key)
    audit(socket, "settings.clear", "ok", %{"name" => key})
    {:noreply, socket |> assign(rows: load_rows()) |> put_flash(:info, "#{key} reset to default")}
  end

  # Two-step confirm (RestartBackend parity): first click arms for 5s, the
  # second one audits and stops the BEAM after the reply flushed — the
  # container restart policy brings up a fresh process, LiveView reconnects.
  def handle_event("restart_backend", _params, socket) do
    cond do
      socket.assigns.restarting ->
        {:noreply, socket}

      not socket.assigns.restart_armed ->
        Process.send_after(self(), :disarm_restart, 5_000)
        {:noreply, assign(socket, restart_armed: true)}

      true ->
        audit(socket, "settings.restart", "ok", nil)
        Process.send_after(self(), :do_restart, 500)
        {:noreply, assign(socket, restart_armed: false, restarting: true)}
    end
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

  @impl true
  def handle_info(:disarm_restart, socket) do
    {:noreply, assign(socket, restart_armed: false)}
  end

  def handle_info(:do_restart, socket) do
    # Graceful BEAM stop; supervised shutdown, then the container restarts.
    System.stop(0)
    {:noreply, socket}
  end

  defp save_setting(key, value, socket) do
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

  defp audit(socket, action, result, detail) do
    Orbit.Audit.write(
      action: action,
      result: result,
      user_id: socket.assigns.current_user.id,
      detail: detail
    )
  end

  defp load_rows do
    order = Registry.ordered_keys() |> Enum.with_index() |> Map.new()

    Registry.editable()
    |> Map.values()
    |> Enum.map(fn defn ->
      effective = to_string(Settings.effective(defn.key))
      meta = Registry.meta(defn.key)

      %{
        key: defn.key,
        type: defn.type,
        secret: defn.is_secret,
        options: defn.options,
        min: defn.min,
        max: defn.max,
        label: meta.label,
        help: meta.help,
        group: meta.group,
        restart: meta.restart,
        overridden: Settings.overridden?(defn.key),
        # Secrets never render by value (invariant 3): set/not-set only.
        default: if(defn.is_secret, do: "", else: System.get_env(defn.env, defn.default)),
        effective: if(defn.is_secret, do: secret_state(effective), else: effective),
        input: if(defn.is_secret, do: "", else: effective)
      }
    end)
    # Curated definition order (GeneralSettings parity), not alphabetical.
    |> Enum.sort_by(&Map.get(order, &1.key, 999))
  end

  # Tabs (SettingsPage parity). Each tab shows one or more registry groups;
  # the channel/checkmk tabs additionally render their mute/toggle + test.
  @tabs [
    {"general", "General", ["Polling", "Retention", "GUI proxy", "Service", "Other"]},
    {"mattermost", "Mattermost", ["Mattermost"]},
    {"telegram", "Telegram", ["Telegram"]},
    {"email", "Email", ["Email"]},
    {"ai", "AI", ["OpenAI", "Anthropic", "OpenRouter"]},
    {"checkmk", "Checkmk", ["Checkmk"]},
    {"prometheus", "Prometheus", []}
  ]

  def tabs, do: @tabs

  # Rows of one tab as {group, rows} sections in the tab's declared group
  # order, empty groups skipped (GeneralSettings section headers parity).
  defp sections_for_tab(rows, tab) do
    groups = Enum.find_value(@tabs, [], fn {k, _, gs} -> if k == tab, do: gs end)

    groups
    |> Enum.map(fn group -> {group, Enum.filter(rows, &(&1.group == group))} end)
    |> Enum.reject(fn {_group, rows} -> rows == [] end)
  end

  # The per-channel mute toggle lives on that channel's tab (not the field list).
  defp mute_row(rows, key), do: Enum.find(rows, &(&1.key == key))

  defp secret_state(""), do: "(not set)"
  defp secret_state(_), do: "•••• (set)"

  @impl true
  def render(assigns) do
    assigns = assign(assigns, tab_sections: sections_for_tab(assigns.rows, assigns.tab))

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:settings} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-1 text-lg font-medium text-base-content">Settings</h1>
        <p class="mb-4 text-xs text-base-content/60">
          Override the defaults that otherwise come from the environment / <code>.env</code>.
          Infra and security settings (database URL, master key, proxy hops…) stay
          environment-only.
        </p>

        <nav class="mb-6 flex flex-wrap gap-1 border-b border-base-300 pb-2">
          <button
            :for={{key, label, _groups} <- tabs()}
            phx-click="set_tab"
            phx-value-tab={key}
            class={[
              "rounded-md px-3 py-1 text-sm",
              if(@tab == key,
                do: "bg-base-300 font-medium text-primary",
                else: "text-base-content/70 hover:bg-base-300/60 hover:text-base-content"
              )
            ]}
          >
            {label}
          </button>
        </nav>

        <p
          :if={@flash[:info]}
          class="mb-3 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-sm text-primary"
        >
          {@flash[:info]}
        </p>
        <p
          :if={@flash[:error]}
          class="mb-3 rounded-md border border-error/40 bg-error/15 px-3 py-2 text-sm text-error"
        >
          {@flash[:error]}
        </p>

        <%!-- Channel/Checkmk tabs: the mute/blackout switch comes FIRST
             (SettingsPage order — MuteToggle above the connection fields). --%>
        <div :if={@tab in ["mattermost", "telegram", "email"]} class="mb-5">
          <.mute_toggle
            :if={mute_row(@rows, "notify_#{@tab}_muted")}
            row={mute_row(@rows, "notify_#{@tab}_muted")}
            title={"Temporarily mute #{String.capitalize(@tab)} alerts"}
            idle_note={"#{String.capitalize(@tab)} alerts are delivered normally."}
            active_note={"#{String.capitalize(@tab)} alerts are paused — real alerts are not sent."}
            active_badge={"Muted — no #{String.capitalize(@tab)} alerts sent"}
            hint="Manual toggle — stays until you switch it back. An explicit “Send test” below still fires."
          />
        </div>
        <div :if={@tab == "checkmk"} class="mb-5 space-y-3">
          <p class="max-w-3xl text-sm text-base-content/70">
            Connect Checkmk to the dashboard and choose which service checks are exported.
            See <code class="rounded bg-base-300 px-1 py-0.5 text-xs">CHECKMK.md</code>
            for the full integration guide. Changing the aggregate toggle alters which
            services Checkmk discovers — re-inventorize the hosts afterwards.
          </p>
          <.mute_toggle
            :if={mute_row(@rows, "checkmk_blackout")}
            row={mute_row(@rows, "checkmk_blackout")}
            title="Checkmk blackout"
            idle_note="The Checkmk export includes all instances and their checks."
            active_note="The Checkmk export is empty — Checkmk sees every service as stale/gone."
            active_badge="Blackout — export empty"
            hint="Manual toggle — stays until you switch it back. Use during maintenance to silence Checkmk."
          />
        </div>

        <%!-- Settings-bearing tabs: one card per registry group with an
             uppercase section header, rows divided (GeneralSettings parity). --%>
        <div class="space-y-5">
          <section
            :for={{group, rows} <- @tab_sections}
            class="rounded-xl border border-base-300 bg-base-200/60 p-5"
          >
            <h4 class="text-xs font-semibold uppercase tracking-wide text-base-content/50">
              {group}
            </h4>
            <div class="mt-1 divide-y divide-base-300/60">
              <.setting_row :for={r <- rows} row={r} />
            </div>
          </section>
        </div>

        <p :if={@tab_sections != []} class="mt-3 text-xs text-base-content/40">
          “Needs restart” settings take effect after the next backend restart; all others
          apply live.
        </p>

        <p
          :if={
            @tab_sections == [] and
              @tab not in ["mattermost", "telegram", "email", "checkmk", "prometheus"]
          }
          class="text-sm text-base-content/60"
        >
          No settings in this tab.
        </p>

        <%!-- General tab: restart card (applies needs-restart settings). --%>
        <div
          :if={@tab == "general"}
          class="mt-4 rounded-lg border border-base-300 bg-base-200/60 p-4"
        >
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div class="min-w-0">
              <span class="text-sm font-medium text-base-content">Backend service</span>
              <p class="mt-0.5 text-xs text-base-content/60">
                Restart the backend process to apply “needs restart” settings. Takes a few
                seconds — the UI reconnects automatically, agents re-attach on their own.
              </p>
            </div>
            <button
              phx-click="restart_backend"
              disabled={@restarting}
              class={[
                "shrink-0 rounded px-3 py-1.5 text-sm text-white disabled:opacity-40",
                if(@restart_armed,
                  do: "bg-error hover:bg-error/80",
                  else: "bg-neutral hover:bg-neutral/80"
                )
              ]}
            >
              {cond do
                @restart_armed -> "Click again to restart"
                @restarting -> "Restarting…"
                true -> "Restart backend"
              end}
            </button>
          </div>
          <p :if={@restarting} class="mt-2 text-xs text-warning">
            Backend is restarting — this page reconnects automatically once it is back.
          </p>
        </div>

        <%!-- Channel tabs: per-channel selection tree (with its own
             test-send) below the connection fields. --%>
        <div :if={@tab in ["mattermost", "telegram", "email"]} class="mt-4">
          <.live_component
            module={OrbitWeb.Components.SelectionTree}
            id={"seltree-#{@tab}"}
            consumer={@tab}
            current_user={@current_user}
          />
        </div>

        <%!-- AI tab: provider test buttons. --%>
        <div :if={@tab == "ai"} class="mt-4">
          <div class="flex flex-wrap gap-2">
            <button
              :for={p <- Orbit.LLM.Analyze.providers()}
              phx-click="llm_test"
              phx-value-provider={p.id}
              disabled={@llm_busy != nil}
              class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300 disabled:opacity-50"
            >
              {if @llm_busy == p.id, do: "Testing…", else: "Test #{p.label}"}
            </button>
          </div>
          <div
            :if={@llm_result}
            class={[
              "mt-3 rounded px-3 py-2 text-sm",
              case @llm_result do
                {:ok, _} -> "bg-primary/10 text-primary"
                _ -> "bg-error/15 text-error"
              end
            ]}
          >
            {elem(@llm_result, 1)}
          </div>
        </div>

        <%!-- Checkmk tab: api keys link + export tree below the fields. --%>
        <div :if={@tab == "checkmk"} class="mt-4 space-y-4">
          <a href={~p"/apikeys"} class="inline-block text-sm text-primary hover:underline">
            Manage Checkmk API keys →
          </a>
          <.live_component
            module={OrbitWeb.Components.SelectionTree}
            id="seltree-checkmk"
            consumer="checkmk"
            current_user={@current_user}
          />
        </div>

        <%!-- Prometheus tab: no settings, just the api key surface. --%>
        <div :if={@tab == "prometheus"} class="mt-4">
          <p class="mb-2 text-sm text-base-content/70">
            Prometheus scrapes <code>/api/export/prometheus</code> with a read-only API key.
          </p>
          <a href={~p"/apikeys"} class="text-sm text-primary hover:underline">
            Manage Prometheus API keys →
          </a>
        </div>
      </section>
    </main>
    """
  end

  # One rich setting row: label + badges, help, key/default line, typed input.
  # Bools save on click (GeneralSettings checkbox parity); everything else
  # submits through its Save button.
  attr :row, :map, required: true

  defp setting_row(assigns) do
    ~H"""
    <div class="flex flex-wrap items-start justify-between gap-3 py-3">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-sm font-medium text-base-content">{@row.label}</span>
          <span
            :if={not @row.overridden}
            class="rounded bg-base-300 px-1.5 py-0.5 text-[10px] text-base-content/60"
          >
            {if @row.secret, do: "not set", else: "default"}
          </span>
          <span
            :if={@row.overridden}
            class="rounded bg-primary/20 px-1.5 py-0.5 text-[10px] text-primary"
          >
            {if @row.secret, do: "set", else: "custom"}
          </span>
          <span
            :if={@row.restart}
            class="rounded bg-warning/20 px-1.5 py-0.5 text-[10px] text-warning"
          >
            needs restart
          </span>
        </div>
        <p :if={@row.help != ""} class="mt-0.5 text-xs text-base-content/60">{@row.help}</p>
        <p class="mt-0.5 font-mono text-[11px] text-base-content/40">
          {@row.key}{if not @row.secret and @row.default not in [nil, ""],
            do: " · default #{@row.default}"}
        </p>
      </div>

      <div :if={@row.type == :bool} class="flex shrink-0 items-center gap-2">
        <input
          type="checkbox"
          checked={@row.effective in ["true", "1"]}
          phx-click="save"
          phx-value-key={@row.key}
          phx-value-val={to_string(@row.effective not in ["true", "1"])}
          class="h-4 w-4 cursor-pointer accent-primary"
        />
        <button
          :if={@row.overridden}
          type="button"
          phx-click="clear"
          phx-value-key={@row.key}
          title="Reset to the environment default"
          class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
        >
          ↺
        </button>
      </div>

      <form :if={@row.type != :bool} phx-submit="save" class="flex shrink-0 items-center gap-2">
        <input type="hidden" name="key" value={@row.key} />
        <select
          :if={@row.type == :str and @row.options not in [nil, []]}
          name="value"
          class="rounded border border-base-content/20 bg-base-100 px-2 py-1 text-sm text-base-content focus:border-primary focus:outline-none"
        >
          <option :for={o <- @row.options} value={o} selected={@row.input == o}>{o}</option>
        </select>
        <input
          :if={not (@row.type == :str and @row.options not in [nil, []])}
          type={
            cond do
              @row.secret -> "password"
              @row.type == :int -> "number"
              true -> "text"
            end
          }
          name="value"
          value={@row.input}
          min={@row.min}
          max={@row.max}
          placeholder={
            cond do
              @row.secret and @row.overridden -> "•••••• (set — type to replace)"
              @row.secret -> "not set"
              true -> nil
            end
          }
          autocomplete="off"
          class={[
            if(@row.secret, do: "w-64", else: "w-28"),
            "rounded border border-base-content/20 bg-base-100 px-2 py-1 text-sm text-base-content focus:border-primary focus:outline-none"
          ]}
        />
        <button
          type="submit"
          class="rounded bg-primary px-2 py-1 text-xs text-white hover:bg-primary/80"
        >
          Save
        </button>
        <button
          :if={@row.overridden}
          type="button"
          phx-click="clear"
          phx-value-key={@row.key}
          title="Reset to the environment default"
          class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
        >
          ↺
        </button>
      </form>
    </div>
    """
  end

  # A bool setting as a status-first mute/blackout card (MuteToggle.tsx
  # parity): a real slider switch shows the STATE (right+amber = active),
  # the sub-line and badge say what is happening right now — never an
  # ambiguous action label like "turn on".
  attr :row, :map, required: true
  attr :title, :string, required: true
  attr :idle_note, :string, required: true
  attr :active_note, :string, required: true
  attr :active_badge, :string, required: true
  attr :hint, :string, default: nil

  defp mute_toggle(assigns) do
    on = assigns.row.effective in ["true", "1"]
    assigns = assign(assigns, on: on)

    ~H"""
    <div class={[
      "rounded-xl border p-5",
      if(@on, do: "border-warning/40 bg-warning/5", else: "border-base-300 bg-base-200/60")
    ]}>
      <div class="flex items-center justify-between gap-4">
        <div>
          <h3 class="text-sm font-semibold text-base-content">{@title}</h3>
          <p class="mt-0.5 text-xs text-base-content/60">
            {if @on, do: @active_note, else: @idle_note}
          </p>
          <p :if={@hint} class="mt-0.5 text-xs text-base-content/40">{@hint}</p>
        </div>

        <button
          type="button"
          role="switch"
          aria-checked={to_string(@on)}
          aria-label={@title}
          phx-click="save"
          phx-value-key={@row.key}
          phx-value-val={to_string(not @on)}
          title={if @on, do: "Active — click to switch off", else: "Inactive — click to switch on"}
          class={[
            "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors",
            if(@on, do: "bg-warning", else: "bg-base-300")
          ]}
        >
          <span class={[
            "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
            if(@on, do: "translate-x-6", else: "translate-x-1")
          ]}></span>
        </button>
      </div>

      <div
        :if={@on}
        class="mt-3 inline-flex items-center gap-1.5 rounded bg-warning/20 px-2 py-1 text-xs text-warning"
      >
        {@active_badge}
      </div>
    </div>
    """
  end
end
