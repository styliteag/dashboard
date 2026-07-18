defmodule OrbitWeb.InstanceDetailLive do
  @moduledoc """
  Per-instance detail: static instance record + live metrics from the hub
  section cache (raw agent sections — cpu.total_pct, memory.used_pct,
  disks[], system, uptime) + the evaluated checks for this instance — the
  per-instance surface of the four-surface parity rule, run through the same
  Orbit.Checks.Export chain the Checkmk/Prometheus/Alerts surfaces use.
  Scoped via get_instance (invariant 1): a missing or out-of-scope id
  redirects to /instances, never revealing existence.

  Refreshes metrics on a 5s live-agent tier timer and on hub roster edges.
  """

  use OrbitWeb, :live_view

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.Export
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Comments
  alias Orbit.Firmware
  alias Orbit.Hub
  alias Orbit.Instances.Instance
  alias Orbit.ConfigBackup.Store, as: CfgStore
  alias Orbit.Logs.Store, as: LogStore

  @write_roles ~w(admin user)

  @refresh_ms 5_000
  @fw_track_ms 4_000
  # Update tracking gives up after 15 min of "unknown" — the box may still be
  # working, but the UI stops implying live progress (FirmwareSection.tsx parity).
  @fw_track_grace_ms 15 * 60_000

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      if connected?(socket) do
        Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
        Process.send_after(self(), :refresh, @refresh_ms)
      end

      socket =
        socket
        |> assign(
          instance: inst,
          writable: user.role in @write_roles,
          admin: user.role == "admin",
          fw_busy: nil,
          fw_msg: nil,
          upgrading: false,
          upgrade_log: [],
          upgrade_started: nil,
          enroll_code: nil,
          agent_busy: false,
          agent_msg: nil,
          ai_busy: false,
          ai_result: nil,
          ai_error: nil,
          gui_openable: Orbit.GUI.openable(inst) == :ok
        )
        |> load_comments()
        |> load_logs()
        |> load_metrics()

      {:ok, socket}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load_metrics(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load_metrics(socket)}
  end

  def handle_info(:fw_track, %{assigns: %{upgrading: true}} = socket) do
    inst = socket.assigns.instance
    {:noreply, start_async(socket, :fw_track_status, fn -> Firmware.upgrade_status(inst) end)}
  end

  # Tracking was ended (done/gave up) while a timer tick was in flight.
  def handle_info(:fw_track, socket), do: {:noreply, socket}

  # Comment writes ride the same write-role gate as the JSON route; a view_only
  # session never sees the editors, and the handler re-checks (never trust the
  # hidden UI). Empty text deletes. source_ip is the LiveView audit seam.
  @impl true
  def handle_event("comment_save", %{"kind" => kind, "entity_key" => ek} = p, socket) do
    {:noreply, write_comment(socket, kind, ek, String.trim(p["comment"] || ""))}
  end

  def handle_event("comment_clear", %{"kind" => kind, "entity_key" => ek}, socket) do
    {:noreply, write_comment(socket, kind, ek, "")}
  end

  # Firmware actions ride the same write gate; the handler re-checks (never
  # trust the hidden UI). Commands block up to 90s, so they run in start_async
  # off the LiveView process; one action at a time (fw_busy).
  def handle_event("fw_" <> kind, _params, socket) when kind in ["check", "update", "upgrade"] do
    {:noreply, fw_start(socket, kind)}
  end

  # Agent enrollment + self-update (AgentSection parity; write-gated).
  def handle_event("mint_enroll", _params, %{assigns: %{writable: true}} = socket) do
    inst = socket.assigns.instance
    {code, expires_at} = Orbit.Enrollment.create_code(inst.id)

    Audit.write(
      action: "agent.enroll_code",
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "instance",
      target_id: inst.id
    )

    {:noreply, assign(socket, enroll_code: {code, expires_at})}
  end

  def handle_event("mint_enroll", _params, socket), do: {:noreply, socket}

  def handle_event(
        "agent_update",
        _params,
        %{assigns: %{writable: true, agent_busy: false}} = socket
      ) do
    inst = socket.assigns.instance
    user = socket.assigns.current_user

    {:noreply,
     socket
     |> assign(agent_busy: true, agent_msg: nil)
     |> start_async(:agent_update, fn -> push_agent_update(inst, user) end)}
  end

  def handle_event("agent_update", _params, socket), do: {:noreply, socket}

  # Open GUI (GUI proxy §18) — write-gated; re-checks openable (agent may
  # have dropped since render), mints the handoff URL and pushes it to the
  # browser to open. Audits agent.gui_open (source_ip is the LiveView seam).
  def handle_event("gui_open", _params, socket) do
    inst = socket.assigns.instance

    if socket.assigns.writable and Orbit.GUI.openable(inst) == :ok do
      url = Orbit.GUI.open_flow(inst, nil)

      Audit.write(
        action: "agent.gui_open",
        result: "ok",
        user_id: socket.assigns.current_user.id,
        target_type: "instance",
        target_id: inst.id
      )

      {:noreply, push_event(socket, "gui_open_url", %{url: url})}
    else
      {:noreply, socket}
    end
  end

  # AI log analysis (AiLogAnalysisSection parity) — admin-only like the raw
  # logs (the LLM sees anonymized text only, invariant 4; still an admin
  # surface). Runs async: anonymize + provider call take seconds.
  def handle_event("ai_analyze", %{"provider" => provider}, socket) do
    cond do
      not socket.assigns.admin or socket.assigns.ai_busy ->
        {:noreply, socket}

      true ->
        instance_id = socket.assigns.instance.id

        {:noreply,
         socket
         |> assign(ai_busy: true, ai_result: nil, ai_error: nil)
         |> start_async(:ai_analyze, fn ->
           Orbit.LLM.Analyze.analyze_logs(provider, log_text_for(instance_id))
         end)}
    end
  end

  # Canary mechanism (DR-6): one box per click. Same guards as the JSON route —
  # pushing the served version only trips the agent's anti-rollback (no-op).
  defp push_agent_update(inst, user) do
    with %Orbit.Hub.Agent{} = agent <- Hub.get(inst.id),
         {:ok, params} <- Orbit.Agent.Package.update_params() do
      if agent.agent_version == params["version"] do
        {:ok, "already at #{params["version"]}"}
      else
        result = Hub.send_command(inst.id, "agent.update", params, 30_000)

        result =
          if is_map(result), do: result, else: %{"success" => false, "output" => "no agent"}

        Hub.pin_update_result(inst.id, result, params["version"])

        Audit.write(
          action: "agent.update",
          result: if(result["success"], do: "ok", else: "error"),
          user_id: user.id,
          target_type: "instance",
          target_id: inst.id,
          detail: %{"version" => params["version"]}
        )

        if result["success"] do
          {:ok, "update to #{params["version"]} pushed — agent restarts"}
        else
          {:error, String.slice(to_string(result["output"] || "update failed"), 0, 200)}
        end
      end
    else
      nil -> {:error, "agent not connected"}
      {:error, :unavailable} -> {:error, "agent script not available"}
    end
  end

  defp fw_start(%{assigns: %{writable: false}} = socket, _kind), do: socket
  defp fw_start(%{assigns: %{fw_busy: busy}} = socket, _kind) when not is_nil(busy), do: socket

  defp fw_start(socket, kind) do
    inst = socket.assigns.instance
    user = socket.assigns.current_user

    action = fn ->
      case kind do
        "check" -> Firmware.check(inst, user)
        "update" -> Firmware.update(inst, user)
        "upgrade" -> Firmware.upgrade(inst, user)
      end
    end

    socket
    |> assign(fw_busy: kind, fw_msg: nil)
    |> start_async(:fw_action, fn -> {kind, action.()} end)
  end

  @impl true
  def handle_async(:fw_action, {:ok, {kind, result}}, socket) do
    socket = assign(socket, fw_busy: nil)

    case {kind, result} do
      {"check", {:ok, _msg}} ->
        {:noreply, socket |> assign(fw_msg: {:ok, "Check complete."}) |> load_metrics()}

      {_start, {:ok, _msg}} ->
        # Update/upgrade started on the box — begin live progress tracking.
        Process.send_after(self(), :fw_track, @fw_track_ms)

        {:noreply,
         assign(socket,
           fw_msg: {:ok, "#{fw_label(kind)} started — tracking progress."},
           upgrading: true,
           upgrade_log: [],
           upgrade_started: System.monotonic_time(:millisecond)
         )}

      {_kind, {:error, reason}} ->
        {:noreply, assign(socket, fw_msg: {:error, fw_error_text(kind, reason)})}
    end
  end

  def handle_async(:fw_action, {:exit, _reason}, socket) do
    {:noreply, assign(socket, fw_busy: nil, fw_msg: {:error, "Action crashed — check the logs."})}
  end

  def handle_async(:fw_track_status, {:ok, %{status: status, log: log}}, socket) do
    elapsed = System.monotonic_time(:millisecond) - (socket.assigns.upgrade_started || 0)

    cond do
      not socket.assigns.upgrading ->
        {:noreply, socket}

      status == "done" ->
        # Heal the (up to ~12h) stale on-box verdict with a fresh check, like
        # the react section does after tracking ends.
        {:noreply,
         socket
         |> assign(
           upgrading: false,
           upgrade_log: log,
           fw_msg: {:ok, "Update finished."},
           fw_busy: "check"
         )
         |> start_async(:fw_action, fw_heal_check(socket))
         |> load_metrics()}

      status == "unknown" and elapsed > @fw_track_grace_ms ->
        {:noreply,
         assign(socket,
           upgrading: false,
           fw_msg:
             {:error,
              "No progress reported for 15 minutes — the update may still be running on the box."}
         )}

      true ->
        Process.send_after(self(), :fw_track, @fw_track_ms)
        socket = if log == [], do: socket, else: assign(socket, upgrade_log: log)
        {:noreply, socket}
    end
  end

  def handle_async(:fw_track_status, {:exit, _reason}, socket) do
    Process.send_after(self(), :fw_track, @fw_track_ms)
    {:noreply, socket}
  end

  def handle_async(:agent_update, {:ok, result}, socket) do
    {:noreply, socket |> assign(agent_busy: false, agent_msg: result) |> load_metrics()}
  end

  def handle_async(:agent_update, {:exit, _}, socket) do
    {:noreply, assign(socket, agent_busy: false, agent_msg: {:error, "update push crashed"})}
  end

  def handle_async(:ai_analyze, {:ok, result}, socket) do
    case result do
      {:ok, analysis} -> {:noreply, assign(socket, ai_busy: false, ai_result: analysis)}
      {:error, reason} -> {:noreply, assign(socket, ai_busy: false, ai_error: reason)}
    end
  end

  def handle_async(:ai_analyze, {:exit, _}, socket) do
    {:noreply, assign(socket, ai_busy: false, ai_error: "analysis crashed")}
  end

  # Latest snapshot content per logfile, concatenated with file headers —
  # the analyze layer anonymizes and caps before anything leaves the box.
  defp log_text_for(instance_id) do
    Orbit.Repo.query!(
      "SELECT l.name, l.content FROM logfiles l " <>
        "JOIN (SELECT name, MAX(id) AS mid FROM logfiles WHERE instance_id = ? " <>
        "GROUP BY name) x ON x.mid = l.id ORDER BY l.name",
      [instance_id]
    ).rows
    |> Enum.map_join("\n\n", fn [name, content] -> "===== #{name} =====\n#{content}" end)
  end

  defp fw_heal_check(socket) do
    inst = socket.assigns.instance
    user = socket.assigns.current_user
    fn -> {"check", Firmware.check(inst, user)} end
  end

  defp fw_label("update"), do: "Update"
  defp fw_label("upgrade"), do: "Series upgrade"
  defp fw_label(_), do: "Check"

  defp fw_error_text(_kind, :not_connected), do: "Agent not connected."

  defp fw_error_text(_kind, :locked), do: "Firmware updates are locked for this instance."

  defp fw_error_text(kind, reason) when is_binary(reason), do: "#{fw_label(kind)}: #{reason}"

  defp write_comment(%{assigns: %{writable: false}} = socket, _kind, _ek, _text), do: socket

  defp write_comment(socket, kind, entity_key, "") do
    inst = socket.assigns.instance

    if Comments.remove(inst.id, kind, entity_key) do
      audit(socket, "comment.delete", kind, entity_key, "")
    end

    load_comments(socket)
  end

  defp write_comment(socket, kind, entity_key, text) do
    if Comments.valid_kind?(kind) do
      user = socket.assigns.current_user
      Comments.upsert(socket.assigns.instance.id, kind, entity_key, text, user.username)
      audit(socket, "comment.set", kind, entity_key, text)
    end

    load_comments(socket)
  end

  defp audit(socket, action, kind, entity_key, text) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "instance",
      target_id: socket.assigns.instance.id,
      detail: %{kind: kind, entity_key: entity_key, comment: text}
    )
  end

  defp load_comments(socket) do
    assign(socket, comments: Comments.list_for_instance(socket.assigns.instance.id))
  end

  # Logs move at push cadence (hourly), so they load once at mount and are NOT
  # re-queried on the 5s metric timer. Snapshot metadata only (no raw content —
  # that stays admin-gated behind a dedicated download route).
  defp load_logs(socket) do
    id = socket.assigns.instance.id

    assign(socket,
      logfiles: LogStore.latest_per_name(id),
      log_events: LogStore.list_events(id),
      config_backups: CfgStore.list(id)
    )
  end

  defp load_metrics(socket) do
    entry = Hub.cache_entry(socket.assigns.instance.id)
    status = entry["status"] || %{}

    assign(socket,
      connected: Hub.get(socket.assigns.instance.id) != nil,
      cpu: get_in(status, ["cpu", "total_pct"]),
      memory: status["memory"],
      disks: status["disks"] || [],
      system: status["system"] || %{},
      uptime: status["uptime"],
      # Raw ipsec section is a map %{"running", "tunnels" => [...]} — iterate the
      # tunnel list, not the map (else :for yields {k,v} tuples). Real OPNsense
      # data exposed this; synthetic pushes had used a bare list.
      ipsec: (entry["ipsec"] || %{})["tunnels"] || [],
      last_seen: entry["last_metrics_ts"],
      firmware: entry["firmware"],
      fw_verdict: Evaluate.firmware_check(entry["firmware"]),
      agent: Hub.get(socket.assigns.instance.id),
      served_agent_version: Orbit.Agent.Package.served_version(),
      gateways: entry["gateways"] || [],
      interfaces: status["interfaces"] || [],
      services: entry["services"] || [],
      external_ip: entry["external_ip"] || %{},
      pf_top: (entry["pf_top"] || %{})["interfaces"] || [],
      firewall_log: Enum.take(entry["firewall_log"] || [], 15),
      check_history: check_history(socket.assigns.instance.id),
      checks: instance_checks(socket.assigns.instance)
    )
  end

  # Recent check transitions (CheckHistorySection parity) — shared table,
  # written by both stacks' ingest.
  defp check_history(instance_id) do
    Orbit.Repo.query!(
      "SELECT ts, check_key, old_state, new_state, summary FROM check_events " <>
        "WHERE instance_id = ? ORDER BY id DESC LIMIT 20",
      [instance_id]
    ).rows
  rescue
    _ -> []
  end

  # Per-instance evaluated checks — same evaluate→overlay chain as the exports
  # and Alerts (four-surface parity). Direct-poll instances have no cached
  # sections yet (poller not ported), so only agent-mode instances get checks.
  defp instance_checks(inst) do
    if Instance.agent_mode?(inst) do
      inst
      |> Export.checks_for(DateTime.utc_now())
      |> Enum.sort_by(&{-ServiceCheck.severity(&1.state), &1.key})
    else
      []
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-6 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">{@instance.name}</h1>
          <span class={["rounded px-2 py-0.5 text-xs", conn_badge(@connected)]}>
            {if @connected, do: "agent connected", else: "no agent"}
          </span>
          <a
            :if={@instance.shell_enabled}
            href={~p"/instances/#{@instance.id}/terminal"}
            target="_blank"
            rel="noopener"
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Terminal
          </a>
          <button
            :if={@writable and @gui_openable}
            phx-click="gui_open"
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Open GUI
          </button>
          <a
            :if={@writable}
            href={~p"/instances/#{@instance.id}/capture"}
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Capture
          </a>
          <a
            :if={@writable and @instance.device_type == "opnsense"}
            href={~p"/instances/#{@instance.id}/firewall"}
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Firewall
          </a>
          <a
            :if={@writable}
            href={~p"/instances/#{@instance.id}/edit"}
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Edit
          </a>
        </div>

        <div class="grid gap-6 md:grid-cols-2">
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 class="mb-3 text-sm font-medium text-slate-400">Instance</h2>
            <dl class="space-y-1 text-sm">
              <.kv label="Type" value={@instance.device_type} />
              <.kv label="Transport" value={@instance.transport} />
              <.kv label="Base URL" value={Orbit.Instances.Instance.primary_base_url(@instance)} />
              <.kv label="Location" value={@instance.location || "—"} />
            </dl>
          </div>

          <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 class="mb-3 text-sm font-medium text-slate-400">Live</h2>
            <div :if={not @connected and @system == %{}} class="text-sm text-slate-500">
              No live data — agent not pushing.
            </div>
            <dl :if={@connected or @system != %{}} class="space-y-1 text-sm">
              <.kv label="Hostname" value={@system["hostname"] || "—"} />
              <.kv label="OS" value={@system["os"] || "—"} />
              <.kv label="Uptime" value={@uptime || "—"} />
              <.kv label="CPU" value={pct(@cpu)} />
              <.kv label="Memory" value={mem_text(@memory)} />
            </dl>
          </div>
        </div>

        <div :if={@checks != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">
            Checks <span class="text-slate-500">({length(@checks)})</span>
          </h2>
          <table class="w-full text-left text-sm">
            <tbody>
              <tr :for={c <- @checks} class="border-b border-slate-800/50 last:border-0">
                <td class="w-16 py-1.5 pr-4 align-top">
                  <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(c.state)]}>
                    {state_label(c.state)}
                  </span>
                </td>
                <td class="whitespace-nowrap py-1.5 pr-4 align-top text-slate-400">{c.key}</td>
                <td class="py-1.5 align-top text-slate-300">{c.summary}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div
          :if={Instance.agent_mode?(@instance)}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-slate-400">Agent</h2>
          <dl class="space-y-1 text-sm">
            <.kv
              label="Status"
              value={if @agent, do: "connected (#{@agent.pushes} pushes)", else: "not connected"}
            />
            <.kv :if={@agent} label="Version" value={@agent.agent_version || "?"} />
            <.kv :if={@agent} label="Platform" value={@agent.platform || "?"} />
            <.kv label="Served version" value={@served_agent_version || "—"} />
            <.kv
              :if={@agent && @agent.last_update_error}
              label="Last update error"
              value={"#{@agent.last_update_version}: #{@agent.last_update_error}"}
            />
          </dl>

          <div :if={@writable} class="mt-3 flex flex-wrap items-center gap-2">
            <button
              phx-click="mint_enroll"
              class="rounded border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              Mint enroll code
            </button>
            <button
              :if={@agent && @served_agent_version && @agent.agent_version != @served_agent_version}
              phx-click="agent_update"
              data-confirm={"Push agent #{@served_agent_version} to #{@instance.name}? The agent restarts (canary: one box at a time)."}
              disabled={@agent_busy}
              class="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @agent_busy,
                do: "Pushing…",
                else: "Push agent update → #{@served_agent_version}"}
            </button>
          </div>

          <div :if={@enroll_code} class="mt-2 text-sm">
            <span class="text-slate-500">Enroll code: </span>
            <span class="font-mono text-emerald-300">{elem(@enroll_code, 0)}</span>
            <span class="text-xs text-slate-500">
              (valid until {cb_ts(elem(@enroll_code, 1))} — run install.sh on the box and paste it)
            </span>
          </div>

          <div
            :if={@agent_msg}
            class={[
              "mt-2 text-xs",
              elem(@agent_msg, 0) == :ok && "text-emerald-400",
              elem(@agent_msg, 0) == :error && "text-red-400"
            ]}
          >
            {elem(@agent_msg, 1)}
          </div>
        </div>

        <div
          :if={Instance.agent_mode?(@instance)}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 flex items-center gap-2 text-sm font-medium text-slate-400">
            Firmware
            <span
              :if={@instance.firmware_locked}
              class="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-amber-300"
            >
              updates locked
            </span>
            <span
              :if={@fw_verdict}
              class={["rounded px-1.5 py-0.5 text-xs", state_class(@fw_verdict.state)]}
            >
              {state_label(@fw_verdict.state)}
            </span>
          </h2>

          <div :if={is_nil(@firmware)} class="text-sm text-slate-500">
            No firmware data yet — run a check or wait for the next push.
          </div>

          <dl :if={@firmware} class="space-y-1 text-sm">
            <.kv label="Installed" value={@firmware["product_version"] || "—"} />
            <.kv
              :if={@firmware["upgrade_available"]}
              label="Available"
              value={@firmware["product_latest"] || "?"}
            />
            <.kv :if={truthy_str(@firmware["branch"])} label="Branch" value={@firmware["branch"]} />
            <.kv :if={@fw_verdict} label="Status" value={@fw_verdict.summary} />
            <.kv
              :if={truthy_str(@firmware["last_check"])}
              label="Last check"
              value={@firmware["last_check"]}
            />
          </dl>

          <div :if={@writable} class="mt-3 flex flex-wrap items-center gap-2">
            <button
              phx-click="fw_check"
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "check", do: "Checking…", else: "Check for updates"}
            </button>
            <button
              :if={not @instance.firmware_locked}
              phx-click="fw_update"
              data-confirm={"Start the firmware update on #{@instance.name}? The box may reboot."}
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "update", do: "Starting…", else: "Start update"}
            </button>
            <button
              :if={
                not @instance.firmware_locked and
                  truthy_str(@firmware && @firmware["upgrade_major_version"])
              }
              phx-click="fw_upgrade"
              data-confirm={"Start the SERIES upgrade to #{@firmware["upgrade_major_version"]} on #{@instance.name}? This is a major version jump; the box will reboot."}
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded bg-amber-700 px-3 py-1 text-xs text-white hover:bg-amber-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "upgrade",
                do: "Starting…",
                else: "Series upgrade → #{@firmware["upgrade_major_version"]}"}
            </button>
          </div>

          <div
            :if={@fw_msg}
            class={[
              "mt-2 text-xs",
              elem(@fw_msg, 0) == :ok && "text-emerald-400",
              elem(@fw_msg, 0) == :error && "text-red-400"
            ]}
          >
            {elem(@fw_msg, 1)}
          </div>

          <div :if={@upgrading} class="mt-3">
            <div class="mb-1 text-xs text-amber-300">Update running…</div>
            <pre
              :if={@upgrade_log != []}
              class="max-h-48 overflow-y-auto rounded bg-slate-950 p-2 text-xs text-slate-400"
            >{Enum.join(Enum.take(@upgrade_log, -20), "\n")}</pre>
          </div>
        </div>

        <div :if={@disks != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">Disks</h2>
          <ul class="space-y-1 text-sm">
            <li :for={d <- @disks} class="flex justify-between text-slate-300">
              <span class="text-slate-400">{d["mountpoint"] || d["device"]}</span>
              <span>{pct(d["used_pct"])}</span>
            </li>
          </ul>
        </div>

        <div :if={@ipsec != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">IPsec tunnels</h2>
          <ul class="space-y-1 text-sm">
            <li :for={t <- @ipsec} class="flex justify-between text-slate-300">
              <span class="text-slate-400">{t["description"] || t["id"] || "tunnel"}</span>
              <span class={tunnel_color(t["status"])}>{t["status"] || "?"}</span>
            </li>
          </ul>
        </div>

        <div :if={@gateways != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">Gateways</h2>
          <table class="w-full text-left text-sm">
            <thead class="text-slate-500">
              <tr class="border-b border-slate-800">
                <th class="py-1 pr-4 font-medium">Name</th>
                <th class="py-1 pr-4 font-medium">Address</th>
                <th class="py-1 pr-4 font-medium">Status</th>
                <th class="py-1 pr-4 font-medium">Delay</th>
                <th class="py-1 font-medium">Loss</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={g <- @gateways} class="border-b border-slate-800/50 last:border-0">
                <td class="py-1.5 pr-4 text-slate-300">{g["name"]}</td>
                <td class="py-1.5 pr-4 font-mono text-xs text-slate-400">{g["address"] || "—"}</td>
                <td class="py-1.5 pr-4">
                  <span class={gw_color(g["status"])}>{g["status"] || "?"}</span>
                </td>
                <td class="py-1.5 pr-4 text-slate-400">{g["delay"] || "—"}</td>
                <td class="py-1.5 text-slate-400">{g["loss"] || "—"}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div :if={@interfaces != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">Interfaces</h2>
          <table class="w-full text-left text-sm">
            <thead class="text-slate-500">
              <tr class="border-b border-slate-800">
                <th class="py-1 pr-4 font-medium">Name</th>
                <th class="py-1 pr-4 font-medium">Address</th>
                <th class="py-1 pr-4 font-medium">Status</th>
                <th class="py-1 pr-4 font-medium">RX/s</th>
                <th class="py-1 pr-4 font-medium">TX/s</th>
                <th class="py-1 font-medium">Errors in/out</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={i <- @interfaces} class="border-b border-slate-800/50 last:border-0">
                <td class="py-1.5 pr-4 text-slate-300">{i["name"]}</td>
                <td class="py-1.5 pr-4 font-mono text-xs text-slate-400">{i["address"] || "—"}</td>
                <td class="py-1.5 pr-4">
                  <span class={
                    if(i["status"] == "up", do: "text-emerald-400", else: "text-slate-500")
                  }>
                    {i["status"] || "?"}
                  </span>
                </td>
                <td class="py-1.5 pr-4 text-slate-400">{rate(i["rx_rate"])}</td>
                <td class="py-1.5 pr-4 text-slate-400">{rate(i["tx_rate"])}</td>
                <td class="py-1.5 text-slate-400">{i["in_errors"] || 0}/{i["out_errors"] || 0}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="mt-6 grid gap-6 md:grid-cols-2">
          <div :if={@services != []} class="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 class="mb-3 text-sm font-medium text-slate-400">Services</h2>
            <ul class="space-y-1 text-sm">
              <li :for={s <- @services} class="flex justify-between text-slate-300">
                <span class="text-slate-400">{s["description"] || s["name"]}</span>
                <span class={if(s["running"], do: "text-emerald-400", else: "text-red-400")}>
                  {if s["running"], do: "running", else: "stopped"}
                </span>
              </li>
            </ul>
          </div>

          <div
            :if={@external_ip != %{} or @pf_top != []}
            class="rounded-lg border border-slate-800 bg-slate-900 p-4"
          >
            <h2 class="mb-3 text-sm font-medium text-slate-400">Network</h2>
            <dl :if={@external_ip != %{}} class="mb-3 space-y-1 text-sm">
              <.kv label="External IPv4" value={@external_ip["ipv4"] || "—"} />
              <.kv label="External IPv6" value={@external_ip["ipv6"] || "—"} />
            </dl>
            <div :if={@pf_top != []}>
              <div class="mb-1 text-xs text-slate-500">Top talkers (pf states)</div>
              <ul class="space-y-1 text-sm">
                <li :for={t <- Enum.take(@pf_top, 8)} class="flex justify-between text-slate-300">
                  <span class="text-slate-400">{t["name"]}</span>
                  <span>{bytes(t["bytes"])} · {t["states"]} states</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div
          :if={@check_history != []}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-slate-400">Check history</h2>
          <table class="w-full text-left text-sm">
            <tbody>
              <tr
                :for={[ts, key, old, new, summary] <- @check_history}
                class="border-b border-slate-800/50 last:border-0"
              >
                <td class="whitespace-nowrap py-1.5 pr-3 font-mono text-xs text-slate-500">
                  {cb_ts(ts)}
                </td>
                <td class="py-1.5 pr-3 align-top">
                  <span class={["rounded px-1.5 py-0.5 text-xs", state_class(new)]}>
                    {state_label(old)} → {state_label(new)}
                  </span>
                </td>
                <td class="whitespace-nowrap py-1.5 pr-3 text-slate-400">{key}</td>
                <td class="py-1.5 text-slate-300">{summary}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div
          :if={@firewall_log != []}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-slate-400">Firewall log (latest)</h2>
          <table class="w-full text-left text-sm">
            <tbody>
              <tr :for={l <- @firewall_log} class="border-b border-slate-800/50 last:border-0">
                <td class="whitespace-nowrap py-1 pr-3 font-mono text-xs text-slate-500">
                  {l["__timestamp__"]}
                </td>
                <td class="py-1 pr-3">
                  <span class={fw_action_color(l["action"])}>{l["action"]}</span>
                </td>
                <td class="py-1 pr-3 text-slate-400">{l["interface"]}</td>
                <td class="py-1 pr-3 text-slate-400">{l["protoname"] || l["proto"]}</td>
                <td class="py-1 font-mono text-xs text-slate-300">
                  {l["src"] || l["srcip"]} → {l["dst"] || l["dstip"]}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div
          :if={@logfiles != [] or @log_events != []}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-slate-400">Logs</h2>
          <div
            :if={@logfiles != []}
            class="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500"
          >
            <a
              :for={lf <- @logfiles}
              :if={@admin}
              href={~p"/api/instances/#{@instance.id}/logfiles/#{lf.id}/raw"}
              target="_blank"
              class="text-slate-400 underline decoration-slate-700 hover:text-emerald-300"
            >
              {lf.name} · {lf.bytes} chars
            </a>
            <span :for={lf <- @logfiles} :if={not @admin}>{lf.name} · {lf.bytes} chars</span>
          </div>
          <table :if={@log_events != []} class="w-full text-left text-sm">
            <tbody>
              <tr
                :for={e <- Enum.take(@log_events, 15)}
                class="border-b border-slate-800/50 last:border-0"
              >
                <td class="w-14 py-1.5 pr-3 align-top">
                  <span class={["rounded px-1.5 py-0.5 text-xs", sev_class(e.severity)]}>
                    {sev_label(e.severity)}
                  </span>
                </td>
                <td class="whitespace-nowrap py-1.5 pr-3 align-top text-slate-400">{e.program}</td>
                <td class="py-1.5 align-top text-slate-300">{e.pattern}</td>
                <td class="w-10 py-1.5 pl-3 text-right align-top text-slate-400">{e.count}</td>
              </tr>
            </tbody>
          </table>
          <div :if={@log_events == [] and @logfiles != []} class="text-xs text-slate-500">
            No critical events in the latest snapshots.
          </div>

          <form
            :if={@admin and @logfiles != []}
            phx-submit="ai_analyze"
            class="mt-3 flex items-center gap-2 border-t border-slate-800 pt-3"
          >
            <select
              name="provider"
              class="rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-300"
            >
              <option :for={p <- Orbit.LLM.Analyze.providers()} value={p.id}>{p.label}</option>
            </select>
            <button
              type="submit"
              disabled={@ai_busy}
              class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @ai_busy, do: "Analyzing…", else: "Analyze with AI"}
            </button>
            <span class="text-xs text-slate-600">anonymized before it leaves the box</span>
          </form>

          <div :if={@ai_error} class="mt-2 text-xs text-red-400">{@ai_error}</div>

          <div :if={@ai_result} class="mt-3 rounded border border-slate-800 bg-slate-950 p-3">
            <div class="mb-2 text-xs text-slate-500">
              {@ai_result.provider} · {@ai_result.model}
            </div>
            <pre class="whitespace-pre-wrap text-xs text-slate-300">{@ai_result.findings}</pre>
          </div>
        </div>

        <div
          :if={@config_backups != []}
          class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-slate-400">
            Config backups <span class="text-slate-500">({length(@config_backups)})</span>
          </h2>
          <table class="w-full text-left text-sm">
            <tbody>
              <tr
                :for={cb <- @config_backups}
                class="border-b border-slate-800/50 last:border-0"
              >
                <td class="py-1.5 pr-4 text-slate-300">{cb_ts(cb.collected_at)}</td>
                <td class="py-1.5 pr-4 font-mono text-xs text-slate-500">
                  {String.slice(cb.sha256, 0, 12)}
                </td>
                <td class="py-1.5 pr-4 text-slate-400">{cb.bytes} bytes · {cb.source}</td>
                <td class="py-1.5 text-right">
                  <a
                    :if={@admin}
                    href={~p"/api/instances/#{@instance.id}/config-backups/#{cb.id}/diff"}
                    target="_blank"
                    class="mr-3 text-xs text-slate-400 hover:text-emerald-300"
                  >
                    diff
                  </a>
                  <a
                    :if={@admin}
                    href={~p"/api/instances/#{@instance.id}/config-backups/#{cb.id}/raw"}
                    target="_blank"
                    class="text-xs text-emerald-400 hover:text-emerald-300"
                  >
                    download
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">Notes</h2>

          <form :if={@writable} phx-submit="comment_save" class="mb-4 space-y-2">
            <div class="flex gap-2">
              <select
                name="kind"
                class="rounded border border-slate-700 bg-slate-950 p-1 text-sm text-slate-200"
              >
                <option value="firmware">firmware</option>
                <option value="ipsec">ipsec</option>
                <option value="connectivity">connectivity</option>
                <option value="cert">cert</option>
              </select>
              <input
                name="entity_key"
                value=""
                placeholder="entity key — tunnel id / monitor id / cert refid (blank for firmware)"
                class="flex-1 rounded border border-slate-700 bg-slate-950 p-1 text-sm text-slate-200"
              />
            </div>
            <textarea
              name="comment"
              rows="2"
              class="w-full rounded border border-slate-700 bg-slate-950 p-2 text-sm text-slate-200"
              placeholder="operator note…"
            ></textarea>
            <button
              type="submit"
              class="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600"
            >
              Add note
            </button>
          </form>

          <div :if={@comments == []} class="text-sm text-slate-500">No notes on this instance.</div>

          <ul :if={@comments != []} class="space-y-2 text-sm">
            <li
              :for={c <- @comments}
              class="flex items-start justify-between gap-3 border-b border-slate-800/50 pb-2"
            >
              <div>
                <div class="text-slate-300">{c.comment}</div>
                <div class="mt-0.5 text-xs text-slate-500">
                  {c.kind}<span :if={c.entity_key != ""}>:{c.entity_key}</span> · {c.updated_by}
                </div>
              </div>
              <button
                :if={@writable}
                phx-click="comment_clear"
                phx-value-kind={c.kind}
                phx-value-entity_key={c.entity_key}
                class="shrink-0 rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-400 hover:bg-slate-800"
              >
                Clear
              </button>
            </li>
          </ul>
        </div>
      </section>
    </main>
    """
  end

  attr :label, :string, required: true
  attr :value, :string, required: true

  defp kv(assigns) do
    ~H"""
    <div class="flex justify-between">
      <dt class="text-slate-500">{@label}</dt>
      <dd class="text-slate-200">{@value}</dd>
    </div>
    """
  end

  defp conn_badge(true), do: "bg-emerald-900/50 text-emerald-300"
  defp conn_badge(false), do: "bg-slate-800 text-slate-500"

  defp truthy_str(value), do: value not in [nil, ""]

  # Interface rates carry the -1.0 no-data sentinel (first push after restart).
  defp rate(v) when is_number(v) and v >= 0, do: bytes(v) <> "/s"
  defp rate(_), do: "—"

  defp bytes(v) when is_number(v) and v >= 1_073_741_824,
    do: "#{Float.round(v / 1_073_741_824, 1)} GB"

  defp bytes(v) when is_number(v) and v >= 1_048_576, do: "#{Float.round(v / 1_048_576, 1)} MB"
  defp bytes(v) when is_number(v) and v >= 1024, do: "#{Float.round(v / 1024, 1)} KB"
  defp bytes(v) when is_number(v), do: "#{round(v)} B"
  defp bytes(_), do: "—"

  @gw_up ~w(online up none)
  defp gw_color(status) do
    case status |> to_string() |> String.downcase() do
      s when s in @gw_up -> "text-emerald-400"
      "" -> "text-slate-500"
      _ -> "text-red-400"
    end
  end

  defp fw_action_color("pass"), do: "text-emerald-400"
  defp fw_action_color("block"), do: "text-red-400"
  defp fw_action_color(_), do: "text-amber-400"

  defp pct(nil), do: "—"
  defp pct(v) when is_number(v), do: "#{Float.round(v / 1, 1)}%"
  defp pct(_), do: "—"

  defp mem_text(%{"used_pct" => up, "total_mb" => tot})
       when is_number(up) and is_number(tot) and tot > 0 do
    "#{Float.round(up / 1, 1)}% of #{round(tot)} MB"
  end

  # Some agents (the Linux node) report used_pct without a usable total_mb —
  # show just the percentage instead of a nonsensical "of 0 MB".
  defp mem_text(%{"used_pct" => up}) when is_number(up), do: "#{Float.round(up / 1, 1)}%"

  defp mem_text(_), do: "—"

  # Raw ipsec tunnel status is mixed-case (ESTABLISHED/down/…); mirror the ipsec
  # check family's up-set. Empty/unknown stays amber, an explicit down goes red.
  @tunnel_up ~w(up established installed connected 1 true yes)
  defp tunnel_color(status) do
    case status |> to_string() |> String.downcase() do
      s when s in @tunnel_up -> "text-emerald-400"
      s when s in ["", "?"] -> "text-amber-400"
      _ -> "text-red-400"
    end
  end

  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(3), do: "UNKNOWN"
  defp state_label(_), do: "OK"

  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(3), do: "bg-slate-700 text-slate-300"
  defp state_class(_), do: "bg-emerald-900/50 text-emerald-300"

  defp cb_ts(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")

  # Syslog severity (0 emerg … 4 warning; lower = worse) for the Logs section.
  defp sev_label(s) when s <= 2, do: "CRIT"
  defp sev_label(3), do: "ERR"
  defp sev_label(_), do: "WARN"

  defp sev_class(s) when s <= 2, do: "bg-red-900/60 text-red-300"
  defp sev_class(3), do: "bg-orange-900/50 text-orange-300"
  defp sev_class(_), do: "bg-amber-900/50 text-amber-300"
end
