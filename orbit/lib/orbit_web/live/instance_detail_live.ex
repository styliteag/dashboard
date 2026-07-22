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

  import OrbitWeb.Components.ConnectivityMonitorDialog, only: [connectivity_monitor_dialog: 1]
  import OrbitWeb.Components.CheckHistoryDialog, only: [check_history_dialog: 1]
  import OrbitWeb.Components.PingMonitorDialog, only: [ping_monitor_dialog: 1]
  import OrbitWeb.Components.InstanceTabs, only: [instance_tabs: 1, tabs_for: 1]
  import OrbitWeb.Components.TunnelHistoryDialog, only: [tunnel_history_dialog: 1]

  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]
  import OrbitWeb.Components.ListKit, only: [base_url_link: 1]

  alias OrbitWeb.Components.CommentEditor

  import OrbitWeb.Components.MetricChart

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
  # Metric history re-reads on the old UI's 60s refetch tier — the 5s live
  # tier would hammer the metrics table with six bucketing queries per tick.
  @charts_refresh_ms 60_000
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
        Process.send_after(self(), :charts_refresh, @charts_refresh_ms)
      end

      socket =
        socket
        |> assign(
          instance: inst,
          page_title: inst.name,
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
          gui_openable: Orbit.GUI.openable(inst) == :ok,
          chart_range: "24h",
          ipsec_busy: MapSet.new(),
          ipsec_msg: nil,
          ipsec_expanded: MapSet.new(),
          conn_editor: nil,
          conn_test: nil,
          conn_test_busy: false,
          ping_editor: nil,
          ping_test: nil,
          ping_test_busy: false,
          show_token: false,
          install_open: false,
          cb_diff: nil,
          diagnosis: nil,
          diagnosis_busy: nil,
          diag_ai_busy: false,
          diag_ai_result: nil,
          diag_ai_error: nil,
          history: nil,
          monitor_history: nil,
          upgrade_confirm: "",
          upgrade_confirm_open: false
        )
        |> load_comments()
        |> load_logs()
        |> load_metrics()
        |> load_charts()
        |> load_monitors()

      {:ok, socket}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  # Tab from the URL path (/instances/7/checks; legacy ?tab= bookmarks land
  # here too since path and query params merge) — patch-navigation keeps the
  # LiveView mounted; an unknown or not-available tab (e.g. "agent" on a
  # Securepoint) falls back to overview, mirroring the react TABS fallback.
  @impl true
  def handle_params(params, _uri, socket) do
    valid =
      for {key, _label, :tab} <- tabs_for(socket.assigns.instance), do: key

    tab = if params["tab"] in valid, do: params["tab"], else: "overview"
    socket = assign(socket, tab: tab)

    # `?enroll=1` is how the create form says "this box was just made, it needs
    # a code" — an intent flag, never the code itself: a secret in a URL lands
    # in history, logs and referrers. Minted once (guarded on the assign) and
    # the flag is patched out, so a reload does not mint a second code.
    if params["enroll"] == "1" and is_nil(socket.assigns.enroll_code) and
         socket.assigns.writable and Instance.agent_mode?(socket.assigns.instance) do
      {:noreply,
       socket
       |> mint_enroll_code()
       |> push_patch(to: ~p"/instances/#{socket.assigns.instance.id}?tab=agent", replace: true)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load_metrics(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load_metrics(socket)}
  end

  def handle_info(:charts_refresh, socket) do
    Process.send_after(self(), :charts_refresh, @charts_refresh_ms)
    {:noreply, load_charts(socket)}
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

  # Per-box notify/export toggle (ChecksSection parity): an existing
  # instance rule is removed (back to the global default); otherwise a new
  # instance rule pins the OPPOSITE of the current live resolution.
  # Write-gated; selector/consumer re-validated (never trust the DOM).
  def handle_event(
        "check_toggle",
        %{"consumer" => consumer, "key" => key},
        %{assigns: %{writable: true}} = socket
      ) do
    inst = socket.assigns.instance

    if Orbit.Selection.valid_consumer?(consumer) and
         Orbit.Selection.valid_selector?(consumer, key) do
      if MapSet.member?(socket.assigns.check_rules, {consumer, key}) do
        Orbit.Selection.delete_rule(consumer, key, inst.id)
      else
        mode =
          if Orbit.Selection.is_on_live(consumer, key, inst.id), do: "exclude", else: "include"

        Orbit.Selection.set_rule(consumer, key, mode, inst.id)
      end

      Audit.write(
        action: "selection.rule.toggle",
        result: "ok",
        user_id: socket.assigns.current_user.id,
        target_type: "instance",
        target_id: inst.id,
        detail: %{"consumer" => consumer, "selector" => key}
      )

      {:noreply, load_metrics(socket)}
    else
      {:noreply, socket}
    end
  end

  def handle_event("check_toggle", _params, socket), do: {:noreply, socket}

  # Range switch is read-only — no write gate. Unknown values fall back to
  # 24h inside Orbit.Metrics, so a forged phx-value can't break the queries.
  def handle_event("chart_range", %{"range" => range}, socket)
      when range in ~w(1h 6h 24h 7d 30d) do
    {:noreply, socket |> assign(chart_range: range) |> load_charts()}
  end

  # IPsec tunnel actions (IPsecSection parity) — write-gated, agent-relayed
  # (ipsec.connect/disconnect/restart in the agent's _COMMANDS; restart goes
  # through the agent's safe reload path, never `service strongswan restart`).
  # Reconnect = best-effort disconnect of the live SA, then re-initiate.
  def handle_event("ipsec_toggle", %{"id" => id}, socket) do
    expanded = socket.assigns.ipsec_expanded

    expanded =
      if MapSet.member?(expanded, id),
        do: MapSet.delete(expanded, id),
        else: MapSet.put(expanded, id)

    {:noreply, assign(socket, ipsec_expanded: expanded)}
  end

  # Readable diagnostic bundle for one tunnel (ipsec.diagnose relay) — raw
  # text per section, deliberately not over-parsed (python parity).
  def handle_event("ipsec_diagnose", %{"id" => id}, socket) do
    inst = socket.assigns.instance

    if socket.assigns.diagnosis_busy do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(diagnosis_busy: id, diagnosis: nil, diag_ai_result: nil, diag_ai_error: nil)
       |> start_async(:ipsec_diagnose, fn ->
         # Transport split: an agent builds the bundle on the box and relays
         # it; a Securepoint has no agent and never will, so the same
         # information is gathered over the SSH session the swanctl
         # enrichment already uses. Before this the button simply did
         # nothing on those boxes.
         if Instance.agent_mode?(inst) do
           result = Hub.send_command(inst.id, "ipsec.diagnose", %{"tunnel_id" => id}, 30_000)
           if is_map(result), do: {id, result}, else: {id, %{"success" => false}}
         else
           sections = Orbit.Securepoint.Diagnose.run(inst, id)
           {id, %{"success" => true, "sections" => sections}}
         end
       end)}
    end
  end

  def handle_event("fw_log_dismiss", _params, socket) do
    {:noreply, assign(socket, upgrade_log: [], upgrade_started: nil)}
  end

  # Tunnel history / graph, same dialog the fleet VPN page uses. An operator
  # debugging ONE tunnel lands here, not on the fleet page, and had no way
  # into the transition timeline at all.
  def handle_event("history_open", %{"tunnel" => tunnel_id} = params, socket) do
    inst = socket.assigns.instance

    # @ipsec is the tunnel LIST here (the fleet page keeps a struct list) —
    # reading it as a map crashed the LiveView on the first click.
    # Rows key on id, falling back to description (same expression the table
    # uses), so the lookup has to accept both.
    live =
      Enum.find(socket.assigns.ipsec || [], fn t ->
        to_string(t["id"] || t["description"] || "tunnel") == tunnel_id
      end)

    {:noreply,
     assign(socket,
       history:
         history_assign(
           %{
             mode: if(params["mode"] == "graph", do: :graph, else: :history),
             instance_id: inst.id,
             instance_name: inst.name,
             tunnel_id: tunnel_id,
             label: params["label"] || tunnel_id,
             up: params["up"] == "true",
             phase2_up: (live && live["phase2_up"]) || 0,
             phase2_total: (live && live["phase2_total"]) || 0
           },
           "7d"
         )
     )}
  end

  # Same window semantics as the fleet page (Ipsec.History.window_start/2), so
  # "7d" cannot come to mean two different things on two pages.
  def handle_event("history_window", %{"window" => window}, socket) do
    case socket.assigns.history do
      nil -> {:noreply, socket}
      h -> {:noreply, assign(socket, history: history_assign(h, window))}
    end
  end

  def handle_event("history_close", _params, socket) do
    {:noreply, assign(socket, history: nil)}
  end

  # Monitor timeline. The instance is already scoped by mount, so only the
  # monitor id comes off the DOM — and it is used solely to name a check key
  # read under this instance's id, never to reach another box's rows.
  def handle_event("monitor_history_open", %{"id" => raw_id}, socket) do
    inst = socket.assigns.instance
    mon = Enum.find(socket.assigns.conn_monitors || [], &(to_string(&1.id) == to_string(raw_id)))

    if mon do
      result = Enum.find(socket.assigns.connectivity || [], &(&1["id"] == mon.id))

      {:noreply,
       assign(socket,
         monitor_history: %{
           instance_name: inst.name,
           label: mon.name,
           live_state: ping_check_state(result),
           events: Orbit.Checks.History.read(inst.id, "connectivity:#{mon.id}")
         }
       )}
    else
      {:noreply, socket}
    end
  end

  def handle_event("monitor_history_close", _params, socket) do
    {:noreply, assign(socket, monitor_history: nil)}
  end

  # "Analyse with AI" on the IPsec bundle (DiagnoseDialog parity). The old
  # dialog offered this for EVERY device type — it was gated on a configured
  # provider, never on agent presence — and the port dropped it: only the Log
  # tab kept an analyse button. The bundle is flattened to text and goes
  # through the same Orbit.LLM.Analyze path as the logs, so the anonymiser
  # and the character caps apply unchanged (invariant 4).
  def handle_event("diag_ai_analyze", %{"provider" => provider}, socket) do
    cond do
      not socket.assigns.admin or socket.assigns.diag_ai_busy ->
        {:noreply, socket}

      is_nil(socket.assigns.diagnosis) ->
        {:noreply, socket}

      true ->
        text = diagnosis_text(socket.assigns.diagnosis)

        {:noreply,
         socket
         |> assign(diag_ai_busy: true, diag_ai_result: nil, diag_ai_error: nil)
         |> start_async(:diag_ai_analyze, fn ->
           Orbit.LLM.Analyze.analyze_logs(provider, text)
         end)}
    end
  end

  def handle_event("ipsec_diagnose_close", _params, socket) do
    {:noreply,
     assign(socket,
       diagnosis: nil,
       diag_ai_result: nil,
       diag_ai_error: nil,
       diag_ai_busy: false
     )}
  end

  def handle_event("ipsec_recheck", _params, socket) do
    inst = socket.assigns.instance

    {:noreply,
     start_async(socket, :ipsec_recheck, fn ->
       Hub.send_command(inst.id, "status.refresh", %{}, 20_000)
     end)}
  end

  def handle_event("ipsec_" <> kind, %{"id" => id} = params, socket)
      when kind in ["connect", "disconnect", "reconnect"] do
    cond do
      not socket.assigns.writable or MapSet.member?(socket.assigns.ipsec_busy, id) ->
        {:noreply, socket}

      true ->
        inst = socket.assigns.instance
        user = socket.assigns.current_user
        uid = params["uid"] || ""

        {:noreply,
         socket
         |> assign(ipsec_busy: MapSet.put(socket.assigns.ipsec_busy, id))
         |> start_async({:ipsec_action, id}, fn ->
           ipsec_action(kind, inst, user, id, uid)
         end)}
    end
  end

  def handle_event("ipsec_restart", _params, %{assigns: %{writable: true}} = socket) do
    inst = socket.assigns.instance
    user = socket.assigns.current_user

    {:noreply,
     start_async(socket, {:ipsec_action, "__restart__"}, fn ->
       result = Hub.send_command(inst.id, "ipsec.restart", %{}, 60_000)
       result = if is_map(result), do: result, else: %{"success" => false}
       audit_ipsec(user, inst, "ipsec.restart", result)

       if result["success"],
         do: {:ok, "IPsec service restarted"},
         else: {:error, to_string(result["output"] || "restart failed")}
     end)}
  end

  def handle_event("ipsec_restart", _params, socket), do: {:noreply, socket}

  # Firmware actions ride the same write gate; the handler re-checks (never
  # trust the hidden UI). Commands block up to 90s, so they run in start_async
  # off the LiveView process; one action at a time (fw_busy).
  def handle_event("fw_" <> kind, _params, socket) when kind in ["check", "update"] do
    {:noreply, fw_start(socket, kind)}
  end

  # A series upgrade is a major version jump that reboots a customer's
  # firewall and cannot be undone from here. A browser confirm() is one
  # reflexive Enter away, and it looked identical to the ordinary update's
  # confirm right beside it. Typing the box's name makes the operator read
  # WHICH box they are about to jump.
  # Gated so the dialog does not lie to a read-only operator: fw_start/2 would
  # refuse them anyway (the role gate is the real one, and the typed name is
  # friction on top of it), but offering the prompt and then doing nothing is
  # worse than not offering it.
  def handle_event("fw_upgrade", _params, %{assigns: %{writable: true}} = socket) do
    {:noreply, assign(socket, upgrade_confirm: "", upgrade_confirm_open: true)}
  end

  def handle_event("fw_upgrade", _params, socket), do: {:noreply, socket}

  def handle_event("fw_upgrade_typing", %{"name" => typed}, socket) do
    {:noreply, assign(socket, upgrade_confirm: typed)}
  end

  def handle_event("fw_upgrade_cancel", _params, socket) do
    {:noreply, assign(socket, upgrade_confirm_open: false, upgrade_confirm: "")}
  end

  # Checked HERE, not in the browser: the dialog is a prompt, the gate is this
  # comparison. A crafted event without the matching name does nothing.
  def handle_event("fw_upgrade_confirm", %{"name" => typed}, socket) do
    if String.trim(typed) == socket.assigns.instance.name do
      {:noreply,
       socket
       |> assign(upgrade_confirm_open: false, upgrade_confirm: "")
       |> fw_start("upgrade")}
    else
      {:noreply, assign(socket, upgrade_confirm: typed)}
    end
  end

  # Agent enrollment + self-update (AgentSection parity; write-gated).
  def handle_event("mint_enroll", _params, %{assigns: %{writable: true}} = socket) do
    {:noreply, mint_enroll_code(socket)}
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

  # Agent lifecycle (AgentSection parity; management.py port). All
  # write-gated; the slow relay calls run in start_async.
  def handle_event("agent_enable", _params, %{assigns: %{writable: true}} = socket) do
    case Orbit.Instances.enable_agent(socket.assigns.instance) do
      {:ok, inst, _token} ->
        audit_agent(socket, "agent.enable", "ok")
        {:noreply, socket |> assign(instance: inst) |> load_metrics()}

      _ ->
        {:noreply, assign(socket, agent_msg: {:error, "enable failed"})}
    end
  end

  def handle_event("agent_disable", _params, %{assigns: %{writable: true}} = socket) do
    case Orbit.Instances.disable_agent(socket.assigns.instance) do
      {:ok, inst} ->
        Hub.unregister(inst.id)
        audit_agent(socket, "agent.disable", "ok")
        {:noreply, socket |> assign(instance: inst, show_token: false) |> load_metrics()}

      _ ->
        {:noreply, assign(socket, agent_msg: {:error, "disable failed"})}
    end
  end

  # Server-held, deliberately not a native <details>: this tab re-renders on the
  # live agent tier, and a LiveView patch drops the browser's `open` state, so
  # the panel snapped shut a second after every click — reproduced in dev, the
  # block was unusable and the copy button unreachable.
  def handle_event("toggle_install", _params, socket) do
    {:noreply, assign(socket, install_open: not socket.assigns.install_open)}
  end

  def handle_event("agent_show_token", _params, %{assigns: %{writable: true}} = socket) do
    # The token is a bearer credential to the agent WS — write-gated like
    # the python /agent/token route; never audited into detail (no values).
    {:noreply, assign(socket, show_token: not socket.assigns.show_token)}
  end

  def handle_event("agent_" <> kind, _params, %{assigns: %{writable: true}} = socket)
      when kind in ["refresh", "reconnect", "uninstall", "test_api"] do
    inst = socket.assigns.instance
    user = socket.assigns.current_user
    agent = Hub.get(inst.id)

    {:noreply,
     socket
     |> assign(agent_msg: nil)
     |> start_async({:agent_action, kind}, fn ->
       agent_lifecycle_action(kind, inst, user, agent)
     end)}
  end

  # Non-writable fallback for every agent_* lifecycle event above.
  def handle_event("agent_" <> _kind, _params, socket), do: {:noreply, socket}

  # Standalone connectivity monitors (ConnectivitySection parity) — every
  # mutation re-pushes the set to the agent so probing starts immediately.
  def handle_event("conn_open", params, %{assigns: %{writable: true}} = socket) do
    mon =
      case Integer.parse(to_string(params["id"] || "")) do
        {id, ""} -> Enum.find(socket.assigns.conn_monitors, &(&1.id == id))
        _ -> nil
      end

    editor = %{
      instance_name: socket.assigns.instance.name,
      monitor_id: mon && mon.id,
      name: (mon && mon.name) || "",
      source: (mon && mon.source) || "",
      destination: (mon && mon.destination) || "",
      ping_count: (mon && mon.ping_count) || 3,
      enabled: is_nil(mon) or mon.enabled
    }

    {:noreply, assign(socket, conn_editor: editor, conn_test: nil)}
  end

  def handle_event("conn_cancel", _params, socket) do
    {:noreply, assign(socket, conn_editor: nil, conn_test: nil)}
  end

  # Keep the editor in step with the form so Test probes what is on screen.
  def handle_event("conn_change", %{"monitor" => attrs}, socket) do
    case socket.assigns.conn_editor do
      nil ->
        {:noreply, socket}

      editor ->
        {:noreply,
         assign(socket,
           conn_editor: %{
             editor
             | name: attrs["name"] || "",
               source: attrs["source"] || "",
               destination: attrs["destination"] || "",
               ping_count: attrs["ping_count"] || editor.ping_count,
               enabled: attrs["enabled"] == "true"
           }
         )}
    end
  end

  # Write-gated: a test sends real traffic from the box.
  def handle_event("conn_test", _params, socket) do
    editor = socket.assigns.conn_editor

    if not socket.assigns.writable or socket.assigns.conn_test_busy or is_nil(editor) do
      {:noreply, socket}
    else
      inst = socket.assigns.instance

      {:noreply,
       socket
       |> assign(conn_test_busy: true, conn_test: nil)
       |> start_async(:conn_test, fn ->
         Orbit.Monitors.ping_test(inst, editor.source, editor.destination, editor.ping_count)
       end)}
    end
  end

  def handle_event("conn_save", %{"monitor" => attrs}, %{assigns: %{writable: true}} = socket) do
    editor = socket.assigns.conn_editor
    iid = socket.assigns.instance.id

    result =
      case editor.monitor_id do
        nil -> Orbit.Monitors.create_connectivity(iid, attrs)
        mid -> Orbit.Monitors.update_connectivity(iid, mid, attrs)
      end

    case result do
      :ok ->
        audit_agent(socket, "connectivity.monitor.create", "ok")
        {:noreply, socket |> assign(conn_editor: nil, conn_test: nil) |> load_monitors()}

      {:error, msg} ->
        {:noreply, assign(socket, conn_test: {:error, msg})}
    end
  end

  def handle_event("conn_delete", %{"id" => raw}, %{assigns: %{writable: true}} = socket) do
    {id, ""} = Integer.parse(raw)
    :ok = Orbit.Monitors.delete_connectivity(socket.assigns.instance.id, id)
    audit_agent(socket, "connectivity.monitor.delete", "ok")
    {:noreply, socket |> assign(conn_editor: nil, conn_test: nil) |> load_monitors()}
  end

  def handle_event("conn_" <> _kind, _params, socket), do: {:noreply, socket}

  # Phase-2 ping monitors — the same dialog the fleet VPN page uses
  # (OrbitWeb.Components.PingMonitorDialog), not a second inline spelling.
  # Test runs one ping on the CURRENT form values before anything is saved,
  # through whichever transport this box has (Monitors.ping_test/4).
  def handle_event("p2mon_open", params, %{assigns: %{writable: true}} = socket) do
    inst = socket.assigns.instance
    child = params["child"] || ""

    mon =
      Enum.find(socket.assigns.ipsec_monitors, fn m ->
        m.tunnel_id == params["tunnel"] and to_string(m.child_name || "") == child
      end)

    editor = %{
      instance_id: inst.id,
      instance_name: inst.name,
      tunnel_id: params["tunnel"] || "",
      child_name: child,
      local_ts: params["lts"] || "",
      remote_ts: params["rts"] || "",
      monitor_id: mon && mon.id,
      source: (mon && mon.source) || params["suggested"] || "",
      destination: (mon && mon.destination) || "",
      ping_count: (mon && mon.ping_count) || 3,
      enabled: is_nil(mon) or mon.enabled
    }

    {:noreply, assign(socket, ping_editor: editor, ping_test: nil)}
  end

  def handle_event("p2mon_cancel", _params, socket) do
    {:noreply, assign(socket, ping_editor: nil, ping_test: nil)}
  end

  # Keep the form's values in the editor so Test probes what is on screen.
  def handle_event("p2mon_change", %{"mon" => attrs}, socket) do
    case socket.assigns.ping_editor do
      nil ->
        {:noreply, socket}

      editor ->
        {:noreply,
         assign(socket,
           ping_editor: %{
             editor
             | source: attrs["source"] || "",
               destination: attrs["destination"] || "",
               ping_count: attrs["ping_count"] || editor.ping_count,
               enabled: attrs["enabled"] == "true"
           }
         )}
    end
  end

  # Write-gated: a test sends real traffic from the box.
  def handle_event("p2mon_test", _params, socket) do
    editor = socket.assigns.ping_editor

    if not socket.assigns.writable or socket.assigns.ping_test_busy or is_nil(editor) do
      {:noreply, socket}
    else
      inst = socket.assigns.instance

      {:noreply,
       socket
       |> assign(ping_test_busy: true, ping_test: nil)
       |> start_async(:ping_test, fn ->
         Orbit.Monitors.ping_test(inst, editor.source, editor.destination, editor.ping_count)
       end)}
    end
  end

  def handle_event("p2mon_save", %{"mon" => attrs}, %{assigns: %{writable: true}} = socket) do
    editor = socket.assigns.ping_editor

    attrs =
      Map.merge(attrs, %{
        "tunnel_id" => editor.tunnel_id,
        "child_name" => editor.child_name,
        "local_ts" => editor.local_ts,
        "remote_ts" => editor.remote_ts
      })

    result =
      case editor.monitor_id do
        nil -> Orbit.Monitors.create_ipsec(socket.assigns.instance.id, attrs)
        mid -> Orbit.Monitors.update_ipsec(socket.assigns.instance.id, mid, attrs)
      end

    case result do
      :ok ->
        audit_agent(socket, "ipsec.ping_monitor.create", "ok")
        {:noreply, socket |> assign(ping_editor: nil, ping_test: nil) |> load_monitors()}

      {:error, msg} ->
        {:noreply, assign(socket, ping_test: {:error, msg})}
    end
  end

  def handle_event("p2mon_delete", %{"id" => raw}, %{assigns: %{writable: true}} = socket) do
    {id, ""} = Integer.parse(raw)
    :ok = Orbit.Monitors.delete_ipsec(socket.assigns.instance.id, id)
    audit_agent(socket, "ipsec.ping_monitor.delete", "ok")
    {:noreply, socket |> assign(ping_editor: nil, ping_test: nil) |> load_monitors()}
  end

  def handle_event("p2mon_" <> _kind, _params, socket), do: {:noreply, socket}

  # Inline config-backup diff (admin-only, same gate as the raw links).
  def handle_event("cb_diff", %{"from" => from, "to" => to}, %{assigns: %{admin: true}} = socket) do
    with {fid, ""} <- Integer.parse(from),
         {tid, ""} <- Integer.parse(to),
         {:ok, text, truncated} <- CfgStore.diff_between(socket.assigns.instance.id, fid, tid) do
      diff =
        case String.trim(text) do
          "" -> {:no_changes}
          _ -> {:lines, String.split(text, "\n"), truncated}
        end

      {:noreply, assign(socket, cb_diff: diff)}
    else
      _ -> {:noreply, assign(socket, cb_diff: {:no_changes})}
    end
  end

  def handle_event("cb_diff", _params, socket), do: {:noreply, socket}

  def handle_event("cb_diff_clear", _params, socket) do
    {:noreply, assign(socket, cb_diff: nil)}
  end

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

  # The diagnose bundle as one text blob for the analyser: section titles
  # kept as headings so the model can tell swanctl output from the log tail.
  # Agent boxes need a live connection to relay ipsec.diagnose; a Securepoint
  # gathers over its own SSH session, so gating it on @connected (which is
  # agent presence) disabled the button there permanently.
  defp diagnose_disabled?(instance, busy, connected) do
    busy != nil or (Instance.agent_mode?(instance) and not connected)
  end

  defp diagnosis_text(%{sections: sections}) when is_list(sections) do
    Enum.map_join(sections, "\n\n", fn s ->
      "== #{s["title"] || "section"} ==\n#{s["content"]}"
    end)
  end

  defp diagnosis_text(_), do: ""

  # Canary mechanism (DR-6): one box per click. Shared push logic lives in
  # Orbit.Agent.Update (also drives the list page's "Update all agents").
  defp push_agent_update(inst, user), do: Orbit.Agent.Update.push(inst, user)

  # Lightweight authenticated probe per platform, so the test exercises the
  # relay CREDENTIALS, not just web-server reachability (relay.py parity).
  @relay_probe_paths %{
    "opnsense" => "api/core/system/status",
    "pfsense" => "api/v2/system/version"
  }

  defp agent_lifecycle_action("refresh", inst, user, _agent) do
    result = Hub.send_command(inst.id, "refresh.full", %{}, 60_000)
    result = if is_map(result), do: result, else: %{"success" => false}
    audit_lifecycle(user, inst, "agent.refresh", result)

    if result["success"],
      do: {:ok, :none, "fresh full snapshot pushed"},
      else: {:error, to_string(result["output"] || "refresh failed")}
  end

  defp agent_lifecycle_action("reconnect", inst, user, _agent) do
    result = Hub.send_command(inst.id, "reconnect", %{}, 15_000)
    result = if is_map(result), do: result, else: %{"success" => false}
    audit_lifecycle(user, inst, "agent.reconnect", result)

    if result["success"],
      do: {:ok, :none, "agent reconnecting"},
      else: {:error, to_string(result["output"] || "reconnect failed")}
  end

  defp agent_lifecycle_action("uninstall", inst, user, _agent) do
    result = Hub.send_command(inst.id, "agent.uninstall", %{"deprovision" => true}, 30_000)
    result = if is_map(result), do: result, else: %{"success" => false}
    audit_lifecycle(user, inst, "agent.uninstall", result)

    if result["success"] do
      # Ack received — the box tears the agent down; drop agent mode so the
      # dashboard stops expecting pushes (enroll.py uninstall parity).
      case Orbit.Instances.disable_agent(inst) do
        {:ok, updated} ->
          Hub.unregister(inst.id)
          {:ok, {:instance, updated}, "agent uninstalling — instance back to direct transport"}

        _ ->
          {:error, "agent acked but transport switch failed"}
      end
    else
      {:error, to_string(result["output"] || "uninstall failed")}
    end
  end

  defp agent_lifecycle_action("test_api", inst, _user, agent) do
    platform = String.downcase(to_string((agent && agent.platform) || ""))

    params = %{
      "method" => "GET",
      "path" => Map.get(@relay_probe_paths, platform, ""),
      "headers" => %{},
      "body" => Base.encode64("")
    }

    t0 = System.monotonic_time(:millisecond)
    result = Hub.send_command(inst.id, "http.relay", params, 15_000)
    latency = System.monotonic_time(:millisecond) - t0
    status = if is_map(result), do: result["status"] || 0, else: 0

    cond do
      status == 0 ->
        {:error,
         "local API call failed: #{if is_map(result), do: result["error"] || "no response", else: "no response"}"}

      status in 200..299 ->
        {:ok, :none, "local API OK — HTTP #{status} in #{latency} ms"}

      true ->
        {:error, "local API answered HTTP #{status}"}
    end
  end

  defp audit_lifecycle(user, inst, action, result) do
    Audit.write(
      action: action,
      result: if(result["success"], do: "ok", else: "error"),
      user_id: user.id,
      target_type: "instance",
      target_id: inst.id
    )
  end

  # ---- install guide -------------------------------------------------------

  defp dash_url, do: OrbitWeb.Endpoint.url()

  defp dash_ws_url do
    uri = URI.parse(dash_url())
    proto = if uri.scheme == "https", do: "wss", else: "ws"
    "#{proto}://#{uri.host}#{if uri.port not in [80, 443], do: ":#{uri.port}"}/api/ws/agent"
  end

  @doc false
  # The three install steps as ONE pasteable script. Blank lines between the
  # steps keep it readable; nothing else separates them, because a root shell
  # takes the whole thing in one paste.
  def install_script(%Instance{} = inst, enroll_code) do
    [
      install_download_cmds(inst),
      install_config_cmd(inst, enroll_code),
      install_start_cmd(inst)
    ]
    |> Enum.join("\n\n")
  end

  defp install_download_cmds(%Instance{device_type: "linux"}) do
    base = dash_url()

    """
    mkdir -p /usr/local/orbit-agent /usr/local/etc
    curl -fsSo /usr/local/orbit-agent/orbit_agent.py #{base}/api/agent/script-linux
    curl -fsSo /usr/local/orbit-agent/run-agent.sh #{base}/api/agent/run
    curl -fsSo /usr/local/orbit-agent/check_mk_agent.linux #{base}/api/agent/checkmk
    chmod 755 /usr/local/orbit-agent/run-agent.sh /usr/local/orbit-agent/check_mk_agent.linux
    curl -fsSo /etc/systemd/system/orbit-agent.service #{base}/api/agent/systemd\
    """
  end

  defp install_download_cmds(_inst) do
    base = dash_url()

    """
    mkdir -p /usr/local/orbit-agent
    fetch -o /usr/local/orbit-agent/orbit_agent.py #{base}/api/agent/script
    fetch -o /usr/local/orbit-agent/run-agent.sh #{base}/api/agent/run
    chmod 755 /usr/local/orbit-agent/run-agent.sh
    fetch -o /usr/local/etc/rc.d/orbit_agent #{base}/api/agent/rc
    chmod 755 /usr/local/etc/rc.d/orbit_agent\
    """
  end

  defp install_config_cmd(inst, enroll_code) do
    interval = if inst.device_type == "linux", do: 120, else: 30

    cred =
      case enroll_code do
        {code, _expires} -> %{"enroll_code" => code}
        _ -> %{"agent_token" => inst.agent_token || "PASTE_TOKEN_HERE"}
      end

    cfg =
      Map.merge(
        %{"dashboard_url" => dash_ws_url(), "push_interval" => interval, "log_level" => "INFO"},
        cred
      )

    """
    printf '%s\\n' '#{Jason.encode!(cfg)}' > /usr/local/etc/orbit-agent.conf
    chmod 600 /usr/local/etc/orbit-agent.conf\
    """
  end

  # `restart`, not `enable --now` / `start`: pasting this on a box that already
  # runs an agent (re-enrollment, a move to another dashboard, a repeat of the
  # snippet) must end with the agent running on the NEW config. `--now` leaves
  # a running unit alone with its old config, and on FreeBSD `start` aborts on
  # "daemon: process already running" and the box quietly keeps the old agent.
  defp install_start_cmd(%Instance{device_type: "linux"}) do
    "systemctl daemon-reload\nsystemctl enable orbit-agent\nsystemctl restart orbit-agent\n" <>
      "# verify it came up and is pushing:\njournalctl -u orbit-agent -n 30 --no-pager"
  end

  defp install_start_cmd(_inst) do
    "sysrc orbit_agent_enable=YES\nservice orbit_agent restart"
  end

  # One place for both ways a code is minted: the agent card's button and the
  # automatic mint right after an agent-mode instance is created.
  defp mint_enroll_code(socket) do
    inst = socket.assigns.instance
    {code, expires_at} = Orbit.Enrollment.create_code(inst.id)

    Audit.write(
      action: "agent.enroll_code",
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "instance",
      target_id: inst.id
    )

    assign(socket, enroll_code: {code, expires_at})
  end

  defp audit_agent(socket, action, result) do
    Audit.write(
      action: action,
      result: result,
      user_id: socket.assigns.current_user.id,
      target_type: "instance",
      target_id: socket.assigns.instance.id
    )
  end

  # One tunnel action over the agent relay. Reconnect terminates the live SA
  # first (best-effort — a half-down tunnel must not block the re-initiate).
  defp ipsec_action("reconnect", inst, user, id, uid) do
    if uid != "", do: Hub.send_command(inst.id, "ipsec.disconnect", %{"tunnel_id" => uid}, 30_000)
    ipsec_action("connect", inst, user, id, uid)
  end

  defp ipsec_action("connect", inst, user, id, _uid) do
    result = Hub.send_command(inst.id, "ipsec.connect", %{"tunnel_id" => id}, 30_000)
    result = if is_map(result), do: result, else: %{"success" => false}
    audit_ipsec(user, inst, "ipsec.connect", result)

    if result["success"],
      do: {:ok, "tunnel #{id} initiated"},
      else: {:error, to_string(result["output"] || "connect failed")}
  end

  defp ipsec_action("disconnect", inst, user, id, uid) do
    tunnel_id = if uid != "", do: uid, else: id
    result = Hub.send_command(inst.id, "ipsec.disconnect", %{"tunnel_id" => tunnel_id}, 30_000)
    result = if is_map(result), do: result, else: %{"success" => false}
    audit_ipsec(user, inst, "ipsec.disconnect", result)

    if result["success"],
      do: {:ok, "tunnel #{id} disconnected"},
      else: {:error, to_string(result["output"] || "disconnect failed")}
  end

  defp audit_ipsec(user, inst, action, result) do
    Audit.write(
      action: action,
      result: if(result["success"], do: "ok", else: "error"),
      user_id: user.id,
      target_type: "instance",
      target_id: inst.id
    )
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
  def handle_async(:conn_test, {:ok, result}, socket) do
    {:noreply, assign(socket, conn_test_busy: false, conn_test: result)}
  end

  def handle_async(:conn_test, {:exit, reason}, socket) do
    {:noreply,
     assign(socket, conn_test_busy: false, conn_test: {:error, "test failed: #{inspect(reason)}"})}
  end

  def handle_async(:ping_test, {:ok, result}, socket) do
    {:noreply, assign(socket, ping_test_busy: false, ping_test: result)}
  end

  def handle_async(:ping_test, {:exit, reason}, socket) do
    {:noreply,
     assign(socket, ping_test_busy: false, ping_test: {:error, "test failed: #{inspect(reason)}"})}
  end

  def handle_async(:diag_ai_analyze, {:ok, {:ok, result}}, socket) do
    {:noreply, assign(socket, diag_ai_busy: false, diag_ai_result: result)}
  end

  def handle_async(:diag_ai_analyze, {:ok, {:error, msg}}, socket) do
    {:noreply, assign(socket, diag_ai_busy: false, diag_ai_error: to_string(msg))}
  end

  def handle_async(:diag_ai_analyze, {:exit, _reason}, socket) do
    {:noreply, assign(socket, diag_ai_busy: false, diag_ai_error: "analysis crashed")}
  end

  def handle_async(:ipsec_diagnose, {:ok, {id, result}}, socket) do
    diagnosis =
      if result["success"] do
        %{tunnel_id: id, sections: result["sections"] || []}
      else
        %{tunnel_id: id, sections: [], error: to_string(result["output"] || "diagnose failed")}
      end

    {:noreply, assign(socket, diagnosis_busy: nil, diagnosis: diagnosis)}
  end

  def handle_async(:ipsec_diagnose, {:exit, _}, socket) do
    {:noreply, assign(socket, diagnosis_busy: nil)}
  end

  def handle_async(:ipsec_recheck, {:ok, _result}, socket) do
    # The agent pushed a fresh snapshot as part of status.refresh — re-read
    # the cache instead of waiting for the next 5s tick.
    {:noreply, load_metrics(socket)}
  end

  def handle_async(:ipsec_recheck, {:exit, _}, socket), do: {:noreply, socket}

  def handle_async({:ipsec_action, id}, {:ok, outcome}, socket) do
    msg =
      case outcome do
        {:ok, text} -> {:ok, text}
        {:error, text} -> {:error, String.slice(text, 0, 200)}
      end

    {:noreply,
     socket
     |> assign(
       ipsec_busy: MapSet.delete(socket.assigns.ipsec_busy, id),
       ipsec_msg: msg
     )
     |> load_metrics()}
  end

  def handle_async({:ipsec_action, id}, {:exit, _}, socket) do
    {:noreply,
     assign(socket,
       ipsec_busy: MapSet.delete(socket.assigns.ipsec_busy, id),
       ipsec_msg: {:error, "action crashed"}
     )}
  end

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

  def handle_async({:agent_action, _kind}, {:ok, outcome}, socket) do
    socket =
      case outcome do
        {:ok, {:instance, inst}, text} ->
          socket |> assign(instance: inst, agent_msg: {:ok, text}) |> load_metrics()

        {:ok, :none, text} ->
          assign(socket, agent_msg: {:ok, text})

        {:error, text} ->
          assign(socket, agent_msg: {:error, String.slice(text, 0, 200)})
      end

    {:noreply, socket}
  end

  def handle_async({:agent_action, _kind}, {:exit, _}, socket) do
    {:noreply, assign(socket, agent_msg: {:error, "action crashed"})}
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

  # The six charted series (METRICS const + the two extra charts in
  # InstanceDetailPage.tsx). agent.collect_ms plots in seconds with the 10s
  # WARN line; uptime plots in days — the sawtooth marks reboots.
  defp chart_series do
    [
      %{
        metric: "cpu.total",
        label: "CPU %",
        color: "#10b981",
        domain_max: 100,
        scale: 1,
        ref_y: nil,
        unit: ""
      },
      %{
        metric: "memory.used_pct",
        label: "RAM %",
        color: "#6366f1",
        domain_max: 100,
        scale: 1,
        ref_y: nil,
        unit: ""
      },
      %{
        metric: "load.1m",
        label: "Load (1m)",
        color: "#f59e0b",
        domain_max: :auto,
        scale: 1,
        ref_y: nil,
        unit: ""
      },
      %{
        metric: "pf.states_pct",
        label: "pf states %",
        color: "#0ea5e9",
        domain_max: 100,
        scale: 1,
        ref_y: nil,
        unit: ""
      },
      %{
        metric: "agent.collect_ms",
        label: "Agent collect (s)",
        color: "#f472b6",
        domain_max: :auto,
        scale: 1000,
        ref_y: 10,
        unit: "s"
      },
      %{
        metric: "system.uptime_seconds",
        label: "Uptime (days)",
        color: "#38bdf8",
        domain_max: :auto,
        scale: 86_400,
        ref_y: nil,
        unit: "d"
      }
    ]
  end

  defp load_charts(socket) do
    id = socket.assigns.instance.id
    range = socket.assigns.chart_range

    points =
      Map.new(chart_series(), fn s -> {s.metric, Orbit.Metrics.read(id, s.metric, range)} end)

    assign(socket, chart_points: points)
  rescue
    # A missing/unreachable metrics table (throwaway test DB) renders the
    # empty state instead of crashing the whole detail view.
    _ -> assign(socket, chart_points: %{})
  catch
    # "unreachable" includes a pool checkout, which exits rather than raising
    # — and this runs on a repeating timer, so one blip crashed the detail
    # view for every operator with it open, not just on load.
    _kind, _reason -> assign(socket, chart_points: %{})
  end

  defp load_monitors(socket) do
    assign(socket,
      conn_monitors: Orbit.Monitors.list_connectivity(socket.assigns.instance.id),
      ipsec_monitors: Orbit.Monitors.list_ipsec(socket.assigns.instance.id),
      conn_error: nil
    )
  end

  @doc """
  Normalise the raw `ipsec` hub section to `{tunnels, running}`.

  The section has TWO shapes depending on where it came from, and the page must
  survive both:

  - agent / OPNsense push: a map `%{"running" => bool, "tunnels" => [...]}`
  - Securepoint direct-poll: a BARE LIST of connections — `fetch_status/1`
    stores whatever `ipsec status` returned, and every Securepoint section is a
    list (see Orbit.Securepoint.Client and its fetch_status test).

  Regression: the map form was hardcoded as `(entry["ipsec"] || %{})["tunnels"]`.
  Applying Access to a Securepoint list raised
  `ArgumentError: the Access module supports only keyword lists`, so the whole
  detail page answered 500 for every Securepoint box (instance "bensheim").
  Do not collapse this back into a single Access call.
  """
  def normalize_ipsec(%{"tunnels" => tunnels} = ipsec) when is_list(tunnels),
    do: {tunnels, ipsec["running"]}

  def normalize_ipsec(%{} = ipsec), do: {[], ipsec["running"]}

  # Securepoint: bare list of connections, no service-level running flag.
  def normalize_ipsec(tunnels) when is_list(tunnels), do: {tunnels, nil}

  def normalize_ipsec(_), do: {[], nil}

  # The Firmware TAB shows for every device that reports versions — the data is a
  # plain status read and a direct-polled box has it too (it was hidden behind an
  # agent_mode? gate although Orbit.Firmware already had a working direct
  # branch). The ACTIONS are narrower: that direct branch talks to the OPNsense
  # firmware API, and Securepoint firmware is read-only from here — python
  # answered its check/update with a not-supported result. Offering the buttons
  # there would only produce an error on click.
  defp firmware_actionable?(%Instance{device_type: "securepoint"}), do: false
  defp firmware_actionable?(%Instance{}), do: true

  defp load_metrics(socket) do
    entry = Hub.cache_entry(socket.assigns.instance.id)
    status = entry["status"] || %{}
    {ipsec_tunnels, ipsec_running} = normalize_ipsec(entry["ipsec"])

    assign(socket,
      connected: Hub.get(socket.assigns.instance.id) != nil,
      cpu: get_in(status, ["cpu", "total_pct"]),
      memory: status["memory"],
      disks: status["disks"] || [],
      system: status["system"] || %{},
      uptime: status["uptime"],
      loadavg: status["loadavg"] || %{},
      pf: status["pf"] || %{},
      ntp: status["ntp"] || %{},
      section_ms: status["section_ms"] || %{},
      config_rev: status["config"] || %{},
      ipsec: ipsec_tunnels,
      ipsec_running: ipsec_running,
      connectivity: entry["connectivity"] || [],
      last_seen: entry["last_metrics_ts"],
      firmware: entry["firmware"],
      fw_verdict: Evaluate.firmware_check(entry["firmware"]),
      agent: Hub.get(socket.assigns.instance.id),
      served_agent_version:
        Orbit.Agent.Package.served_version(
          Orbit.Agent.Package.line_for(socket.assigns.instance.device_type)
        ),
      gateways: entry["gateways"] || [],
      interfaces: status["interfaces"] || [],
      services: entry["services"] || [],
      # Public-IP view, one shape for every transport (Orbit.ExternalIp):
      # the agent's ipify probe when there is one, otherwise a routable
      # address off the box's own interfaces — so poll-mode and Securepoint
      # boxes answer the question too.
      public_ip: public_ip_view(socket.assigns.instance, entry),
      # Geo of the box's WAN address (City edition; display-only, nil when
      # unknown/private or the mmdb is unloaded).
      external_geo: OrbitWeb.Geo.label(get_in(entry, ["external_ip", "ipv4"])),
      certificates: entry["certificates"] || [],
      pf_top: entry["pf_top"] || %{},
      firewall_log: Enum.take(entry["firewall_log"] || [], 15),
      check_history: check_history(socket.assigns.instance.id),
      checks: instance_checks(socket.assigns.instance),
      check_rules: instance_rules(socket.assigns.instance.id)
    )
  end

  # Public IP + NAT verdict. The agent connection (when there is one) also
  # supplies the address the hub saw the box connect from; a poll-mode box
  # never connects to us, so that stays nil by nature rather than by gap.
  defp public_ip_view(instance, entry) do
    agent = Hub.get(instance.id)

    # Map.get, not agent.source_ip: on a rolling deploy the hub GenServer
    # keeps running with Agent structs minted before this field existed, and
    # every already-connected box would 500 this page until it reconnected.
    Orbit.ExternalIp.build(entry,
      source_ip: agent && Map.get(agent, :source_ip),
      connected: not is_nil(agent)
    )
  end

  # {consumer, selector} pairs that have a rule pinned to THIS instance —
  # the ChecksSection toggles show override vs global-inherited state.
  defp instance_rules(instance_id) do
    Orbit.Selection.list_rules()
    |> Enum.filter(&(&1.instance_id == instance_id))
    |> MapSet.new(&{&1.consumer, &1.selector})
  rescue
    _ -> MapSet.new()
  catch
    # A pool checkout exits rather than raising; same fallback, or a stressed
    # database takes the whole page down instead of one panel.
    _kind, _reason -> MapSet.new()
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
  catch
    # A pool checkout exits rather than raising; same fallback, or a stressed
    # database takes the whole page down instead of one panel.
    _kind, _reason -> []
  end

  # Per-instance evaluated checks — same evaluate→overlay chain as the exports
  # and Alerts (four-surface parity). Direct-poll instances have no cached
  # sections yet (poller not ported), so only agent-mode instances get checks.
  # NOT gated on agent_mode?: Export.checks_for/2 reads the hub cache, which a
  # direct poll fills exactly like an agent push. The gate used to blank the
  # Checks tab for every polled box although the evaluation was working — on a
  # Securepoint instance it hid memory/cpu/load/disk/firmware and one row per
  # IPsec tunnel, all of which the python UI showed.
  defp instance_checks(inst) do
    inst
    |> Export.checks_for(DateTime.utc_now())
    |> Enum.sort_by(&{-ServiceCheck.severity(&1.state), &1.key})
  end

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :tone, :string, default: "text-primary"
  slot :note

  defp ip_card(assigns) do
    ~H"""
    <div class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4">
      <div class="flex items-center gap-2 text-xs text-base-content/60">
        <Icons.icon name={:globe} class={["h-3.5 w-3.5", @tone]} /> {@label}
      </div>
      <div class="mt-1 flex items-start gap-2">
        <span class={[
          "min-w-0 break-all font-mono text-sm",
          if(@value, do: "text-base-content", else: "text-base-content/40")
        ]}>
          {@value || "—"}
        </span>
        <%!-- Copy affordance from the react original; the hook falls back to
             a hidden textarea where the clipboard API is unavailable. --%>
        <button
          :if={@value}
          type="button"
          id={"copy-#{@label |> String.downcase() |> String.replace(~r/[^a-z0-9]+/, "-")}"}
          phx-hook="CopyValue"
          data-copy={@value}
          title="Copy to clipboard"
          aria-label={"Copy #{@label}"}
          class="shrink-0 rounded p-1 text-base-content/50 hover:bg-base-300 hover:text-base-content"
        >
          <Icons.icon name={:copy} class="h-3.5 w-3.5" />
        </button>
      </div>
      <p :if={@note != []} class="mt-1 text-[11px] text-base-content/50">{render_slot(@note)}</p>
    </div>
    """
  end

  attr :nat, :atom, required: true

  defp nat_badge(assigns) do
    ~H"""
    <span
      :if={@nat != :unknown}
      title={
        if @nat == :behind_nat,
          do:
            "The box's public IPv4 is not configured on any of its interfaces — an upstream NAT owns the public address.",
          else: "The box owns its public IPv4 directly on an interface (no upstream NAT)."
      }
      class={[
        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs",
        if(@nat == :behind_nat,
          do: "bg-warning/20 text-warning",
          else: "bg-primary/20 text-primary"
        )
      ]}
    >
      {if @nat == :behind_nat, do: "Behind NAT", else: "Direct"}
    </span>
    """
  end

  # One honest line about where the addresses came from — a probe from the
  # box itself and an address read off its interfaces are different claims.
  defp source_note(%{source: :probe, checked_at: at}) when is_binary(at) do
    "Probed by the agent from the box itself · #{rev_time(at)}"
  end

  defp source_note(%{source: :probe}), do: "Probed by the agent from the box itself."

  defp source_note(%{source: :interface}),
    do: "Read off the box's own interfaces — no outbound probe runs on this transport."

  defp source_note(_), do: "No public address reported yet."

  # Why this card is empty, per transport. A poll-mode box has no inbound
  # connection at all, so "unknown" there is the correct final answer, not a
  # gap — say which of the two it is instead of leaving a bare dash.
  defp connects_from_note(instance, public_ip) do
    cond do
      not Instance.agent_mode?(instance) ->
        "polled by the dashboard — this box never connects to us"

      not public_ip.connected ->
        "agent not connected"

      is_nil(public_ip.source_ip) ->
        "recorded on the agent's next reconnect"

      true ->
        "address the hub saw on the agent's connect"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <%!-- Wraps: the five action buttons pushed the page ~190px wide on a
             phone-width viewport (every page then scrolled sideways). --%>
        <div class="mb-6 flex flex-wrap items-center gap-x-3 gap-y-2">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/60" /> {@instance.name}
            <.base_url_link base_url={@instance.base_url} />
          </h1>
          <span
            class={["rounded px-2 py-0.5 text-xs", conn_badge(@connected)]}
            title={agent_badge_hint(@instance, @connected)}
          >
            {agent_badge(@instance, @connected)}
          </span>
          <a
            :if={@instance.shell_enabled}
            href={~p"/instances/#{@instance.id}/terminal"}
            target="_blank"
            rel="noopener"
            class="inline-flex items-center gap-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            <Icons.icon name={:terminal} class="h-3 w-3" /> Terminal
          </a>
          <button
            :if={@writable and @gui_openable}
            phx-click="gui_open"
            class="inline-flex items-center gap-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            <Icons.icon name={:external} class="h-3 w-3" /> Open GUI
          </button>
          <a
            :if={@writable}
            href={~p"/instances/#{@instance.id}/capture"}
            class="inline-flex items-center gap-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            <Icons.icon name={:capture} class="h-3 w-3" /> Capture
          </a>
          <a
            :if={@writable and @instance.device_type == "opnsense"}
            href={~p"/instances/#{@instance.id}/firewall"}
            class="inline-flex items-center gap-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            <Icons.icon name={:firewall} class="h-3 w-3" /> Firewall
          </a>
          <a
            :if={@writable}
            href={~p"/instances/#{@instance.id}/edit"}
            class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            Edit
          </a>
        </div>

        <.instance_tabs instance={@instance} active={@tab} patch?={true} />

        <div :if={@tab == "overview"} class="grid gap-6 md:grid-cols-2">
          <div class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Instance</h2>
            <dl class="space-y-1 text-sm">
              <.kv label="Type" value={@instance.device_type} />
              <.kv label="Transport" value={@instance.transport} />
              <div class="flex justify-between gap-3">
                <dt class="shrink-0 text-base-content/60">Base URL</dt>
                <dd class="min-w-0 break-words text-right text-base-content">
                  <.base_url_links base_url={@instance.base_url} />
                </dd>
              </div>
              <.kv label="Location" value={@instance.location || "—"} />
            </dl>
          </div>

          <div class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Live</h2>
            <div :if={not @connected and @system == %{}} class="text-sm text-base-content/60">
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

        <%!-- Console-password policy note (InstanceDetailPage parity): the
             fleet standard is NO password on the console menu. --%>
        <div
          :if={@tab == "overview" and @system["console_password_protected"] == true}
          class="mt-4 rounded-md border border-warning/50 bg-warning/10 px-3 py-2 text-sm text-warning"
        >
          <span class="font-medium">Console password protection enabled.</span>
          We prefer no password on the console. Disable “Password protect the console
          menu” under System → Settings → Administration → Console / Serial Communications.
        </div>

        <%!-- System health strip (SystemHealthSection parity): load per core,
             swap, pf state table, NTP — plus the last config revision
             (ConfigSection parity). Sections the box never reported stay
             hidden (no-data ⇒ no tile, never a fake 0). --%>
        <div :if={@tab == "overview"} class="mt-6 grid gap-6 md:grid-cols-2">
          <div class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">System health</h2>
            <dl class="space-y-1 text-sm">
              <.kv
                :if={@loadavg["one"] != nil}
                label="Load 1 · 5 · 15"
                value={"#{@loadavg["one"]} · #{@loadavg["five"]} · #{@loadavg["fifteen"]}#{if num0(@loadavg["cores"]) > 0, do: "  (#{num0(@loadavg["cores"])} cores)"}"}
              />
              <.kv
                :if={num0(@memory && @memory["swap_total_mb"]) > 0}
                label="Swap"
                value={"#{@memory["swap_used_pct"]}% of #{num0(@memory["swap_total_mb"])} MB"}
              />
              <.kv
                :if={num0(@pf["states_limit"]) > 0}
                label="pf states"
                value={"#{num0(@pf["states_current"])} / #{num0(@pf["states_limit"])} (#{@pf["states_pct"]}%)"}
              />
              <.kv
                :if={@ntp != %{}}
                label="NTP"
                value={ntp_text(@ntp)}
              />
              <.kv
                :if={@loadavg == %{} and @pf == %{} and @ntp == %{}}
                label="Status"
                value="no health data yet"
              />
            </dl>
          </div>

          <%!-- Inside the overview-only grid — a stray tab=="config" gate here
               meant this card rendered on NO tab at all and left a hole next
               to System health. --%>
          <div class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4">
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Config revision</h2>
            <dl :if={@config_rev != %{}} class="space-y-1 text-sm">
              <.kv label="Last change" value={rev_time(@config_rev["revision_time"])} />
              <.kv label="Description" value={@config_rev["revision_description"] || "—"} />
              <.kv label="By" value={@config_rev["revision_user"] || "—"} />
            </dl>
            <div :if={@config_rev == %{}} class="text-sm text-base-content/60">
              No config revision reported.
            </div>
          </div>
        </div>

        <div
          :if={@tab == "checks" and @checks != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">
            Checks <span class="text-base-content/60">({length(@checks)})</span>
          </h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <tbody>
                <tr :for={c <- @checks} class="border-b border-base-300/50 last:border-0">
                  <td class="w-16 py-1.5 pr-4 align-top">
                    <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(c.state)]}>
                      {state_label(c.state)}
                    </span>
                  </td>
                  <td class="whitespace-nowrap py-1.5 pr-4 align-top text-base-content/70">
                    {c.key}
                  </td>
                  <td class="py-1.5 align-top text-base-content/80">{c.summary}</td>
                  <td :if={@writable} class="whitespace-nowrap py-1.5 pl-2 text-right align-top">
                    <button
                      :for={consumer <- Orbit.Selection.consumers()}
                      :if={Orbit.Selection.valid_selector?(consumer, c.key)}
                      phx-click="check_toggle"
                      phx-value-consumer={consumer}
                      phx-value-key={c.key}
                      aria-pressed={
                        to_string(Orbit.Selection.is_on_live(consumer, c.key, @instance.id))
                      }
                      title={"Export to #{consumer}: #{if Orbit.Selection.is_on_live(consumer, c.key, @instance.id), do: "ON", else: "OFF"} — #{if MapSet.member?(@check_rules, {consumer, c.key}), do: "instance override, click to clear back to the global rule", else: "global rule, click to override for this box"}"}
                      class={[
                        "ml-1 rounded px-2 py-0.5 text-[11px]",
                        if(Orbit.Selection.is_on_live(consumer, c.key, @instance.id),
                          do: "bg-primary/20 text-primary",
                          else: "bg-base-300 text-base-content/60"
                        ),
                        MapSet.member?(@check_rules, {consumer, c.key}) && "ring-1 ring-primary"
                      ]}
                    >
                      {consumer_tag(consumer)}
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <%!-- Metric history (InstanceDetailPage Metrics parity): six fixed
             series over the shared metrics table, range-switchable. Series
             the box never reported (pf on a linux node, collect on a
             direct-poll box) render the empty state, same as recharts did. --%>
        <section :if={@tab == "overview"} class="mt-8">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold text-base-content/70">Metrics</h2>
            <div class="flex gap-1">
              <button
                :for={r <- ~w(1h 6h 24h 7d 30d)}
                phx-click="chart_range"
                phx-value-range={r}
                class={[
                  "rounded-md px-2 py-1 text-xs",
                  if(@chart_range == r,
                    do: "bg-primary text-primary-content",
                    else: "text-base-content/70 hover:bg-base-300"
                  )
                ]}
              >
                {r}
              </button>
            </div>
          </div>
          <div class="mt-4 grid gap-6 lg:grid-cols-2">
            <.metric_chart
              :for={s <- chart_series()}
              label={s.label}
              points={@chart_points[s.metric] || []}
              color={s.color}
              domain_max={s.domain_max}
              scale={s.scale}
              ref_y={s.ref_y}
              unit={s.unit}
            />
          </div>
        </section>

        <div
          :if={@tab == "agent" and Instance.agent_mode?(@instance)}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Agent</h2>
          <dl class="space-y-1 text-sm">
            <.kv
              label="Status"
              value={if @agent, do: "connected (#{@agent.pushes} pushes)", else: "not connected"}
            />
            <.kv :if={@agent} label="Version" value={@agent.agent_version || "?"} />
            <.kv :if={@agent} label="Platform" value={@agent.platform || "?"} />
            <.kv label="Served version" value={@served_agent_version || "—"} />
          </dl>

          <%!-- Per-collector runtime of the LAST push (AgentRuntimeSection
               parity): live snapshot only — the whole-cycle total has its
               own history chart above. --%>
          <div :if={@section_ms != %{}} class="mt-3">
            <h3 class="mb-1 text-xs text-base-content/60">Collector runtime (last push)</h3>
            <div
              :for={{name, ms} <- top_sections(@section_ms)}
              class="flex items-center gap-2 text-xs"
            >
              <span class="w-28 truncate text-base-content/60">{name}</span>
              <div class="h-1.5 flex-1 overflow-hidden rounded bg-base-300">
                <div
                  class={["h-full", if(ms >= 10_000, do: "bg-warning", else: "bg-primary")]}
                  style={"width: #{section_pct(ms, @section_ms)}%"}
                >
                </div>
              </div>
              <span class="w-16 text-right text-base-content/70">{Float.round(ms / 1000, 2)}s</span>
            </div>
          </div>

          <dl class="space-y-1 text-sm">
            <.kv
              :if={@agent && @agent.last_update_error}
              label="Last update error"
              value={"#{@agent.last_update_version}: #{@agent.last_update_error}"}
            />
          </dl>

          <div :if={@writable} class="mt-3 flex flex-wrap items-center gap-2">
            <button
              phx-click="mint_enroll"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              Mint enroll code
            </button>
            <button
              :if={@agent && @served_agent_version && @agent.agent_version != @served_agent_version}
              phx-click="agent_update"
              data-confirm={"Push agent #{@served_agent_version} to #{@instance.name}? The agent restarts (canary: one box at a time)."}
              disabled={@agent_busy}
              class="rounded bg-primary px-3 py-1 text-xs text-primary-content hover:bg-primary/80 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @agent_busy,
                do: "Pushing…",
                else: "Push agent update → #{@served_agent_version}"}
            </button>
            <button
              phx-click="agent_refresh"
              title="Force a full re-collect now (logfiles/firmware/backup are normally throttled)"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              Refresh now
            </button>
            <button
              :if={@agent}
              phx-click="agent_reconnect"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              Reconnect
            </button>
            <%!-- Relay test only where a local firewall API exists: a
                 generic Linux node has none, so the button could only ever
                 fail there. `@agent` is the hub record (a struct), so it
                 needs an explicit nil check — `struct and x` raises
                 BadBooleanError while rendering. --%>
            <button
              :if={@agent != nil and @instance.device_type != "linux"}
              phx-click="agent_test_api"
              title="Authenticated API call through the agent relay"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              Test local API
            </button>
            <button
              phx-click="agent_show_token"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              {if @show_token, do: "Hide token", else: "Show token"}
            </button>
            <button
              :if={@agent}
              phx-click="agent_uninstall"
              data-confirm={"Uninstall the agent from #{@instance.name}? The box falls back to direct transport."}
              class="rounded border border-error/40 px-3 py-1 text-xs text-error hover:bg-error/15"
            >
              Uninstall agent
            </button>
            <button
              phx-click="agent_disable"
              data-confirm={"Disable agent mode on #{@instance.name}? The token is revoked; a running agent can no longer connect."}
              class="rounded border border-error/40 px-3 py-1 text-xs text-error hover:bg-error/15"
            >
              Disable agent mode
            </button>
          </div>

          <div :if={@show_token and @instance.agent_token} class="mt-2 text-xs">
            <span class="text-base-content/60">Agent token: </span>
            <code class="break-all font-mono text-primary">{@instance.agent_token}</code>
          </div>

          <%!-- Guided install (AgentSection walkthrough parity, condensed to
               the copy-paste essentials; the enroll code above slots into
               the config). tcsh-safe printf, no heredocs. --%>
          <div :if={@writable} class="mt-3 text-xs">
            <button
              type="button"
              phx-click="toggle_install"
              class="cursor-pointer text-base-content/70 hover:text-base-content"
            >
              {if @install_open, do: "▾", else: "▸"} Install instructions
            </button>
            <div :if={@install_open} class="mt-2 space-y-2">
              <div class="flex items-start justify-between gap-2">
                <p class="text-base-content/60">
                  Run as root on the box. 1) download, 2) write config {if @enroll_code,
                    do: "(one-time enroll code baked in)",
                    else: "(mint an enroll code above, or paste the token)"}, 3) start.
                </p>
                <button
                  type="button"
                  id="copy-install-script"
                  phx-hook="CopyValue"
                  data-copy={install_script(@instance, @enroll_code)}
                  title="Copy to clipboard"
                  aria-label="Copy install instructions"
                  class="flex shrink-0 items-center gap-1 rounded border border-base-content/20 px-2 py-1 text-base-content/60 hover:bg-base-300 hover:text-base-content"
                >
                  <Icons.icon name={:copy} class="h-3.5 w-3.5" /> Copy
                </button>
              </div>
              <%!-- ONE block, not three: the three steps used to sit in
                   separate <pre>s, so pasting them meant three selections and
                   three round trips to a root shell. They are one script. --%>
              <pre class="overflow-x-auto rounded bg-base-100 p-2 font-mono text-base-content/80">{install_script(@instance, @enroll_code)}</pre>
            </div>
          </div>

          <div :if={@enroll_code} class="mt-2 text-sm">
            <span class="text-base-content/60">Enroll code: </span>
            <span class="font-mono text-primary">{elem(@enroll_code, 0)}</span>
            <span class="text-xs text-base-content/60">
              (valid until {cb_ts(elem(@enroll_code, 1))} — run install.sh on the box and paste it)
            </span>
          </div>

          <div
            :if={@agent_msg}
            class={[
              "mt-2 text-xs",
              elem(@agent_msg, 0) == :ok && "text-primary",
              elem(@agent_msg, 0) == :error && "text-error"
            ]}
          >
            {elem(@agent_msg, 1)}
          </div>
        </div>

        <%!-- Direct-poll boxes: offer the switch INTO agent mode (management
             enable_agent parity). Securepoint is pull-only by design. --%>
        <div
          :if={
            @tab == "agent" and not Instance.agent_mode?(@instance) and @writable and
              @instance.device_type != "securepoint"
          }
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Agent</h2>
          <p class="mb-2 text-sm text-base-content/60">
            This box is polled directly. Switch to the push agent for live metrics,
            shell, capture and the GUI tunnel.
          </p>
          <button
            phx-click="agent_enable"
            class="rounded bg-primary px-3 py-1 text-xs text-primary-content hover:bg-primary/80"
          >
            Enable agent mode
          </button>
          <div
            :if={@agent_msg}
            class={[
              "mt-2 text-xs",
              elem(@agent_msg, 0) == :ok && "text-primary",
              elem(@agent_msg, 0) == :error && "text-error"
            ]}
          >
            {elem(@agent_msg, 1)}
          </div>
        </div>

        <div
          :if={@tab == "firmware"}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 flex items-center gap-2 text-sm font-medium text-base-content/70">
            Firmware
            <.comment_editor
              text={CommentEditor.text(@comments, @instance.id, "firmware", "")}
              writable={@writable}
              instance_id={@instance.id}
              kind="firmware"
              entity_key=""
            />
            <span
              :if={@instance.firmware_locked}
              class="rounded bg-base-300 px-1.5 py-0.5 text-xs text-warning"
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

          <div :if={is_nil(@firmware)} class="text-sm text-base-content/60">
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
            <.kv
              :if={(@firmware["known_branches"] || []) != []}
              label="Known branches"
              value={Enum.join(@firmware["known_branches"] || [], ", ")}
            />
            <.kv :if={@fw_verdict} label="Status" value={@fw_verdict.summary} />
            <.kv
              :if={num0(@firmware["updates_available"]) > 0}
              label="Pending updates"
              value={"#{num0(@firmware["updates_available"])}#{if num0(@firmware["security_updates"]) > 0, do: " (#{num0(@firmware["security_updates"])} security)", else: " (none security-relevant)"}"}
            />
            <.kv
              :if={truthy_str(@firmware["last_check"])}
              label="Last check"
              value={@firmware["last_check"]}
            />
          </dl>

          <div
            :if={@firmware && @firmware["needs_reboot"] == true}
            class="mt-2 rounded border border-warning/40 bg-warning/10 px-3 py-1.5 text-xs text-warning"
          >
            Reboot required to finish applying updates.
          </div>
          <div
            :if={@firmware && @firmware["check_failed"] == true}
            class="mt-2 rounded border border-warning/40 bg-warning/10 px-3 py-1.5 text-xs text-warning"
          >
            The box could not check for updates (repo unreachable or pkg broken) — status unknown.
          </div>

          <%!-- Pending package list (linux nodes; FreeBSD reports only the
               product verdict). Capped at 50 by the agent. --%>
          <details :if={@firmware && (@firmware["packages"] || []) != []} class="mt-2 text-xs">
            <summary class="cursor-pointer text-base-content/70 hover:text-base-content">
              {length(@firmware["packages"] || [])} pending package(s)
            </summary>
            <table class="mt-1 w-full text-left font-mono text-xs">
              <tbody>
                <tr :for={p <- @firmware["packages"] || []} class="border-t border-base-300/50">
                  <td class="py-0.5 pr-3 text-base-content/80">{p["name"]}</td>
                  <td class="py-0.5 pr-3 text-base-content/60">{p["current"]}</td>
                  <td class="py-0.5 text-base-content/70">→ {p["new"]}</td>
                </tr>
              </tbody>
            </table>
          </details>

          <details
            :if={@firmware && truthy_str(@firmware["update_check_output"])}
            class="mt-2 text-xs"
          >
            <summary class="cursor-pointer text-base-content/70 hover:text-base-content">
              Last check output
            </summary>
            <pre class="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap rounded bg-base-100 p-2 font-mono text-base-content/70">{@firmware["update_check_output"]}</pre>
          </details>

          <p :if={not firmware_actionable?(@instance)} class="mt-3 text-xs text-base-content/50">
            Firmware on this device is read-only from the dashboard — the vendor API
            reports the versions but exposes no check or update action.
          </p>

          <div
            :if={@writable and firmware_actionable?(@instance)}
            class="mt-3 flex flex-wrap items-center gap-2"
          >
            <button
              phx-click="fw_check"
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "check", do: "Checking…", else: "Check for updates"}
            </button>
            <button
              :if={not @instance.firmware_locked}
              phx-click="fw_update"
              data-confirm={"Start the firmware update on #{@instance.name}? The box may reboot."}
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded bg-primary px-3 py-1 text-xs text-primary-content hover:bg-primary/80 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "update", do: "Starting…", else: "Start update"}
            </button>
            <button
              :if={
                not @instance.firmware_locked and
                  truthy_str(@firmware && @firmware["upgrade_major_version"])
              }
              phx-click="fw_upgrade"
              disabled={not @connected or @fw_busy != nil or @upgrading}
              class="rounded bg-warning px-3 py-1 text-xs text-warning-content hover:bg-warning/80 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @fw_busy == "upgrade",
                do: "Starting…",
                else: "Series upgrade → #{@firmware["upgrade_major_version"]}"}
            </button>
          </div>

          <%!-- Type-the-name confirmation. The comparison happens on the
               server (fw_upgrade_confirm); this is the prompt, not the gate. --%>
          <div
            :if={@upgrade_confirm_open}
            class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
          >
            <form
              phx-submit="fw_upgrade_confirm"
              phx-change="fw_upgrade_typing"
              class="w-full max-w-md rounded-lg border border-warning/50 bg-base-200 p-5"
            >
              <h3 class="text-sm font-medium text-warning">
                Series upgrade to {@firmware["upgrade_major_version"]}
              </h3>
              <p class="mt-2 text-sm text-base-content/70">
                This is a major version jump on <span class="font-medium text-base-content">{@instance.name}</span>. The box
                reboots, and it cannot be undone from here. Type the instance name to confirm.
              </p>
              <input
                name="name"
                value={@upgrade_confirm}
                autocomplete="off"
                spellcheck="false"
                placeholder={@instance.name}
                class="mt-3 w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-warning focus:outline-none"
              />
              <div class="mt-4 flex justify-end gap-2">
                <button
                  type="button"
                  phx-click="fw_upgrade_cancel"
                  class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/70 hover:bg-base-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={String.trim(@upgrade_confirm) != @instance.name}
                  class="rounded bg-warning px-3 py-1 text-xs text-warning-content hover:bg-warning/80 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Start series upgrade
                </button>
              </div>
            </form>
          </div>

          <div
            :if={@fw_msg}
            class={[
              "mt-2 text-xs",
              elem(@fw_msg, 0) == :ok && "text-primary",
              elem(@fw_msg, 0) == :error && "text-error"
            ]}
          >
            {elem(@fw_msg, 1)}
          </div>

          <%!-- The log used to be gated on @upgrading alone, so it vanished
               the moment tracking stopped — exactly when the operator wants
               to read the boot-environment name and the final lines. It now
               stays until dismissed. --%>
          <div :if={@upgrading or @upgrade_log != []} class="mt-3">
            <div class="mb-1 flex items-center justify-between">
              <span class={[
                "text-xs",
                if(@upgrading, do: "text-warning", else: "text-base-content/60")
              ]}>
                {if @upgrading, do: "Update running…", else: "Update finished — log kept for review"}
              </span>
              <button
                :if={not @upgrading and @upgrade_log != []}
                phx-click="fw_log_dismiss"
                class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
              >
                Dismiss
              </button>
            </div>
            <pre
              :if={@upgrade_log != []}
              class="max-h-48 overflow-y-auto rounded bg-base-100 p-2 text-xs text-base-content/70"
            >{Enum.join(Enum.take(@upgrade_log, -20), "\n")}</pre>
          </div>
        </div>

        <%!-- Standalone connectivity monitors (ConnectivitySection parity):
             live ping results from the agent's last push, plus CRUD. The
             agent echoes each monitor's id, so results join by id. --%>
        <div
          :if={@tab == "connectivity" and Instance.monitors_runnable?(@instance)}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Connectivity monitors</h2>

          <div :if={@conn_error} class="mb-2 rounded bg-error/15 px-2 py-1 text-xs text-error">
            {@conn_error}
          </div>

          <div class="overflow-x-auto">
            <table :if={@conn_monitors != []} class="w-full min-w-[46rem] text-left text-sm">
              <thead class="text-xs text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-1 pr-3 font-medium">Monitor</th>
                  <th class="py-1 pr-3 font-medium">Source → Destination</th>
                  <th class="py-1 pr-3 font-medium">State</th>
                  <th class="py-1 pr-3 font-medium">RTT / Loss</th>
                  <th class="py-1 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                <%= for m <- @conn_monitors do %>
                  <% result = Enum.find(@connectivity, &(&1["id"] == m.id)) %>
                  <tr class="border-b border-base-300/50 last:border-0">
                    <td class="py-1.5 pr-3 text-base-content/80">
                      {m.name}
                      <span :if={not m.enabled} class="ml-1 text-xs text-base-content/40">(disabled)</span>
                      <.comment_editor
                        text={
                          CommentEditor.text(@comments, @instance.id, "connectivity", to_string(m.id))
                        }
                        writable={@writable}
                        instance_id={@instance.id}
                        kind="connectivity"
                        entity_key={to_string(m.id)}
                      />
                    </td>
                    <td class="py-1.5 pr-3 text-base-content/70">
                      {if m.source == "", do: "default", else: m.source} → {m.destination}
                    </td>
                    <td class={["py-1.5 pr-3", ping_state_color(result && result["ping_state"])]}>
                      {(result && result["ping_state"]) || "no data yet"}
                    </td>
                    <td class="py-1.5 pr-3 text-base-content/70">
                      <span :if={result && is_number(result["ping_rtt_ms"])}>
                        {result["ping_rtt_ms"]} ms
                      </span>
                      <span :if={result && is_number(result["ping_loss_pct"])}>
                        · {result["ping_loss_pct"]}%
                      </span>
                    </td>
                    <td class="py-1.5 text-right text-xs whitespace-nowrap">
                      <%!-- History is a read: available without the write role. --%>
                      <button
                        phx-click="monitor_history_open"
                        phx-value-id={m.id}
                        title="Recorded state transitions of this monitor"
                        class="rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                      >
                        History
                      </button>
                      <button
                        :if={@writable}
                        phx-click="conn_open"
                        phx-value-id={m.id}
                        class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>

          <p :if={@conn_monitors == []} class="text-sm text-base-content/60">
            No monitors configured — the box pings each (source, destination) pair
            on every cycle{if not Instance.agent_mode?(@instance),
              do: " (run over SSH; this box has no agent)"}.
          </p>

          <div :if={@writable} class="mt-3 flex items-center gap-2">
            <button
              phx-click="conn_open"
              class="rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/80 hover:bg-base-300"
            >
              Add monitor
            </button>
          </div>

          <.connectivity_monitor_dialog
            editor={@conn_editor}
            busy={@conn_test_busy}
            result={@conn_test}
          />
          <.check_history_dialog history={@monitor_history} />
        </div>

        <%!-- IPsec (IPsecSection parity): live SA table with phase-2 expand and
             tunnel actions over the agent relay. Reconnect = terminate + re-
             initiate; the service restart goes through the agent's safe
             reload path (never `service strongswan restart`). --%>
        <div
          :if={@tab == "security" and @ipsec != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <div class="mb-3 flex items-center justify-between">
            <h2 class="text-sm font-medium text-base-content/70">
              IPsec tunnels
              <span
                :if={@ipsec_running != nil}
                class={[
                  "ml-2 text-xs",
                  if(@ipsec_running, do: "text-primary", else: "text-error")
                ]}
              >
                Service {if @ipsec_running, do: "running", else: "stopped"}
              </span>
            </h2>
            <div :if={Instance.monitors_runnable?(@instance)} class="flex items-center gap-1">
              <button
                phx-click="ipsec_recheck"
                title="Re-check tunnel status now (no 5s wait)"
                class="rounded-md px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
              >
                Recheck
              </button>
              <button
                :if={@writable}
                phx-click="ipsec_restart"
                data-confirm={"Restart the IPsec service on #{@instance.name}? ALL tunnels drop and re-establish."}
                class="rounded-md px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
              >
                Restart Service
              </button>
            </div>
          </div>

          <div
            :if={Instance.agent_mode?(@instance) and not @connected}
            class="mb-3 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning"
          >
            Agent silent — tunnel status below is the last push, not live.
          </div>

          <div
            :if={@ipsec_msg}
            class={[
              "mb-3 rounded px-3 py-2 text-xs",
              case @ipsec_msg do
                {:ok, _} -> "bg-primary/15 text-primary"
                _ -> "bg-error/15 text-error"
              end
            ]}
          >
            {elem(@ipsec_msg, 1)}
          </div>

          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <thead class="text-xs text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-1 pr-3 font-medium">Tunnel</th>
                  <th class="py-1 pr-3 font-medium">Remote</th>
                  <th class="py-1 pr-3 font-medium">Status</th>
                  <th class="py-1 pr-3 font-medium">Phase 2</th>
                  <th class="py-1 pr-3 font-medium">Uptime</th>
                  <th class="py-1 pr-3 font-medium">In / Out</th>
                  <th
                    :if={@writable and Instance.monitors_runnable?(@instance)}
                    class="py-1 font-medium"
                  >
                  </th>
                </tr>
              </thead>
              <tbody>
                <%= for t <- @ipsec do %>
                  <% id = to_string(t["id"] || t["description"] || "tunnel") %>
                  <tr class="border-b border-base-300/50 last:border-0">
                    <td class="py-1.5 pr-3">
                      <button
                        :if={(t["children"] || []) != []}
                        phx-click="ipsec_toggle"
                        phx-value-id={id}
                        class="mr-1 text-base-content/60 hover:text-base-content/80"
                      >
                        {if MapSet.member?(@ipsec_expanded, id), do: "▾", else: "▸"}
                      </button>
                      <span class="text-base-content/80">{t["description"] || id}</span>
                      <%!-- Same lip-mismatch hint as the fleet page: the
                           pinned local endpoint is a public address the box
                           no longer owns (moved behind NAT / WAN changed).
                           @public_ip is already loaded for the Network tab. --%>
                      <span
                        :if={Orbit.Ipsec.LocalEndpoint.mismatch?(t["local"], t["status"], @public_ip)}
                        title={Orbit.Ipsec.LocalEndpoint.hint(t["local"], @public_ip)}
                        class="ml-1 rounded bg-warning/20 px-1 py-0.5 text-[10px] text-warning"
                      >
                        local IP drift
                      </span>
                      <.comment_editor
                        text={CommentEditor.text(@comments, @instance.id, "ipsec", id)}
                        writable={@writable}
                        instance_id={@instance.id}
                        kind="ipsec"
                        entity_key={id}
                      />
                    </td>
                    <td class="py-1.5 pr-3 text-base-content/70">{t["remote"] || "—"}</td>
                    <td class={["py-1.5 pr-3", tunnel_color(t["status"])]}>{t["status"] || "?"}</td>
                    <td class="py-1.5 pr-3 text-base-content/70">
                      <span :if={num0(t["phase2_total"]) > 0}>
                        {num0(t["phase2_up"])}/{num0(t["phase2_total"])} up
                      </span>
                      <span :if={num0(t["phase2_total"]) == 0}>—</span>
                    </td>
                    <td class="py-1.5 pr-3 text-base-content/70">
                      {fmt_duration(t["seconds_established"])}
                    </td>
                    <td class="py-1.5 pr-3 text-base-content/70">
                      {fmt_bytes(t["bytes_in"])} / {fmt_bytes(t["bytes_out"])}
                    </td>
                    <td
                      :if={@writable and Instance.monitors_runnable?(@instance)}
                      class="py-1.5 text-right text-xs"
                    >
                      <button
                        phx-click="history_open"
                        phx-value-tunnel={id}
                        phx-value-label={t["description"] || id}
                        phx-value-up={to_string(tunnel_up?(t["status"]))}
                        phx-value-mode="graph"
                        title="Uptime graph"
                        aria-label="Uptime graph"
                        class="mr-1 rounded border border-base-content/20 p-1 align-middle text-base-content/80 hover:bg-base-300"
                      >
                        <Icons.icon name={:chart} class="h-3.5 w-3.5" />
                      </button>
                      <button
                        phx-click="history_open"
                        phx-value-tunnel={id}
                        phx-value-label={t["description"] || id}
                        phx-value-up={to_string(tunnel_up?(t["status"]))}
                        phx-value-mode="history"
                        title="Transition history"
                        aria-label="Transition history"
                        class="mr-1 rounded border border-base-content/20 p-1 align-middle text-base-content/80 hover:bg-base-300"
                      >
                        <Icons.icon name={:audit} class="h-3.5 w-3.5" />
                      </button>
                      <button
                        phx-click="ipsec_diagnose"
                        phx-value-id={id}
                        disabled={diagnose_disabled?(@instance, @diagnosis_busy, @connected)}
                        class="rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {if @diagnosis_busy == id, do: "…", else: "Diagnose"}
                      </button>
                      <button
                        phx-click="ipsec_reconnect"
                        phx-value-id={id}
                        phx-value-uid={t["unique_id"] || ""}
                        disabled={MapSet.member?(@ipsec_busy, id) or not @connected}
                        class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {if MapSet.member?(@ipsec_busy, id), do: "…", else: "Reconnect"}
                      </button>
                      <button
                        :if={tunnel_up?(t["status"])}
                        phx-click="ipsec_disconnect"
                        phx-value-id={id}
                        phx-value-uid={t["unique_id"] || ""}
                        disabled={MapSet.member?(@ipsec_busy, id) or not @connected}
                        class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Disconnect
                      </button>
                      <button
                        :if={not tunnel_up?(t["status"])}
                        phx-click="ipsec_connect"
                        phx-value-id={id}
                        phx-value-uid={t["unique_id"] || ""}
                        disabled={MapSet.member?(@ipsec_busy, id) or not @connected}
                        class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Connect
                      </button>
                    </td>
                  </tr>
                  <tr
                    :for={ch <- t["children"] || []}
                    :if={MapSet.member?(@ipsec_expanded, id)}
                    class="border-b border-base-300/30 bg-base-100/40 text-xs last:border-0"
                  >
                    <td class="py-1 pl-6 pr-3 text-base-content/60">{ch["name"] || "child"}</td>
                    <td class="py-1 pr-3 text-base-content/60" colspan="2">
                      {ch["local_ts"] || "?"} ⇄ {ch["remote_ts"] || "?"}
                    </td>
                    <td class={["py-1 pr-3", tunnel_color(ch["status"])]}>{ch["status"] || "?"}</td>
                    <td class="py-1 pr-3 text-base-content/60" colspan="3">
                      <% mon = p2_monitor(@ipsec_monitors, ch["name"]) %>
                      <span :if={ch["ping_state"] not in [nil, "none"]} class="mr-2">
                        ping {ch["ping_state"]}
                      </span>
                      <span
                        :if={ch["phase2_dup_persistent"] == true}
                        title="Duplicate CHILD_SAs for this selector persisted over several pushes — usually a rekey leak"
                        class="mr-2 text-warning"
                      >
                        ⚠ {ch["dup_count"] || 2}× SAs
                      </span>
                      <span :if={mon} class="text-base-content/40">
                        monitor {if mon.source != "", do: "#{mon.source} "}→ {mon.destination}
                        <span :if={not mon.enabled} class="text-base-content/30">(disabled)</span>
                      </span>
                      <button
                        :if={@writable}
                        phx-click="p2mon_open"
                        phx-value-tunnel={id}
                        phx-value-child={ch["name"] || ""}
                        phx-value-lts={ch["local_ts"] || ""}
                        phx-value-rts={ch["remote_ts"] || ""}
                        phx-value-suggested={ch["suggested_source"] || ""}
                        class="ml-1 rounded border border-base-content/20 px-1.5 py-0.5 text-[10px] text-base-content/70 hover:bg-base-300"
                      >
                        {if mon, do: "edit monitor", else: "add monitor"}
                      </button>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>

          <.tunnel_history_dialog history={@history} />

          <.ping_monitor_dialog
            editor={@ping_editor}
            busy={@ping_test_busy}
            result={@ping_test}
          />

          <div :if={@diagnosis} class="mt-3 rounded-lg border border-base-content/20 bg-base-100 p-3">
            <div class="mb-2 flex items-center justify-between">
              <h3 class="text-xs font-medium text-base-content/80">
                Diagnosis — {@diagnosis.tunnel_id}
              </h3>
              <button
                phx-click="ipsec_diagnose_close"
                class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
              >
                Close
              </button>
            </div>
            <div :if={@diagnosis[:error]} class="text-xs text-error">{@diagnosis.error}</div>
            <details
              :for={s <- @diagnosis.sections}
              class="mb-1 text-xs"
              open={hd(@diagnosis.sections) == s}
            >
              <summary class="cursor-pointer text-base-content/70 hover:text-base-content">
                {s["title"] || "section"}
              </summary>
              <pre class="mt-1 max-h-64 overflow-y-auto whitespace-pre-wrap rounded bg-base-200 p-2 font-mono text-base-content/80">{s["content"]}</pre>
            </details>

            <%!-- "Analyse with AI" over the bundle (DiagnoseDialog parity).
                 Admin-only like the Log-tab analyser, since the bundle is raw
                 box output; the anonymiser and char caps are inside
                 Orbit.LLM.Analyze, so nothing raw leaves here. --%>
            <form
              :if={@admin and @diagnosis.sections != []}
              phx-submit="diag_ai_analyze"
              class="mt-3 flex flex-wrap items-center gap-2 border-t border-base-300 pt-3"
            >
              <select
                name="provider"
                class="rounded border border-base-content/20 bg-base-100 p-1 text-xs text-base-content/80"
              >
                <option :for={p <- Orbit.LLM.Analyze.providers()} value={p.id}>{p.label}</option>
              </select>
              <button
                type="submit"
                disabled={@diag_ai_busy}
                class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {if @diag_ai_busy, do: "Analyzing…", else: "Analyse with AI"}
              </button>
              <span class="text-xs text-base-content/40">anonymized before it leaves the box</span>
            </form>

            <div :if={@diag_ai_error} class="mt-2 text-xs text-error">{@diag_ai_error}</div>

            <div :if={@diag_ai_result} class="mt-3 rounded border border-base-300 bg-base-200 p-3">
              <div class="mb-2 text-xs text-base-content/60">
                {@diag_ai_result.provider} · {@diag_ai_result.model}
              </div>
              <OrbitWeb.MarkdownLite.ai_markdown text={@diag_ai_result.findings} />
            </div>
          </div>
        </div>

        <%!-- Public IP (ExternalIpSection parity, widened to every
             transport): where this box sits on the internet. Hidden
             entirely when nothing is known, so a box that has not reported
             yet shows nothing rather than three dashes. --%>
        <section :if={@tab == "network" and Orbit.ExternalIp.known?(@public_ip)} class="mt-6">
          <h2 class="flex flex-wrap items-center gap-2 text-sm font-medium text-base-content/70">
            <Icons.icon name={:globe} class="h-4 w-4" /> Public IP <.nat_badge nat={@public_ip.nat} />
          </h2>

          <div class="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <.ip_card label="External IPv4" value={@public_ip.ipv4} tone="text-primary">
              <:note :if={@external_geo}>{@external_geo}</:note>
            </.ip_card>
            <.ip_card label="External IPv6" value={@public_ip.ipv6} tone="text-info" />
            <.ip_card
              label="Connects from"
              value={@public_ip.connected && @public_ip.source_ip}
              tone="text-secondary"
            >
              <:note>{connects_from_note(@instance, @public_ip)}</:note>
            </.ip_card>
          </div>

          <p class="mt-2 text-xs text-base-content/50">
            {source_note(@public_ip)}
          </p>
        </section>

        <div
          :if={@tab == "network" and @gateways != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Gateways</h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <thead class="text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-1 pr-4 font-medium">Name</th>
                  <th class="py-1 pr-4 font-medium">Address</th>
                  <th class="py-1 pr-4 font-medium">Status</th>
                  <th class="py-1 pr-4 font-medium">Delay</th>
                  <th class="py-1 font-medium">Loss</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={g <- @gateways} class="border-b border-base-300/50 last:border-0">
                  <td class="py-1.5 pr-4 text-base-content/80">{g["name"]}</td>
                  <td class="py-1.5 pr-4 font-mono text-xs text-base-content/70">
                    {g["address"] || "—"}
                  </td>
                  <td class="py-1.5 pr-4">
                    <span class={gw_color(g["status"])}>{g["status"] || "?"}</span>
                  </td>
                  <td class="py-1.5 pr-4 text-base-content/70">{g["delay"] || "—"}</td>
                  <td class="py-1.5 text-base-content/70">{g["loss"] || "—"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div
          :if={@tab == "network" and @interfaces != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Interfaces</h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <thead class="text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-1 pr-4 font-medium">Name</th>
                  <th class="py-1 pr-4 font-medium">Address</th>
                  <th class="py-1 pr-4 font-medium">Status</th>
                  <th class="py-1 pr-4 font-medium">RX/s</th>
                  <th class="py-1 pr-4 font-medium">TX/s</th>
                  <th class="py-1 font-medium">Errors in/out</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={i <- @interfaces} class="border-b border-base-300/50 last:border-0">
                  <td class="py-1.5 pr-4 text-base-content/80">{i["name"]}</td>
                  <td class="py-1.5 pr-4 font-mono text-xs text-base-content/70">
                    {i["address"] || "—"}
                  </td>
                  <td class="py-1.5 pr-4">
                    <span class={
                      if(i["status"] == "up", do: "text-primary", else: "text-base-content/60")
                    }>
                      {i["status"] || "?"}
                    </span>
                  </td>
                  <td class="py-1.5 pr-4 text-base-content/70">{rate(i["rx_rate"])}</td>
                  <td class="py-1.5 pr-4 text-base-content/70">{rate(i["tx_rate"])}</td>
                  <td class="py-1.5 text-base-content/70">
                    {i["in_errors"] || 0}/{i["out_errors"] || 0}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div :if={@tab in ["overview", "network"]} class="mt-6 grid items-start gap-6 md:grid-cols-2">
          <div
            :if={@tab == "overview" and @services != []}
            class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4"
          >
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Services</h2>
            <ul class="space-y-1 text-sm">
              <li :for={s <- @services} class="flex justify-between text-base-content/80">
                <span class="text-base-content/70">{s["description"] || s["name"]}</span>
                <%!-- "stopped" is not an alarm — plenty of services are off on
                     purpose (iperf, ddclient). The check engine decides what a
                     stopped service means; this list only reports state. --%>
                <span class={if(s["running"], do: "text-primary", else: "text-base-content/50")}>
                  {if s["running"], do: "running", else: "stopped"}
                </span>
              </li>
            </ul>
          </div>

          <div
            :if={@tab == "overview" and @disks != []}
            class="min-w-0 rounded-lg border border-base-300 bg-base-200 p-4"
          >
            <h2 class="mb-3 text-sm font-medium text-base-content/70">Disks</h2>
            <ul class="space-y-1 text-sm">
              <li :for={d <- @disks} class="flex justify-between text-base-content/80">
                <span class="text-base-content/70">{d["mountpoint"] || d["device"]}</span>
                <span>{pct(d["used_pct"])}</span>
              </li>
            </ul>
          </div>
        </div>

        <%!-- Top Talkers (TopTalkersSection parity): pf state-table insight —
              top source/dest talkers by state-lifetime bytes, per-interface /
              protocol state counts, and the biggest flows. Agent push only
              (direct/Securepoint instances never have pf_top). --%>
        <div
          :if={@tab == "network" and (@pf_top["total_states"] || 0) > 0}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">
            Top Talkers
            <span class="font-normal text-base-content/60">· {@pf_top["total_states"]} states</span>
          </h2>

          <div class="grid gap-4 lg:grid-cols-2">
            <.talker_table title="Source" rows={@pf_top["top_sources"] || []} />
            <.talker_table title="Destination" rows={@pf_top["top_dests"] || []} />
          </div>

          <div class="mt-3 flex flex-wrap gap-2 text-xs">
            <span
              :for={i <- @pf_top["interfaces"] || []}
              class="rounded-full border border-base-300 bg-base-100 px-2.5 py-1 text-base-content/70"
              title={bytes(i["bytes"])}
            >
              {i["name"]}: {i["states"]} states
            </span>
            <span
              :for={p <- @pf_top["protocols"] || []}
              class="rounded-full border border-base-300 bg-base-100 px-2.5 py-1 text-base-content/60"
              title={bytes(p["bytes"])}
            >
              {p["proto"]}: {p["states"]}
            </span>
          </div>

          <div
            :if={(@pf_top["top_flows"] || []) != []}
            class="mt-4 overflow-x-auto rounded-lg border border-base-300"
          >
            <table class="w-full min-w-[46rem] text-sm">
              <thead class="bg-base-100 text-left text-xs text-base-content/60">
                <tr>
                  <th class="px-3 py-2">Source</th>
                  <th class="px-3 py-2">Destination</th>
                  <th class="px-3 py-2">Proto</th>
                  <th class="px-3 py-2">Interface</th>
                  <th class="px-3 py-2 text-right">Bytes</th>
                  <th class="px-3 py-2 text-right">Packets</th>
                  <th class="px-3 py-2 text-right">Age</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={f <- @pf_top["top_flows"] || []} class="border-t border-base-300">
                  <td class="px-3 py-2 font-mono text-xs">{hostport(f["src"], f["sport"])}</td>
                  <td class="px-3 py-2 font-mono text-xs">{hostport(f["dst"], f["dport"])}</td>
                  <td class="px-3 py-2 text-base-content/70">{f["proto"]}</td>
                  <td class="px-3 py-2 text-base-content/70">{f["iface"]}</td>
                  <td class="px-3 py-2 text-right font-mono text-xs">{bytes(f["bytes"])}</td>
                  <td class="px-3 py-2 text-right font-mono text-xs">{f["pkts"]}</td>
                  <td class="px-3 py-2 text-right font-mono text-xs">{dur(f["age_s"])}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <%!-- Certificate inventory + expiry (CertificatesSection parity): agent
              push only; soonest expiry first; hidden when the box reports none
              (direct-poll / Securepoint). days_remaining recomputed from
              not_after at render so the countdown never freezes on stale pushes. --%>
        <div
          :if={@tab == "overview" and @certificates != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Certificates</h2>
          <div class="overflow-x-auto rounded-lg border border-base-300">
            <table class="w-full min-w-[46rem] text-sm">
              <thead class="bg-base-100 text-left text-xs text-base-content/60">
                <tr>
                  <th class="px-3 py-2">Name</th>
                  <th class="px-3 py-2">Type</th>
                  <th class="px-3 py-2">Expires</th>
                  <th class="px-3 py-2">Remaining</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={c <- cert_sorted(@certificates)} class="border-t border-base-300">
                  <td class="px-3 py-2 font-medium">
                    <span class="inline-flex items-center gap-1.5">
                      {c["name"]}
                      <span
                        :if={c["is_gui"]}
                        class="rounded bg-info/20 px-1.5 py-0.5 text-[10px] text-info"
                      >
                        GUI
                      </span>
                      <.comment_editor
                        text={
                          CommentEditor.text(
                            @comments,
                            @instance.id,
                            "cert",
                            to_string(c["refid"] || c["name"] || "")
                          )
                        }
                        writable={@writable}
                        instance_id={@instance.id}
                        kind="cert"
                        entity_key={to_string(c["refid"] || c["name"] || "")}
                      />
                    </span>
                  </td>
                  <td class="px-3 py-2 text-base-content/70">
                    {String.upcase(to_string(c["type"] || ""))}
                  </td>
                  <td class="px-3 py-2 font-mono text-xs text-base-content/70">
                    {cert_date(c["not_after"])}
                  </td>
                  <td class={["px-3 py-2", expiry_class(cert_days(c))]}>
                    {expiry_label(cert_days(c))}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div
          :if={@tab == "checks" and @check_history != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Check history</h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <tbody>
                <tr
                  :for={[ts, key, old, new, summary] <- @check_history}
                  class="border-b border-base-300/50 last:border-0"
                >
                  <td class="whitespace-nowrap py-1.5 pr-3 font-mono text-xs text-base-content/60">
                    {cb_ts(ts)}
                  </td>
                  <td class="py-1.5 pr-3 align-top">
                    <span class={["rounded px-1.5 py-0.5 text-xs", state_class(new)]}>
                      {state_label(old)} → {state_label(new)}
                    </span>
                  </td>
                  <td class="whitespace-nowrap py-1.5 pr-3 text-base-content/70">{key}</td>
                  <td class="py-1.5 text-base-content/80">{summary}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div
          :if={@tab == "log" and @firewall_log != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Firewall log (latest)</h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <tbody>
                <tr :for={l <- @firewall_log} class="border-b border-base-300/50 last:border-0">
                  <td class="whitespace-nowrap py-1 pr-3 font-mono text-xs text-base-content/60">
                    {l["__timestamp__"]}
                  </td>
                  <td class="py-1 pr-3">
                    <span class={fw_action_color(l["action"])}>{l["action"]}</span>
                  </td>
                  <td class="py-1 pr-3 text-base-content/70">{l["interface"]}</td>
                  <td class="py-1 pr-3 text-base-content/70">{l["protoname"] || l["proto"]}</td>
                  <td class="py-1 font-mono text-xs text-base-content/80">
                    {l["src"] || l["srcip"]} → {l["dst"] || l["dstip"]}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div
          :if={@tab == "log" and (@logfiles != [] or @log_events != [])}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Logs</h2>
          <div
            :if={@logfiles != []}
            class="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-base-content/60"
          >
            <a
              :for={lf <- @logfiles}
              :if={@admin}
              href={~p"/api/instances/#{@instance.id}/logfiles/#{lf.id}/raw"}
              target="_blank"
              class="text-base-content/70 underline decoration-slate-700 hover:text-primary"
            >
              {lf.name} · {lf.bytes} chars
            </a>
            <span :for={lf <- @logfiles} :if={not @admin}>{lf.name} · {lf.bytes} chars</span>
          </div>
          <div class="overflow-x-auto">
            <table :if={@log_events != []} class="w-full min-w-[46rem] text-left text-sm">
              <tbody>
                <tr
                  :for={e <- Enum.take(@log_events, 15)}
                  class="border-b border-base-300/50 last:border-0"
                >
                  <td class="w-14 py-1.5 pr-3 align-top">
                    <span class={["rounded px-1.5 py-0.5 text-xs", sev_class(e.severity)]}>
                      {sev_label(e.severity)}
                    </span>
                  </td>
                  <td class="whitespace-nowrap py-1.5 pr-3 align-top text-base-content/70">
                    {e.program}
                  </td>
                  <td class="py-1.5 align-top text-base-content/80">{e.pattern}</td>
                  <td class="w-10 py-1.5 pl-3 text-right align-top text-base-content/70">
                    {e.count}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@log_events == [] and @logfiles != []} class="text-xs text-base-content/60">
            No critical events in the latest snapshots.
          </div>

          <form
            :if={@admin and @logfiles != []}
            phx-submit="ai_analyze"
            class="mt-3 flex items-center gap-2 border-t border-base-300 pt-3"
          >
            <select
              name="provider"
              class="rounded border border-base-content/20 bg-base-100 p-1 text-xs text-base-content/80"
            >
              <option :for={p <- Orbit.LLM.Analyze.providers()} value={p.id}>{p.label}</option>
            </select>
            <button
              type="submit"
              disabled={@ai_busy}
              class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @ai_busy, do: "Analyzing…", else: "Analyze with AI"}
            </button>
            <span class="text-xs text-base-content/40">anonymized before it leaves the box</span>
          </form>

          <div :if={@ai_error} class="mt-2 text-xs text-error">{@ai_error}</div>

          <div :if={@ai_result} class="mt-3 rounded border border-base-300 bg-base-100 p-3">
            <div class="mb-2 text-xs text-base-content/60">
              {@ai_result.provider} · {@ai_result.model}
            </div>
            <OrbitWeb.MarkdownLite.ai_markdown text={@ai_result.findings} />
          </div>
        </div>

        <div
          :if={@tab == "config" and @config_backups != []}
          class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/70">
            Config backups <span class="text-base-content/60">({length(@config_backups)})</span>
          </h2>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <tbody>
                <tr
                  :for={cb <- @config_backups}
                  class="border-b border-base-300/50 last:border-0"
                >
                  <td class="py-1.5 pr-4 text-base-content/80">{cb_ts(cb.collected_at)}</td>
                  <td class="py-1.5 pr-4 font-mono text-xs text-base-content/60">
                    {String.slice(cb.sha256, 0, 12)}
                  </td>
                  <td class="py-1.5 pr-4 text-base-content/70">{cb.bytes} bytes · {cb.source}</td>
                  <td class="py-1.5 text-right">
                    <a
                      :if={@admin}
                      href={~p"/api/instances/#{@instance.id}/config-backups/#{cb.id}/diff"}
                      target="_blank"
                      class="mr-3 text-xs text-base-content/70 hover:text-primary"
                    >
                      diff
                    </a>
                    <a
                      :if={@admin}
                      href={~p"/api/instances/#{@instance.id}/config-backups/#{cb.id}/raw"}
                      target="_blank"
                      class="text-xs text-primary hover:text-primary"
                    >
                      download
                    </a>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <%!-- Inline two-version diff (ConfigBackupsSection parity):
              +/- coloured, bounded by the store's diff caps. Admin-only,
              same gate as the raw download links. --%>
          <form
            :if={@admin and length(@config_backups) > 1}
            phx-submit="cb_diff"
            class="mt-3 flex flex-wrap items-end gap-2 text-xs"
          >
            <label class="block">
              <span class="mb-0.5 block text-base-content/60">From</span>
              <select
                name="from"
                class="rounded border border-base-content/20 bg-base-300 px-2 py-1 text-base-content"
              >
                <option
                  :for={cb <- @config_backups}
                  value={cb.id}
                  selected={cb.id == (Enum.at(@config_backups, 1) || %{id: nil}).id}
                >
                  {cb_ts(cb.collected_at)}
                </option>
              </select>
            </label>
            <label class="block">
              <span class="mb-0.5 block text-base-content/60">To</span>
              <select
                name="to"
                class="rounded border border-base-content/20 bg-base-300 px-2 py-1 text-base-content"
              >
                <option
                  :for={cb <- @config_backups}
                  value={cb.id}
                  selected={cb.id == hd(@config_backups).id}
                >
                  {cb_ts(cb.collected_at)}
                </option>
              </select>
            </label>
            <button
              type="submit"
              class="rounded border border-base-content/20 px-3 py-1 text-base-content/80 hover:bg-base-300"
            >
              Show diff
            </button>
            <button
              :if={@cb_diff != nil}
              type="button"
              phx-click="cb_diff_clear"
              class="rounded border border-base-content/20 px-3 py-1 text-base-content/70 hover:bg-base-300"
            >
              Hide
            </button>
          </form>

          <div :if={@cb_diff == {:no_changes}} class="mt-2 text-xs text-base-content/60">
            No differences between the selected versions.
          </div>
          <div
            :if={is_tuple(@cb_diff) and elem(@cb_diff, 0) == :lines}
            class="mt-2 max-h-96 overflow-y-auto rounded bg-base-100 p-2 font-mono text-xs"
          >
            <div
              :for={line <- elem(@cb_diff, 1)}
              class={[
                "whitespace-pre-wrap",
                String.starts_with?(line, "+") && "text-primary",
                String.starts_with?(line, "-") && "text-error"
              ]}
            >
              {line}
            </div>
            <div :if={elem(@cb_diff, 2)} class="mt-1 text-warning">
              (diff truncated)
            </div>
          </div>
        </div>

        <div :if={@tab == "overview"} class="mt-6 rounded-lg border border-base-300 bg-base-200 p-4">
          <h2 class="mb-3 text-sm font-medium text-base-content/70">Notes</h2>

          <form :if={@writable} phx-submit="comment_save" class="mb-4 space-y-2">
            <div class="flex gap-2">
              <select
                name="kind"
                class="rounded border border-base-content/20 bg-base-100 p-1 text-sm text-base-content"
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
                class="flex-1 rounded border border-base-content/20 bg-base-100 p-1 text-sm text-base-content"
              />
            </div>
            <textarea
              name="comment"
              rows="2"
              class="w-full rounded border border-base-content/20 bg-base-100 p-2 text-sm text-base-content"
              placeholder="operator note…"
            ></textarea>
            <button
              type="submit"
              class="rounded bg-primary px-3 py-1 text-xs text-primary-content hover:bg-primary/80"
            >
              Add note
            </button>
          </form>

          <div :if={@comments == []} class="text-sm text-base-content/60">
            No notes on this instance.
          </div>

          <ul :if={@comments != []} class="space-y-2 text-sm">
            <li
              :for={c <- @comments}
              class="flex items-start justify-between gap-3 border-b border-base-300/50 pb-2"
            >
              <div>
                <div class="text-base-content/80">{c.comment}</div>
                <div class="mt-0.5 text-xs text-base-content/60">
                  {c.kind}<span :if={c.entity_key != ""}>:{c.entity_key}</span> · {c.updated_by}
                </div>
              </div>
              <button
                :if={@writable}
                phx-click="comment_clear"
                phx-value-kind={c.kind}
                phx-value-entity_key={c.entity_key}
                class="shrink-0 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
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
    <%!-- min-w-0 + break-words: unbreakable values (a config-revision path,
         a long base URL) used to push the whole card past the viewport on a
         narrow screen instead of wrapping inside it. --%>
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-base-content/60">{@label}</dt>
      <dd class="min-w-0 break-words text-right text-base-content">{@value}</dd>
    </div>
    """
  end

  attr :title, :string, required: true
  attr :rows, :list, required: true

  # One Top-Talkers table (source or destination) — ip / states / bytes.
  defp talker_table(assigns) do
    ~H"""
    <div class="overflow-x-auto rounded-lg border border-base-300">
      <table class="w-full min-w-[46rem] text-sm">
        <thead class="bg-base-100 text-left text-xs text-base-content/60">
          <tr>
            <th class="px-3 py-2">{@title}</th>
            <th class="px-3 py-2 text-right">States</th>
            <th class="px-3 py-2 text-right">Bytes</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={t <- @rows} class="border-t border-base-300">
            <td class="px-3 py-2 font-mono text-xs">{t["ip"]}</td>
            <td class="px-3 py-2 text-right">{t["states"]}</td>
            <td class="px-3 py-2 text-right font-mono text-xs">{bytes(t["bytes"])}</td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  # Certificates soonest-expiry first (CertificatesSection sort).
  defp cert_sorted(certs), do: Enum.sort_by(certs, &cert_days/1)

  # Days until expiry, recomputed from not_after (ISO8601) so a stale push
  # doesn't freeze the countdown; falls back to the pushed days_remaining.
  defp cert_days(%{"not_after" => na} = c) when is_binary(na) do
    case DateTime.from_iso8601(na) do
      {:ok, dt, _} -> DateTime.diff(dt, DateTime.utc_now(), :day)
      _ -> to_int(c["days_remaining"])
    end
  end

  defp cert_days(c), do: to_int(c["days_remaining"])

  defp to_int(n) when is_integer(n), do: n
  defp to_int(_), do: 0

  # not_after → date only (YYYY-MM-DD); mirrors fmtDate.
  defp cert_date(na) when is_binary(na), do: String.slice(na, 0, 10)
  defp cert_date(_), do: "—"

  defp expiry_label(d) when d < 0, do: "expired #{-d}d ago"
  defp expiry_label(0), do: "expires today"
  defp expiry_label(d), do: "#{d}d left"

  defp expiry_class(d) when d < 7, do: "text-error"
  defp expiry_class(d) when d < 30, do: "text-warning"
  defp expiry_class(_), do: "text-primary"

  # "ip:port" (bracketed for IPv6) — mirrors TopTalkersSection.host().
  defp hostport(ip, port) do
    ip = to_string(ip || "")
    port = to_string(port || "")

    cond do
      port == "" -> ip
      String.contains?(ip, ":") -> "[#{ip}]:#{port}"
      true -> "#{ip}:#{port}"
    end
  end

  # Coarse flow-age (seconds → "1h2m" / "3m4s" / "5s").
  defp dur(s) when is_number(s) and s >= 3600,
    do: "#{div(trunc(s), 3600)}h#{rem(div(trunc(s), 60), 60)}m"

  defp dur(s) when is_number(s) and s >= 60, do: "#{div(trunc(s), 60)}m#{rem(trunc(s), 60)}s"
  defp dur(s) when is_number(s), do: "#{trunc(s)}s"
  defp dur(_), do: "—"

  # "no agent" used to mean only "not connected right now", which reads the same
  # on a box that HAS an agent that is momentarily down and on one that never
  # has one at all. Those imply different things — the first will pick up
  # queued monitor config on reconnect, the second is polled and runs its
  # monitors over SSH — so the badge names which it is.
  defp agent_badge(_inst, true), do: "agent connected"

  defp agent_badge(inst, false) do
    if Instance.agent_mode?(inst), do: "agent offline", else: "no agent"
  end

  defp agent_badge_hint(_inst, true), do: "The agent is connected and pushing."

  defp agent_badge_hint(inst, false) do
    if Instance.agent_mode?(inst) do
      "This box runs an agent but it is not connected right now."
    else
      "This box has no agent by design — the dashboard polls it."
    end
  end

  defp conn_badge(true), do: "bg-primary/20 text-primary"
  defp conn_badge(false), do: "bg-base-300 text-base-content/60"

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
      s when s in @gw_up -> "text-primary"
      "" -> "text-base-content/60"
      _ -> "text-error"
    end
  end

  defp fw_action_color("pass"), do: "text-primary"
  defp fw_action_color("block"), do: "text-error"
  defp fw_action_color(_), do: "text-warning"

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
      s when s in @tunnel_up -> "text-primary"
      s when s in ["", "?"] -> "text-warning"
      _ -> "text-error"
    end
  end

  defp tunnel_up?(status) do
    status |> to_string() |> String.downcase() |> Kernel.in(@tunnel_up)
  end

  defp p2_monitor(monitors, child_name) do
    Enum.find(monitors, &(&1.child_name == to_string(child_name || "")))
  end

  defp history_assign(history, window) do
    now = DateTime.utc_now()
    start = Orbit.Ipsec.History.window_start(window, now)

    history
    |> Map.put(:window, window)
    |> Map.put(:window_start, start)
    |> Map.put(
      :events,
      Orbit.Ipsec.History.read(history.instance_id, history.tunnel_id, 200, start)
    )
  end

  # The history lane's right edge: the monitor's CURRENT state, taken from the
  # same evaluation the four check surfaces use rather than re-derived here.
  defp ping_check_state(nil), do: nil

  defp ping_check_state(result) do
    case Orbit.Checks.Evaluate.connectivity_checks([result]) do
      [%{state: state} | _] -> state
      _ -> nil
    end
  end

  defp ping_state_color("ok"), do: "text-primary"
  defp ping_state_color("fail"), do: "text-error"
  defp ping_state_color(nil), do: "text-base-content/60"
  defp ping_state_color(_), do: "text-warning"

  defp num0(v) when is_number(v), do: trunc(v)
  defp num0(_), do: 0

  defp ntp_text(ntp) do
    synced = if ntp["synced"], do: "synced", else: "NOT synced"
    stratum = ntp["stratum"]
    offset = ntp["offset_ms"]

    stratum_part =
      if is_number(stratum) and stratum >= 0, do: ["stratum #{stratum}"], else: []

    offset_part =
      if is_number(offset), do: ["offset #{Float.round(offset / 1, 1)} ms"], else: []

    Enum.join([synced] ++ stratum_part ++ offset_part, " · ")
  end

  # The box reports its config revision as a raw ISO-8601 string
  # ("2026-07-15T23:54:15.630000+00:00") — unreadable in a two-column card.
  # Anything unparseable is passed through untouched rather than hidden.
  defp rev_time(nil), do: "—"
  defp rev_time(""), do: "—"

  defp rev_time(raw) when is_binary(raw) do
    case DateTime.from_iso8601(raw) do
      {:ok, dt, _offset} ->
        Calendar.strftime(DateTime.shift_zone!(dt, "Etc/UTC"), "%Y-%m-%d %H:%M UTC")

      _ ->
        raw
    end
  end

  defp rev_time(other), do: to_string(other)

  defp consumer_tag("checkmk"), do: "cmk"
  defp consumer_tag("mattermost"), do: "mm"
  defp consumer_tag("telegram"), do: "tg"
  defp consumer_tag("email"), do: "mail"
  defp consumer_tag(other), do: other

  # Slowest collectors of the last push, longest first.
  defp top_sections(section_ms) do
    section_ms
    |> Enum.filter(fn {_k, v} -> is_number(v) end)
    |> Enum.sort_by(fn {_k, v} -> -v end)
    |> Enum.take(8)
  end

  defp section_pct(ms, section_ms) do
    max_ms =
      section_ms |> Enum.map(fn {_k, v} -> if(is_number(v), do: v, else: 0) end) |> Enum.max()

    if max_ms > 0, do: trunc(ms / max_ms * 100), else: 0
  end

  defp fmt_duration(seconds) when is_number(seconds) and seconds > 0 do
    s = trunc(seconds)

    cond do
      s >= 86_400 -> "#{div(s, 86_400)}d #{div(rem(s, 86_400), 3_600)}h"
      s >= 3_600 -> "#{div(s, 3_600)}h #{div(rem(s, 3_600), 60)}m"
      s >= 60 -> "#{div(s, 60)}m"
      true -> "#{s}s"
    end
  end

  defp fmt_duration(_), do: "—"

  defp fmt_bytes(n) when is_number(n) and n > 0 do
    cond do
      n >= 1_073_741_824 -> "#{Float.round(n / 1_073_741_824, 1)} GB"
      n >= 1_048_576 -> "#{Float.round(n / 1_048_576, 1)} MB"
      n >= 1_024 -> "#{Float.round(n / 1_024, 1)} KB"
      true -> "#{trunc(n)} B"
    end
  end

  defp fmt_bytes(_), do: "0 B"

  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(3), do: "UNKNOWN"
  defp state_label(_), do: "OK"

  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(3), do: "bg-base-300 text-base-content/70"
  defp state_class(_), do: "bg-primary/20 text-primary"

  defp cb_ts(dt), do: local_time_tag(dt, "datetime")

  # Syslog severity (0 emerg … 4 warning; lower = worse) for the Logs section.
  defp sev_label(s) when s <= 2, do: "CRIT"
  defp sev_label(3), do: "ERR"
  defp sev_label(_), do: "WARN"

  defp sev_class(s) when s <= 2, do: "bg-error/20 text-error"
  defp sev_class(3), do: "bg-orange-900/50 text-orange-300"
  defp sev_class(_), do: "bg-warning/20 text-warning"
end
