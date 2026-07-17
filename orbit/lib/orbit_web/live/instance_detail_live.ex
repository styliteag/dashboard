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
  alias Orbit.Checks.Export
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Comments
  alias Orbit.Hub
  alias Orbit.Instances.Instance
  alias Orbit.Logs.Store, as: LogStore

  @write_roles ~w(admin user)

  @refresh_ms 5_000

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
          admin: user.role == "admin"
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
    assign(socket, logfiles: LogStore.latest_per_name(id), log_events: LogStore.list_events(id))
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
      checks: instance_checks(socket.assigns.instance)
    )
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
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Terminal
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

  # Syslog severity (0 emerg … 4 warning; lower = worse) for the Logs section.
  defp sev_label(s) when s <= 2, do: "CRIT"
  defp sev_label(3), do: "ERR"
  defp sev_label(_), do: "WARN"

  defp sev_class(s) when s <= 2, do: "bg-red-900/60 text-red-300"
  defp sev_class(3), do: "bg-orange-900/50 text-orange-300"
  defp sev_class(_), do: "bg-amber-900/50 text-amber-300"
end
