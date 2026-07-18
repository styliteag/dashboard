defmodule OrbitWeb.CaptureLive do
  @moduledoc """
  Live packet capture for one instance — the UI over the capture WS
  (/api/ws/capture/:id, PacketCaptureViewer parity). The page renders a
  small interface/filter form; on start it mounts the `Capture` JS hook
  which opens the session-authed WS, so the full capture auth order (write
  role, scope, connected agent → close codes 4401/4403/4404, regression
  b622b6f) runs server-side, not here.

  mount scopes the instance (get_instance → nil ⇒ redirect, no existence
  oracle) and requires the write role — capture streams a box's raw traffic
  and must never render for a view-only session. Changing interface/filter
  re-keys the hook element so a fresh WS opens with the new params.
  """

  use OrbitWeb, :live_view

  alias Orbit.Auth.Scope
  alias Orbit.Capture.Snapshots

  @write_roles ~w(admin user)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with true <- user.role in @write_roles,
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      {:ok,
       assign(socket,
         instance: inst,
         capturing: false,
         interface: "",
         filter: "",
         run: 0,
         snap_busy: false,
         snap_error: nil,
         snap_id: nil,
         snap_meta: nil,
         snap_packets: [],
         snap_filter: ""
       )}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  @impl true
  def handle_event("start", %{"cap" => params}, socket) do
    {:noreply,
     assign(socket,
       capturing: true,
       interface: String.trim(params["interface"] || ""),
       filter: String.trim(params["filter"] || ""),
       # Bump the run id so the hook element is fresh → new WS with new params.
       run: socket.assigns.run + 1
     )}
  end

  def handle_event("stop", _params, socket) do
    {:noreply, assign(socket, capturing: false)}
  end

  # Snapshot mode (PacketCaptureSection parity): bounded tcpdump via the
  # agent, pcap stored server-side (1h TTL) for download + inline viewer.
  def handle_event("snapshot", %{"cap" => params}, socket) do
    inst = socket.assigns.instance
    seconds = bounded_int(params["max_seconds"], 30, 1, 120)

    payload = %{
      "interface" => String.trim(params["interface"] || ""),
      "filter" => String.trim(params["filter"] || ""),
      "max_seconds" => seconds,
      "max_bytes" => bounded_int(params["max_bytes"], 1_000_000, 10_000, 10_000_000)
    }

    user = socket.assigns.current_user

    {:noreply,
     socket
     |> assign(snap_busy: true, snap_error: nil, capturing: false)
     |> start_async(:snapshot, fn ->
       result = Orbit.Hub.send_command(inst.id, "packet_capture", payload, (seconds + 60) * 1000)
       result = if is_map(result), do: result, else: %{"success" => false}

       Orbit.Audit.write(
         action: "packet_capture.start",
         result: if(result["success"], do: "ok", else: "error"),
         user_id: user.id,
         target_type: "instance",
         target_id: inst.id,
         detail: %{"interface" => payload["interface"], "seconds" => seconds}
       )

       with true <- result["success"] || {:error, to_string(result["output"] || "capture failed")},
            {:ok, pcap} <- Base.decode64(result["pcap_b64"] || "") do
         meta = %{
           "bytes" => result["bytes"] || byte_size(pcap),
           "truncated" => result["truncated"] == true,
           "interface" => result["interface"],
           "filter" => result["filter"] || ""
         }

         {:ok, Snapshots.store(inst.id, pcap, meta), meta, Snapshots.parse(pcap)}
       else
         {:error, msg} -> {:error, msg}
         :error -> {:error, "bad pcap data"}
       end
     end)}
  end

  def handle_event("snap_filter", %{"q" => q}, socket) do
    {:noreply, assign(socket, snap_filter: q)}
  end

  @impl true
  def handle_async(:snapshot, {:ok, outcome}, socket) do
    case outcome do
      {:ok, cid, meta, packets} ->
        {:noreply,
         assign(socket, snap_busy: false, snap_id: cid, snap_meta: meta, snap_packets: packets)}

      {:error, msg} ->
        {:noreply, assign(socket, snap_busy: false, snap_error: String.slice(msg, 0, 300))}
    end
  end

  def handle_async(:snapshot, {:exit, _}, socket) do
    {:noreply, assign(socket, snap_busy: false, snap_error: "capture crashed")}
  end

  defp bounded_int(raw, default, min, max) do
    case Integer.parse(to_string(raw || "")) do
      {n, ""} -> n |> max(min) |> min(max)
      _ -> default
    end
  end

  defp visible_packets(packets, q) do
    q = String.downcase(q)

    if q == "" do
      packets
    else
      Enum.filter(packets, fn p ->
        [p.src, p.dst, p.proto, p.info]
        |> Enum.any?(&String.contains?(String.downcase(to_string(&1)), q))
      end)
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">Packet capture — {@instance.name}</h1>
          <a href={~p"/instances/#{@instance.id}"} class="text-xs text-slate-500 hover:text-slate-300">
            back to detail
          </a>
        </div>

        <form phx-submit="start" class="mb-4 flex flex-wrap items-end gap-2 text-sm">
          <label class="block">
            <span class="mb-1 block text-xs text-slate-500">Interface (blank = default)</span>
            <input name="cap[interface]" value={@interface} placeholder="em0" class={input_cls()} />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-slate-500">BPF filter (blank = all)</span>
            <input
              name="cap[filter]"
              value={@filter}
              placeholder="host 10.0.0.1 and port 443"
              class={input_cls()}
            />
          </label>
          <button
            type="submit"
            class="rounded bg-emerald-700 px-3 py-1.5 text-xs text-white hover:bg-emerald-600"
          >
            {if @capturing, do: "Restart", else: "Start capture"}
          </button>
          <button
            :if={@capturing}
            type="button"
            phx-click="stop"
            class="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Stop
          </button>
        </form>

        <%!-- Snapshot mode: bounded capture, downloadable pcap + parsed view. --%>
        <form phx-submit="snapshot" class="mb-4 flex flex-wrap items-end gap-2 text-sm">
          <label class="block">
            <span class="mb-1 block text-xs text-slate-500">Interface</span>
            <input name="cap[interface]" value={@interface} placeholder="em0" class={input_cls()} />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-slate-500">BPF filter</span>
            <input name="cap[filter]" value={@filter} class={input_cls()} />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-slate-500">Seconds (≤120)</span>
            <input
              name="cap[max_seconds]"
              value="15"
              class="w-20 rounded border border-slate-700 bg-slate-950 p-1.5 text-sm text-slate-200"
            />
          </label>
          <button
            type="submit"
            disabled={@snap_busy}
            class="rounded bg-sky-700 px-3 py-1.5 text-xs text-white hover:bg-sky-600 disabled:opacity-50"
          >
            {if @snap_busy, do: "Capturing…", else: "Snapshot capture"}
          </button>
          <a
            :if={@snap_id}
            href={~p"/api/captures/#{@snap_id}/pcap"}
            class="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Download pcap ({@snap_meta["bytes"]} B{if @snap_meta["truncated"], do: ", truncated"})
          </a>
        </form>

        <div :if={@snap_error} class="mb-3 rounded bg-red-900/40 px-3 py-2 text-xs text-red-300">
          {@snap_error}
        </div>

        <div
          :if={@snap_packets != []}
          class="mb-4 rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <form phx-change="snap_filter" onsubmit="return false" class="mb-2">
            <input
              type="text"
              name="q"
              value={@snap_filter}
              placeholder="Filter packets (src/dst/proto/info)…"
              phx-debounce="200"
              class="w-full max-w-sm rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200"
            />
          </form>
          <div class="max-h-96 overflow-y-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="sticky top-0 bg-slate-950 text-slate-500">
                <tr>
                  <th class="py-1 pr-3 font-medium">#</th>
                  <th class="py-1 pr-3 font-medium">Proto</th>
                  <th class="py-1 pr-3 font-medium">Source</th>
                  <th class="py-1 pr-3 font-medium">Destination</th>
                  <th class="py-1 pr-3 font-medium">Len</th>
                  <th class="py-1 font-medium">Info</th>
                </tr>
              </thead>
              <tbody>
                <%= for p <- visible_packets(@snap_packets, @snap_filter) do %>
                  <tr class="border-t border-slate-800/50 align-top">
                    <td class="py-0.5 pr-3 text-slate-600">{p.idx}</td>
                    <td class="py-0.5 pr-3 text-slate-300">{p.proto}</td>
                    <td class="py-0.5 pr-3 text-slate-400">{p.src}</td>
                    <td class="py-0.5 pr-3 text-slate-400">{p.dst}</td>
                    <td class="py-0.5 pr-3 text-slate-500">{p.len}</td>
                    <td class="py-0.5 text-slate-400">
                      <details :if={p.hex != ""}>
                        <summary class="cursor-pointer">{p.info}</summary>
                        <div class="mt-1 break-all text-[10px] text-slate-600">{p.hex}</div>
                      </details>
                      <span :if={p.hex == ""}>{p.info}</span>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>

        <div
          :if={@capturing}
          id={"capture-#{@run}"}
          phx-hook="Capture"
          data-instance-id={@instance.id}
          data-interface={@interface}
          data-filter={@filter}
          class="rounded-lg border border-slate-800 bg-slate-950 p-3"
        >
          <div class="mb-2 text-xs text-slate-500">
            Status: <span data-cap-status class="text-slate-300">connecting…</span>
          </div>
          <pre
            data-cap-out
            class="h-96 overflow-y-auto whitespace-pre-wrap font-mono text-xs text-slate-300"
          ></pre>
        </div>

        <p :if={not @capturing} class="text-sm text-slate-500">
          Start a capture to stream live traffic from the box. Requires a connected agent.
        </p>
      </section>
    </main>
    """
  end

  defp input_cls do
    "rounded border border-slate-700 bg-slate-950 p-1.5 text-sm text-slate-200"
  end
end
