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

  @write_roles ~w(admin user)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with true <- user.role in @write_roles,
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      {:ok, assign(socket, instance: inst, capturing: false, interface: "", filter: "", run: 0)}
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
