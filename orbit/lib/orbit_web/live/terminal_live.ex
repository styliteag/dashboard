defmodule OrbitWeb.TerminalLive do
  @moduledoc """
  Browser root terminal for one instance — the UI over the shell WS
  (/api/ws/shell/:id). The page only renders the terminal shell + the
  `Terminal` JS hook; the hook opens the session-authed WS, so the full auth
  order (write role, scope, per-instance shell_enabled, slot cap → close
  codes 4401/4403/4404/4008) runs server-side, not here.

  mount scopes the instance (get_instance → nil ⇒ redirect, no existence
  oracle) and refuses when the terminal isn't enabled for the box, so the
  hook only ever attaches to a shell that will actually open.
  """

  use OrbitWeb, :live_view

  alias Orbit.Auth.Scope

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      {:ok, assign(socket, instance: inst, shell_enabled: inst.shell_enabled == true)}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <nav class="flex gap-3 text-sm text-slate-400">
            <a href={~p"/instances/#{@instance.id}"} class="hover:text-slate-200">
              ← {@instance.name}
            </a>
          </nav>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Terminal — {@instance.name}
          <span class="ml-2 rounded bg-red-900/60 px-2 py-0.5 text-xs text-red-300">root</span>
        </h1>

        <div :if={not @shell_enabled} class="text-sm text-amber-400">
          The terminal is not enabled for this instance (Edit instance → Terminal).
        </div>

        <div
          :if={@shell_enabled}
          id="terminal"
          phx-hook="Terminal"
          data-instance-id={@instance.id}
          class="rounded-lg border border-slate-800 bg-black p-3"
        >
          <pre
            data-term-out
            class="h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-emerald-300"
          ></pre>
          <input
            data-term-input
            type="text"
            autofocus
            autocomplete="off"
            spellcheck="false"
            placeholder="type here — keystrokes stream to the box"
            class="mt-2 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-100 focus:border-emerald-500 focus:outline-none"
          />
        </div>
      </section>
    </main>
    """
  end
end
