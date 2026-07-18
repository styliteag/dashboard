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
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-base-content">
          Terminal — {@instance.name}
          <span class="ml-2 rounded bg-error/20 px-2 py-0.5 text-xs text-error">root</span>
        </h1>

        <div :if={not @shell_enabled} class="text-sm text-warning">
          The terminal is not enabled for this instance (Edit instance → Terminal).
        </div>

        <div :if={@shell_enabled} class="max-w-5xl">
          <div
            id="terminal"
            phx-hook="Terminal"
            phx-update="ignore"
            data-instance-id={@instance.id}
            class="rounded-lg border border-base-300 bg-black p-3"
          >
            <div class="mb-2 flex items-center gap-2 text-xs">
              <span data-term-status class="text-xs text-warning">connecting…</span>
              <span class="text-base-content/40">— click to focus; keystrokes stream live to the box.</span>
            </div>
            <div data-term-mount class="h-[32rem] w-full"></div>
          </div>
        </div>
      </section>
    </main>
    """
  end
end
