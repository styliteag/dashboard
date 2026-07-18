defmodule OrbitWeb.Components.ListKit do
  @moduledoc """
  Shared building blocks for the fleet/overview list pages (VPN, Alerts,
  Firmware, Certificates, Connectivity, Hub, Log events) — the interaction
  pattern the react pages shared: clickable KPI tiles, sortable headers,
  filter chips and the per-row WebUI/Terminal quick links.

  Quick links: `gui_open_row/2` is the shared, scope-checked handler body
  for the `row_gui_open` event every page using `webui_link` must wire up
  (invariant 1 — the id from the DOM is untrusted).
  """

  use Phoenix.Component
  use OrbitWeb, :verified_routes

  alias Orbit.Auth.Scope

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :color, :string, default: "text-base-content"
  attr :active, :boolean, default: false
  attr :event, :string, required: true
  attr :value_name, :string, required: true, doc: "phx-value-* payload for the click"

  def kpi_tile(assigns) do
    ~H"""
    <button
      phx-click={@event}
      phx-value-bucket={@value_name}
      class={[
        "rounded-lg border p-3 text-left",
        if(@active,
          do: "border-primary bg-base-200",
          else: "border-base-300 bg-base-200 hover:border-base-content/20"
        )
      ]}
    >
      <div class="text-xs text-base-content/60">{@label}</div>
      <div class={["text-2xl font-semibold", @color]}>{@value}</div>
    </button>
    """
  end

  attr :col, :string, required: true
  attr :label, :string, required: true
  attr :sort_col, :string, required: true
  attr :sort_dir, :atom, required: true

  def sort_th(assigns) do
    ~H"""
    <th class="px-3 py-2 font-medium">
      <button phx-click="sort" phx-value-col={@col} class="hover:text-base-content/80">
        {@label}
        <span :if={@sort_col == @col}>{if @sort_dir == :asc, do: "↑", else: "↓"}</span>
      </button>
    </th>
    """
  end

  @doc "Filter chip class (active/emerald vs idle/slate)."
  def chip(true), do: "rounded-full bg-primary px-3 py-1 text-xs text-white"

  def chip(false),
    do: "rounded-full bg-base-300 px-3 py-1 text-xs text-base-content/70 hover:bg-neutral"

  attr :instance_id, :integer, required: true
  attr :openable, :boolean, required: true, doc: "Orbit.GUI.openable(inst) == :ok, precomputed"

  def webui_link(assigns) do
    ~H"""
    <button
      :if={@openable}
      phx-click="row_gui_open"
      phx-value-id={@instance_id}
      title="Open WebGUI (tunneled)"
      aria-label="Open WebGUI (tunneled)"
      class="inline-flex items-center rounded p-0.5 align-text-bottom text-base-content/70 hover:bg-base-300 hover:text-base-content"
    >
      <%!-- heroicon: arrow-top-right-on-square (outline) --%>
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.8"
        class="h-3.5 w-3.5"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"
        />
      </svg>
    </button>
    """
  end

  attr :instance_id, :integer, required: true
  attr :shell_enabled, :boolean, required: true

  def shell_link(assigns) do
    ~H"""
    <a
      :if={@shell_enabled}
      href={~p"/instances/#{@instance_id}/terminal"}
      target="_blank"
      rel="noopener"
      title="Open root terminal"
      aria-label="Open root terminal"
      class="inline-flex items-center rounded p-0.5 align-text-bottom text-warning/80 hover:bg-base-300 hover:text-warning"
    >
      <%!-- heroicon: command-line (outline) --%>
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.8"
        class="h-3.5 w-3.5"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"
        />
      </svg>
    </a>
    """
  end

  @doc """
  Shared `row_gui_open` handler body: re-resolves the id through the
  caller's scope (never trust the DOM id), re-checks openable, audits and
  pushes the one-shot handoff URL to the `phx:gui_open_url` window hook.
  Write role required — same gate as the detail page button.
  """
  def gui_open_row(socket, raw_id) do
    user = socket.assigns.current_user

    with true <- user.role in ~w(admin user),
         {id, ""} <- Integer.parse(to_string(raw_id)),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         :ok <- Orbit.GUI.openable(inst) do
      url = Orbit.GUI.open_flow(inst, nil)

      Orbit.Audit.write(
        action: "agent.gui_open",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: inst.id
      )

      Phoenix.LiveView.push_event(socket, "gui_open_url", %{url: url})
    else
      _ -> socket
    end
  end
end
