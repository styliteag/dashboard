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
  attr :color, :string, default: "text-slate-100"
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
          do: "border-emerald-600 bg-slate-900",
          else: "border-slate-800 bg-slate-900 hover:border-slate-700"
        )
      ]}
    >
      <div class="text-xs text-slate-500">{@label}</div>
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
      <button phx-click="sort" phx-value-col={@col} class="hover:text-slate-300">
        {@label}
        <span :if={@sort_col == @col}>{if @sort_dir == :asc, do: "↑", else: "↓"}</span>
      </button>
    </th>
    """
  end

  @doc "Filter chip class (active/emerald vs idle/slate)."
  def chip(true), do: "rounded-full bg-emerald-600 px-3 py-1 text-xs text-white"

  def chip(false),
    do: "rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-400 hover:bg-slate-700"

  attr :instance_id, :integer, required: true
  attr :openable, :boolean, required: true, doc: "Orbit.GUI.openable(inst) == :ok, precomputed"

  def webui_link(assigns) do
    ~H"""
    <button
      :if={@openable}
      phx-click="row_gui_open"
      phx-value-id={@instance_id}
      title="Open WebGUI (tunneled)"
      class="inline-flex items-center rounded p-0.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
    >
      ⧉
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
      class="inline-flex items-center rounded p-0.5 text-amber-400/80 hover:bg-slate-800 hover:text-amber-300"
    >
      ⌘
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
