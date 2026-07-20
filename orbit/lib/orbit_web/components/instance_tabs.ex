defmodule OrbitWeb.Components.InstanceTabs do
  @moduledoc """
  The per-instance tab bar, shared by the detail page and every sub-page.

  Capture, Firewall and Terminal are their own LiveViews rather than tabs of
  the detail page (they hold sockets and long-running state). They rendered
  without this bar, so opening one dropped the operator out of the instance:
  no way to reach another tab, only a "back to detail" link. The bar now
  travels with them, with the sub-page marked active.

  `tabs_for/1` is the single definition of which tabs a box has — the
  device-capability filter that used to live inside InstanceDetailLive.
  """

  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: OrbitWeb.Endpoint,
    router: OrbitWeb.Router,
    statics: OrbitWeb.static_paths()

  alias Orbit.Instances.Instance

  @doc """
  Which tabs this box has: `{key, label, kind}` where kind is `:tab` (patched
  within the detail LiveView) or `:link` (its own LiveView).

  Mirrors the react device-capability filter: Securepoint is pull-only (no
  agent tabs), the rule editor is OPNsense-specific, linux nodes have no
  config.xml and no VPN.
  """
  def tabs_for(inst) do
    agent = Instance.agent_mode?(inst)
    linux = inst.device_type == "linux"

    [
      {"overview", "Overview", :tab},
      unless(linux, do: {"config", "Config", :tab}),
      {"checks", "Checks", :tab},
      {"network", "Network", :tab},
      if(agent, do: {"capture", "Capture", :link}),
      if(inst.device_type == "opnsense", do: {"firewall", "Firewall", :link}),
      unless(linux, do: {"security", "VPN", :tab}),
      if(Instance.monitors_runnable?(inst), do: {"connectivity", "Connectivity", :tab}),
      {"log", "Log", :tab},
      {"firmware", "Firmware", :tab},
      unless(inst.device_type == "securepoint", do: {"agent", "Agent", :tab})
    ]
    |> Enum.reject(&is_nil/1)
  end

  attr :instance, :map, required: true
  attr :active, :string, required: true, doc: ~s(tab key, e.g. "overview" or "capture")

  attr :patch?, :boolean,
    default: false,
    doc: "true only on the detail LiveView, which patches its own tabs"

  def instance_tabs(assigns) do
    ~H"""
    <nav class="mb-6 flex flex-wrap gap-1 border-b border-base-300 pb-2">
      <%= for {key, label, kind} <- tabs_for(@instance) do %>
        <%!-- Patch keeps the detail LiveView (and its timers) mounted. From a
             sub-page there is nothing to patch into, so those navigate. --%>
        <.link
          :if={kind == :tab and @patch?}
          patch={tab_path(@instance, key)}
          class={tab_class(@active == key)}
        >
          {label}
        </.link>
        <.link
          :if={kind == :tab and not @patch?}
          navigate={tab_path(@instance, key)}
          class={tab_class(@active == key)}
        >
          {label}
        </.link>
        <.link
          :if={kind == :link}
          navigate={link_path(@instance, key)}
          class={tab_class(@active == key)}
        >
          {label}
        </.link>
      <% end %>
    </nav>
    """
  end

  defp tab_path(inst, "overview"), do: ~p"/instances/#{inst.id}"
  defp tab_path(inst, key), do: ~p"/instances/#{inst.id}/#{key}"

  defp link_path(inst, "capture"), do: ~p"/instances/#{inst.id}/capture"
  defp link_path(inst, "firewall"), do: ~p"/instances/#{inst.id}/firewall"
  defp link_path(inst, key), do: tab_path(inst, key)

  defp tab_class(active?) do
    [
      "rounded-md px-3 py-1 text-sm",
      if(active?,
        do: "bg-base-300 text-base-content",
        else: "text-base-content/70 hover:bg-base-300/60 hover:text-base-content"
      )
    ]
  end
end
