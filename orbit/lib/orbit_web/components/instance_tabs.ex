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

  # Vendor/extension tabs (§28): a downstream build (Pro) registers extra tabs
  # via `config :orbit, :vendor_tabs` — each `%{key, label, device_types,
  # agent: bool}` — and open ships none. compile_env must be read in the module
  # body, not per-call. The matching render lives in InstanceDetailLive via the
  # same config, so the tab and its content stay a single registration.
  @vendor_tabs Application.compile_env(:orbit, :vendor_tabs, [])

  @doc """
  The tabs this box can USE right now: `{key, label, kind}` where kind is
  `:tab` (patched within the detail LiveView) or `:link` (its own
  LiveView). This is the routing truth — the detail page's valid-tab set.
  """
  def tabs_for(inst, entry \\ nil) do
    for {key, label, kind, nil} <- all_tabs_for(inst, entry), do: {key, label, kind}
  end

  @doc """
  Every tab of the box's DEVICE CLASS, fourth element = disabled reason
  (nil = usable). Hidden vs disabled (UI/UX review U-M8): a tab the class
  can never have (linux has no config.xml, only OPNsense has the rule
  editor) does not exist; a tab gated on box STATE (agent not enrolled,
  SSH not set up, no data pushed yet) renders disabled with the reason as
  tooltip — the tab set stays predictable per device type instead of
  silently varying 9-vs-11 between two boxes of the same type.

  Mirrors the react device-capability filter: Securepoint is pull-only (no
  agent tabs), the rule editor is OPNsense-specific, linux nodes have no
  config.xml and no VPN.
  """
  def all_tabs_for(inst, entry \\ nil) do
    agent = Instance.agent_mode?(inst)
    # Line-based, not name-based: proxmox/truenas are Linux nodes too — no
    # config.xml, no VPN, Checkmk-dump tab instead.
    linux = Orbit.Agent.Package.linux_line?(inst.device_type)

    # Linux nodes push a raw Checkmk-agent dump; the tab shows it and what
    # Orbit exports to Checkmk for the box.
    ([
       {"overview", "Overview", :tab, nil},
       unless(linux, do: {"config", "Config", :tab, nil}),
       {"checks", "Checks", :tab, nil},
       if(linux, do: {"checkmk", "Checkmk", :tab, agent_reason(agent)})
     ] ++
       vendor_tabs_for(inst, entry) ++
       [
         {"network", "Network", :tab, nil},
         unless(inst.device_type == "securepoint",
           do: {"capture", "Capture", :link, agent_reason(agent)}
         ),
         if(inst.device_type == "opnsense", do: {"firewall", "Firewall", :link, nil}),
         unless(linux, do: {"security", "VPN", :tab, nil}),
         {"connectivity", "Connectivity", :tab, monitors_reason(inst)},
         {"log", "Log", :tab, nil},
         {"firmware", "Firmware", :tab, nil},
         unless(inst.device_type == "securepoint", do: {"agent", "Agent", :tab, nil})
       ])
    |> Enum.reject(&is_nil/1)
  end

  defp agent_reason(true), do: nil
  defp agent_reason(false), do: "Needs a connected agent (push transport)"

  defp monitors_reason(inst) do
    if Instance.monitors_runnable?(inst),
      do: nil,
      else: "Needs an agent — or, on a Securepoint, SSH access with a pinned host key"
  end

  # Vendor tabs matching this box's device type (§28). The optional
  # `visible: {mod, fun}` predicate `fun(entry) -> bool` (e.g. Pro's ZFS tab
  # on a box without ZFS) now DISABLES instead of hiding — evaluated only
  # when a cache `entry` is on hand (the detail page); with no entry
  # (sub-pages) the tab counts as usable, since we can't tell.
  defp vendor_tabs_for(inst, entry) do
    for t <- @vendor_tabs, inst.device_type in Map.get(t, :device_types, []) do
      reason =
        cond do
          Map.get(t, :agent, false) and not Instance.agent_mode?(inst) ->
            agent_reason(false)

          not vendor_tab_visible?(t, entry) ->
            "No data for this on this box yet"

          true ->
            nil
        end

      {t.key, t.label, :tab, reason}
    end
  end

  defp vendor_tab_visible?(t, entry) do
    case Map.get(t, :visible) do
      {mod, fun} when is_map(entry) -> apply(mod, fun, [entry]) == true
      _ -> true
    end
  end

  attr :instance, :map, required: true
  attr :active, :string, required: true, doc: ~s(tab key, e.g. "overview" or "capture")

  attr :entry, :map,
    default: nil,
    doc: "cache entry, so vendor tabs can hide when their data is absent"

  attr :patch?, :boolean,
    default: false,
    doc: "true only on the detail LiveView, which patches its own tabs"

  def instance_tabs(assigns) do
    ~H"""
    <nav class="mb-6 flex flex-wrap gap-1 border-b border-base-300 pb-2">
      <%= for {key, label, kind, reason} <- all_tabs_for(@instance, @entry) do %>
        <%!-- Unavailable-on-this-box tabs render disabled with the reason as
             tooltip instead of vanishing (UI/UX review U-M8). Disabled UI is
             exempt from the text-contrast floor. --%>
        <span
          :if={reason}
          aria-disabled="true"
          title={reason}
          class="cursor-not-allowed rounded-md px-3 py-1 text-sm text-base-content/40"
        >
          {label}
        </span>
        <%!-- Patch keeps the detail LiveView (and its timers) mounted. From a
             sub-page there is nothing to patch into, so those navigate. --%>
        <.link
          :if={is_nil(reason) and kind == :tab and @patch?}
          patch={tab_path(@instance, key)}
          aria-current={if @active == key, do: "page"}
          class={tab_class(@active == key)}
        >
          {label}
        </.link>
        <.link
          :if={is_nil(reason) and kind == :tab and not @patch?}
          navigate={tab_path(@instance, key)}
          aria-current={if @active == key, do: "page"}
          class={tab_class(@active == key)}
        >
          {label}
        </.link>
        <.link
          :if={is_nil(reason) and kind == :link}
          navigate={link_path(@instance, key)}
          aria-current={if @active == key, do: "page"}
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
