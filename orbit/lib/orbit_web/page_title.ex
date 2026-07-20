defmodule OrbitWeb.PageTitle do
  @moduledoc """
  Default `page_title` for every LiveView, derived from the module name
  (AlertsLive → "Alerts"), attached once via the `live_view` macro in
  `OrbitWeb`. Before this hook no view set a title at all, so every browser
  tab read the bare layout default and history was one indistinguishable
  entry per page. Views with a better dynamic title (InstanceDetailLive
  assigns the instance name) simply assign over it in `mount`/`handle_params`
  — `assign_new` here never wins against an explicit assign.
  """

  import Phoenix.Component, only: [assign_new: 3]

  # Names where the mechanical CamelCase split reads wrong.
  @overrides %{
    "Vpn" => "VPN",
    "ApiKeys" => "API keys",
    "HubStatus" => "Hub status",
    "AccessControl" => "Access control",
    "LogEvents" => "Logs",
    "InstanceCreate" => "New instance",
    "InstanceDetail" => "Instance",
    "InstanceEdit" => "Edit instance"
  }

  def on_mount(:default, _params, _session, socket) do
    {:cont, assign_new(socket, :page_title, fn -> title(socket.view) end)}
  end

  defp title(view) do
    base = view |> Module.split() |> List.last() |> String.replace_suffix("Live", "")
    Map.get(@overrides, base, humanize(base))
  end

  # "FirewallRules" → "Firewall rules"
  defp humanize(base) do
    [head | rest] =
      base
      |> String.replace(~r/(?<=[a-z])(?=[A-Z])/, " ")
      |> String.split(" ")

    Enum.join([head | Enum.map(rest, &String.downcase/1)], " ")
  end
end
