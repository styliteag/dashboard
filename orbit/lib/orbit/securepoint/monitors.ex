defmodule Orbit.Securepoint.Monitors do
  @moduledoc """
  Run the ping monitors ON a Securepoint box over SSH — the agent's
  `collect_connectivity` and the ping half of `collect_ipsec`, for a device that
  has no agent.

  Both probes must originate on the box: an IPsec Phase-2 monitor pings the far
  end THROUGH the tunnel from a specific source address, and a connectivity
  monitor pings from the box's own vantage point. Neither is something the
  dashboard can do from outside, which is why an agent-less appliance had no
  ping results at all.

  Results carry the same keys the agent pushes (`ping_state`, `ping_rtt_ms`,
  `ping_loss_pct`, `ping_ts`), so the checks engine, the VPN page and the
  Connectivity page need no per-transport branch.

  Everything here is best-effort: one bad monitor yields an `error` row, never
  an exception, and a failure to connect leaves the sections untouched rather
  than reporting the fleet down.
  """

  alias Orbit.Monitors
  alias Orbit.Securepoint.SSH

  @doc """
  Attach ping results to a status map: the `connectivity` section, and
  `ping_*` fields on the matching IPsec children.

  Takes an ALREADY OPEN connection: the caller shares one handshake with the
  swanctl dump, and every monitor on the box reuses it.
  """
  def enrich(status, conn, inst) do
    conn_monitors = Enum.filter(Monitors.list_connectivity(inst.id), & &1.enabled)
    ipsec_monitors = Enum.filter(Monitors.list_ipsec(inst.id), & &1.enabled)

    if conn_monitors == [] and ipsec_monitors == [] do
      status
    else
      status
      |> put_connectivity(conn, conn_monitors)
      |> put_ipsec_pings(conn, ipsec_monitors)
    end
  end

  defp put_connectivity(status, _conn, []), do: status

  defp put_connectivity(status, conn, monitors) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    rows =
      for m <- monitors do
        res = SSH.ping(conn, m.source, m.destination, m.ping_count)

        %{
          "id" => m.id,
          "name" => m.name || "",
          "source" => m.source || "",
          "destination" => m.destination || "",
          "ping_state" => res["ping_state"],
          "ping_rtt_ms" => res["ping_rtt_ms"],
          "ping_loss_pct" => res["ping_loss_pct"],
          "ping_ts" => now,
          "enabled" => true
        }
      end

    Map.put(status, "connectivity", rows)
  end

  defp put_ipsec_pings(%{"ipsec" => %{"tunnels" => tunnels} = ipsec} = status, conn, monitors)
       when monitors != [] do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    probed =
      Enum.map(tunnels, fn t ->
        children =
          Enum.map(t["children"] || [], fn c ->
            case match_monitor(t, c, monitors) do
              nil ->
                c

              m ->
                Map.merge(
                  c,
                  ping_fields(SSH.ping(conn, m.source, m.destination, m.ping_count), now)
                )
            end
          end)

        Map.put(t, "children", children)
      end)

    Map.put(status, "ipsec", Map.put(ipsec, "tunnels", probed))
  end

  defp put_ipsec_pings(status, _conn, _monitors), do: status

  defp ping_fields(res, now) do
    %{
      "ping_state" => res["ping_state"],
      "ping_rtt_ms" => res["ping_rtt_ms"],
      "ping_loss_pct" => res["ping_loss_pct"],
      "ping_ts" => now
    }
  end

  # Selector pair first, then name, then whole-tunnel — the agent's
  # `_match_monitor` rule. The pair is authoritative because strongSwan splits a
  # multi-net child into siblings that SHARE one name, so matching on the name
  # alone would run one pair's probe against its sibling.
  defp match_monitor(tunnel, child, monitors) do
    avail = Enum.filter(monitors, &(&1.tunnel_id == tunnel["id"]))

    Enum.find(avail, &selector_match?(&1, child)) ||
      Enum.find(avail, &name_match?(&1, child)) ||
      Enum.find(avail, &whole_tunnel?/1)
  end

  defp selector_match?(m, child) do
    (present(m.local_ts) or present(m.remote_ts)) and
      m.local_ts == child["local_ts"] and m.remote_ts == child["remote_ts"]
  end

  defp name_match?(m, child), do: present(m.child_name) and m.child_name == child["name"]

  defp whole_tunnel?(m), do: not present(m.child_name) and not present(m.local_ts)

  defp present(v), do: is_binary(v) and String.trim(v) != ""
end
