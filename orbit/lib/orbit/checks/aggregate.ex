defmodule Orbit.Checks.Aggregate do
  @moduledoc """
  Collapse high-fan-out checks into one aggregate per category for the
  Checkmk export — port of checks/aggregate.py. A firewall with hundreds of
  certs/tunnels then shows a handful of services instead of one per item:
  each aggregate takes the worst member state and names the offenders in its
  summary so the admin sees exactly what is wrong. Export-only — the
  dashboard and per-instance checks stay granular. Pure + DB-free.
  """

  alias Orbit.Checks.ServiceCheck

  # Key category (text before the first ':') -> {aggregate key, human label}.
  # Only these high-fan-out families collapse; every other key (memory, cpu,
  # agent, firmware, ipsec.service, ...) has no ':' and passes through as its
  # own service. Mirror of python _AGG — keep both sides in sync.
  @agg %{
    "cert" => {"certs", "Certificates"},
    "ipsec.tunnel" => {"ipsec.tunnels", "IPsec tunnels"},
    "ipsec.tunnel_ping" => {"ipsec.pings", "IPsec pings"},
    "service" => {"services", "Services"},
    "iface_errors" => {"iface_errors", "Interface errors"},
    "gateway" => {"gateways", "Gateways"},
    "connectivity" => {"connectivity", "Connectivity"},
    "disk" => {"disks", "Disks"}
  }

  @label Map.new(Map.values(@agg))

  # Offenders named inline before the rest collapse to "(+N more)". Keeps the
  # one-line Checkmk summary readable even when many members fail.
  @max_named 8

  # Worst-wins + offender ordering (severity/1: CRIT > WARN > UNKNOWN > OK).
  @states [2, 1, 3, 0]
  @word %{0 => "OK", 1 => "WARN", 2 => "CRIT", 3 => "UNKNOWN"}

  @doc """
  Collapse each aggregatable category into one ServiceCheck and pass
  everything else through unchanged. Passthrough keeps input order;
  aggregates follow, in the order their category was first seen.
  """
  @spec aggregate_for_checkmk([ServiceCheck.t()]) :: [ServiceCheck.t()]
  def aggregate_for_checkmk(checks) do
    {passthrough, groups, order} =
      Enum.reduce(checks, {[], %{}, []}, fn c, {pass, groups, order} ->
        case category(c.key) && @agg[category(c.key)] do
          nil ->
            {[c | pass], groups, order}

          {agg_key, _label} ->
            order = if Map.has_key?(groups, agg_key), do: order, else: [agg_key | order]
            {pass, Map.update(groups, agg_key, [c], &[c | &1]), order}
        end
      end)

    Enum.reverse(passthrough) ++
      for agg_key <- Enum.reverse(order), do: build(agg_key, Enum.reverse(groups[agg_key]))
  end

  # Category only for colon keys — bare keys never aggregate (python parity:
  # partition on ":" with an empty separator yields None).
  defp category(key) do
    case String.split(key, ":", parts: 2) do
      [head, _rest] -> head
      _ -> nil
    end
  end

  defp build(agg_key, members) do
    label = @label[agg_key]
    worst = Enum.max_by(members, &ServiceCheck.severity(&1.state)).state
    total = length(members)
    counts = Map.new(@states, fn st -> {st, Enum.count(members, &(&1.state == st))} end)

    metrics = [
      ServiceCheck.metric("crit", counts[2] * 1.0),
      ServiceCheck.metric("warn", counts[1] * 1.0),
      ServiceCheck.metric("total", total * 1.0)
    ]

    if worst == 0 do
      %ServiceCheck{
        key: agg_key,
        state: worst,
        summary: "#{label}: all #{total} OK",
        metrics: metrics
      }
    else
      breakdown =
        @states
        |> Enum.filter(&(counts[&1] > 0))
        |> Enum.map_join(", ", &"#{counts[&1]} #{@word[&1]}")

      offenders =
        members
        |> Enum.filter(&(&1.state != 0))
        |> Enum.sort_by(&ServiceCheck.severity(&1.state), :desc)

      named =
        offenders
        |> Enum.take(@max_named)
        |> Enum.map_join("; ", &"#{@word[&1.state]} #{&1.summary}")

      more =
        if length(offenders) > @max_named,
          do: "; (+#{length(offenders) - @max_named} more)",
          else: ""

      %ServiceCheck{
        key: agg_key,
        state: worst,
        summary: "#{label}: #{breakdown} · #{named}#{more}",
        metrics: metrics
      }
    end
  end
end
