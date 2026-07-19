defmodule Orbit.Checks.Confidence do
  @moduledoc """
  Turn one probe result into the `ping` / `http` service checks — port of the
  deleted `checks/confidence.py`.

  These checks are deliberately NOT capped by the staleness overlay: the probe
  is freshly measured and is the very signal that justifies CRIT while
  everything else is stale. The confidence model:

      confirmed-up (agent fresh OR an ICMP reply) → a failing probe is only WARN
      otherwise                                   → a failing probe is CRIT

  So: agent stale + ICMP down = CRIT (a real outage); agent stale + ICMP up =
  the box is reachable but its agent is dead (WARN); agent fresh + HTTP down =
  the web service is down while the box lives (WARN).
  """

  alias Orbit.Checks.ServiceCheck
  alias Orbit.Probe

  @doc "The probe checks for one instance. Empty when nothing was measured."
  @spec probe_checks(boolean(), Probe.result() | nil) :: [ServiceCheck.t()]
  def probe_checks(_agent_fresh?, nil), do: []

  def probe_checks(agent_fresh?, probe) do
    if Probe.probed?(probe) do
      confirmed_up? = agent_fresh? or probe.icmp_up == true

      []
      |> maybe_add(probe.icmp_up, fn -> icmp_check(probe, confirmed_up?) end)
      |> maybe_add(probe.http_up, fn -> http_check(probe, confirmed_up?) end)
    else
      []
    end
  end

  defp maybe_add(list, nil, _fun), do: list
  defp maybe_add(list, _measured, fun), do: list ++ [fun.()]

  # A failed probe is WARN when something else confirms the box is up, else CRIT.
  defp down_state(true), do: ServiceCheck.warn()
  defp down_state(false), do: ServiceCheck.crit()

  defp icmp_check(%{icmp_up: true} = probe, _confirmed) do
    %ServiceCheck{
      key: "ping",
      state: ServiceCheck.ok(),
      summary: "ICMP reachable#{rtt_suffix(probe.rtt_ms)}",
      metrics: rtt_metrics(probe.rtt_ms)
    }
  end

  defp icmp_check(_probe, confirmed_up?) do
    %ServiceCheck{
      key: "ping",
      state: down_state(confirmed_up?),
      summary: "ICMP no echo reply#{other_means(confirmed_up?)}"
    }
  end

  defp http_check(%{http_up: true} = probe, _confirmed) do
    %ServiceCheck{
      key: "http",
      state: ServiceCheck.ok(),
      summary: "HTTP #{probe.http_status} reachable"
    }
  end

  defp http_check(probe, confirmed_up?) do
    code = if probe.http_status, do: " (status #{probe.http_status})", else: ""

    %ServiceCheck{
      key: "http",
      state: down_state(confirmed_up?),
      summary: "HTTP probe failed#{code}#{other_means(confirmed_up?)}"
    }
  end

  defp other_means(true), do: " — box reachable by other means"
  defp other_means(false), do: ""

  defp rtt_suffix(nil), do: ""
  defp rtt_suffix(rtt), do: " (#{:erlang.float_to_binary(rtt, decimals: 1)}ms)"

  defp rtt_metrics(nil), do: []

  defp rtt_metrics(rtt),
    do: [%{"name" => "rtt_ms", "value" => Float.round(rtt, 2), "unit" => "ms"}]
end
