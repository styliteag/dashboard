defmodule Orbit.Checks.AggregateTest do
  @moduledoc "Checkmk aggregate-collapse parity with checks/aggregate.py."
  use ExUnit.Case, async: true

  alias Orbit.Checks.{Aggregate, ServiceCheck}

  defp check(key, state, summary \\ nil) do
    %ServiceCheck{key: key, state: state, summary: summary || key, metrics: []}
  end

  test "bare keys pass through untouched, input order kept" do
    checks = [check("cpu", 0), check("memory", 1), check("agent", 0)]
    assert Aggregate.aggregate_for_checkmk(checks) == checks
  end

  test "unknown colon category passes through (only listed families collapse)" do
    checks = [check("pf_states:foo", 0)]
    assert Aggregate.aggregate_for_checkmk(checks) == checks
  end

  test "all-OK family collapses to one OK aggregate with counts" do
    out = Aggregate.aggregate_for_checkmk([check("cert:web", 0), check("cert:vpn", 0)])

    assert [%ServiceCheck{key: "certs", state: 0, summary: "Certificates: all 2 OK"} = agg] = out

    assert Enum.map(agg.metrics, &{&1.name, &1.value}) == [
             {"crit", 0.0},
             {"warn", 0.0},
             {"total", 2.0}
           ]
  end

  test "worst member state wins; offenders named worst-first, breakdown counted" do
    out =
      Aggregate.aggregate_for_checkmk([
        check("service:sshd", 0),
        check("service:ntpd", 1, "ntpd stopped"),
        check("service:unbound", 2, "unbound stopped")
      ])

    assert [%ServiceCheck{key: "services", state: 2, summary: summary}] = out
    assert summary =~ "Services: 1 CRIT, 1 WARN, 1 OK"
    # Worst first: CRIT offender before the WARN one.
    assert summary =~ "CRIT unbound stopped; WARN ntpd stopped"
  end

  test "UNKNOWN ranks below WARN for worst-wins (severity, not numeric state)" do
    out = Aggregate.aggregate_for_checkmk([check("gateway:WAN", 3), check("gateway:LTE", 1)])
    assert [%ServiceCheck{key: "gateways", state: 1}] = out
  end

  test "more than 8 offenders collapse into (+N more)" do
    members = for i <- 1..11, do: check("cert:c#{i}", 2, "cert c#{i} expired")
    assert [%ServiceCheck{summary: summary}] = Aggregate.aggregate_for_checkmk(members)
    assert summary =~ "(+3 more)"
  end

  test "passthrough first, aggregates follow in first-seen category order" do
    out =
      Aggregate.aggregate_for_checkmk([
        check("gateway:WAN", 0),
        check("cpu", 0),
        check("cert:web", 0)
      ])

    assert Enum.map(out, & &1.key) == ["cpu", "gateways", "certs"]
  end
end
