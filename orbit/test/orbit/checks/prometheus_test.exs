defmodule Orbit.Checks.PrometheusTest do
  @moduledoc "Prometheus text-format parity with checks/prometheus.py."
  use ExUnit.Case, async: true

  alias Orbit.Checks.{Prometheus, ServiceCheck}

  defp inst, do: %{id: 7, name: "pf2", device_type: "pfsense", mode: "push"}

  test "empty rows render nothing" do
    assert Prometheus.render([]) == ""
  end

  test "instance_info + check_state families, HELP + TYPE headers" do
    checks = [%ServiceCheck{key: "cpu", state: 0, summary: "CPU 12%", metrics: []}]
    text = Prometheus.render([{inst(), checks}])

    assert text =~ "# HELP orbit_instance_info Instance metadata; value is always 1"
    assert text =~ "# TYPE orbit_instance_info gauge"

    assert text =~
             ~s(orbit_instance_info{instance_id="7",instance_name="pf2",device_type="pfsense",mode="push"} 1)

    assert text =~ ~s(orbit_check_state{instance_id="7",instance_name="pf2",key="cpu"} 0)
  end

  test "metric + warn + crit families with metric/unit labels" do
    checks = [
      %ServiceCheck{
        key: "memory",
        state: 1,
        summary: "Memory 85% used (high)",
        metrics: [ServiceCheck.metric("mem_used_pct", 85.0, warn: 80.0, crit: 90.0, unit: "%")]
      }
    ]

    text = Prometheus.render([{inst(), checks}])
    labels = ~s(instance_id="7",instance_name="pf2",key="memory",metric="mem_used_pct",unit="%")
    assert text =~ "orbit_check_metric{#{labels}} 85"
    assert text =~ "orbit_check_metric_warn{#{labels}} 80"
    assert text =~ "orbit_check_metric_crit{#{labels}} 90"
  end

  test "reserved `instance` label never appears; instance_id/name always do" do
    checks = [%ServiceCheck{key: "cpu", state: 0, summary: "x", metrics: []}]
    text = Prometheus.render([{inst(), checks}])
    assert text =~ ~s(instance_id=")
    assert text =~ ~s(instance_name=")
    refute Regex.match?(~r/[{,]instance="/, text)
  end

  test "integral floats drop .0, fractional keep precision, no sci notation" do
    checks = [
      %ServiceCheck{
        key: "k",
        state: 0,
        summary: "s",
        metrics: [ServiceCheck.metric("m", 1234.0, unit: "")]
      }
    ]

    text = Prometheus.render([{inst(), checks}])
    assert text =~ "orbit_check_metric{"
    assert text =~ "} 1234"
    refute text =~ "1234.0"
  end

  test "every emitted family is registered in HELP (rule 20)" do
    checks = [
      %ServiceCheck{
        key: "m",
        state: 2,
        summary: "s",
        metrics: [ServiceCheck.metric("x", 5.0, warn: 1.0, crit: 2.0)]
      }
    ]

    text = Prometheus.render([{inst(), checks}])
    help = Regex.scan(~r/^# HELP (\S+)/m, text) |> Enum.map(&List.last/1) |> MapSet.new()

    families =
      Regex.scan(~r/^([a-zA-Z_:][a-zA-Z0-9_:]*)\{/m, text)
      |> Enum.map(&List.last/1)
      |> MapSet.new()

    assert MapSet.subset?(families, help)
  end
end
