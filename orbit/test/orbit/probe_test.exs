defmodule Orbit.ProbeTest do
  @moduledoc """
  Target resolution and the probe→check confidence model.

  The network axes themselves are proven live (commit body): ICMP answers from
  a lab box and from 1.1.1.1, times out on unroutable TEST-NET space, and
  reports nxdomain for an unresolvable name. What is unit-tested here is the
  logic that decides WHAT runs and HOW a failure is graded — the part that must
  not regress silently.
  """
  use ExUnit.Case, async: true

  alias Orbit.Checks.Confidence
  alias Orbit.Probe

  describe "target_host/1 — the form of ping_url decides what is probed" do
    test "a URL yields its hostname" do
      assert Probe.target_host("https://fw.example.net:4444/status") == "fw.example.net"
      assert Probe.target_host("http://10.1.2.3/") == "10.1.2.3"
    end

    test "a bare host or host:port yields the host" do
      assert Probe.target_host("10.1.2.3") == "10.1.2.3"
      assert Probe.target_host("fw.example.net") == "fw.example.net"
      assert Probe.target_host("fw.example.net:443") == "fw.example.net"
    end

    test "an IPv6 literal is left alone — several colons are an address, not a port" do
      assert Probe.target_host("2001:db8::1") == "2001:db8::1"
    end

    test "nothing configured means nothing to probe" do
      assert Probe.target_host(nil) == nil
      assert Probe.target_host("  ") == nil
    end
  end

  describe "run/2" do
    test "an unset target measures nothing — never reports down" do
      assert Probe.run(nil) == Probe.empty()
      refute Probe.probed?(Probe.run(nil))
    end
  end

  describe "probed?/1" do
    test "a result is only 'probed' once an axis actually ran" do
      refute Probe.probed?(Probe.empty())
      assert Probe.probed?(%{Probe.empty() | icmp_up: false})
      assert Probe.probed?(%{Probe.empty() | http_up: true})
    end
  end

  describe "confidence model" do
    defp up, do: %{Probe.empty() | icmp_up: true, rtt_ms: 9.87, http_up: true, http_status: 200}
    defp icmp_down, do: %{Probe.empty() | icmp_up: false}
    defp http_down, do: %{Probe.empty() | icmp_up: true, rtt_ms: 1.0, http_up: false}

    test "no probe, or an unmeasured one, yields no checks" do
      assert Confidence.probe_checks(true, nil) == []
      assert Confidence.probe_checks(true, Probe.empty()) == []
    end

    test "a reachable box reports both axes OK with the rtt" do
      assert [ping, http] = Confidence.probe_checks(false, up())

      assert ping.key == "ping"
      assert ping.state == 0
      assert ping.summary == "ICMP reachable (9.9ms)"
      assert [%{"name" => "rtt_ms", "value" => 9.87}] = ping.metrics

      assert http.key == "http"
      assert http.state == 0
      assert http.summary == "HTTP 200 reachable"
    end

    test "ICMP down with nothing confirming the box is up is CRIT" do
      assert [ping] = Confidence.probe_checks(false, icmp_down())

      assert ping.state == 2
      assert ping.summary == "ICMP no echo reply"
    end

    test "ICMP down while the agent is fresh is only WARN" do
      assert [ping] = Confidence.probe_checks(true, icmp_down())

      assert ping.state == 1
      assert ping.summary =~ "reachable by other means"
    end

    test "an ICMP reply alone confirms the box, so a failing HTTP axis is WARN" do
      assert [_ping, http] = Confidence.probe_checks(false, http_down())

      assert http.state == 1, "an answering box must not CRIT because its web service is down"
      assert http.summary =~ "reachable by other means"
    end

    test "only the axes that ran produce a check" do
      assert [only] = Confidence.probe_checks(false, %{Probe.empty() | icmp_up: true, rtt_ms: 2.0})
      assert only.key == "ping"
    end
  end
end
