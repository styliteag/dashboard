defmodule Orbit.Checks.EvaluateTest do
  @moduledoc "Threshold + incident-rule parity with checks/evaluate.py (pure, DB-free)."
  use ExUnit.Case, async: true

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck

  describe "memory_check — 80/90 thresholds" do
    test "ok / warn / crit boundaries" do
      assert %ServiceCheck{state: 0, key: "memory"} = Evaluate.memory_check(%{"used_pct" => 79.9})
      assert %ServiceCheck{state: 1} = Evaluate.memory_check(%{"used_pct" => 80.0})
      assert %ServiceCheck{state: 1} = Evaluate.memory_check(%{"used_pct" => 89.9})
      assert %ServiceCheck{state: 2} = Evaluate.memory_check(%{"used_pct" => 90.0})
    end

    test "summary rounds the percent and carries perfdata levels" do
      c = Evaluate.memory_check(%{"used_pct" => 90.4})
      assert c.summary == "Memory 90% used (critical)"
      assert [%{name: "mem_used_pct", value: 90.4, warn: 80.0, crit: 90.0, unit: "%"}] = c.metrics
    end

    test "no memory section → nil (never a check on absent data)" do
      assert Evaluate.memory_check(nil) == nil
      assert Evaluate.memory_check(%{}) == nil
    end
  end

  describe "swap_check — no-data sentinel (swap_total_mb<=0)" do
    test "no swap device → nil (incident c37de13: never crit on absent feature)" do
      assert Evaluate.swap_check(%{"swap_total_mb" => 0.0, "swap_used_pct" => 0.0}) == nil
      assert Evaluate.swap_check(%{"used_pct" => 30.0}) == nil
    end

    test "50/80 thresholds when swap present" do
      assert %ServiceCheck{state: 0} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 49.0})

      assert %ServiceCheck{state: 1} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 50.0})

      assert %ServiceCheck{state: 2, key: "swap"} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 80.0})
    end
  end

  describe "cpu_check — WARN ceiling, never crit" do
    test "ok below 95, warn at/above 95, NEVER crit" do
      assert %ServiceCheck{state: 0} = Evaluate.cpu_check(%{"total_pct" => 94.9})
      assert %ServiceCheck{state: 1} = Evaluate.cpu_check(%{"total_pct" => 95.0})
      # Even pegged at 100 CPU stays WARN — spiky, deliberately can't crit.
      assert %ServiceCheck{state: 1} = Evaluate.cpu_check(%{"total_pct" => 100.0})
    end

    test "raw key is total_pct, nil otherwise" do
      assert Evaluate.cpu_check(%{"total" => 99.0}) == nil
      assert Evaluate.cpu_check(nil) == nil
    end
  end

  describe "disk_checks — size-scaled levels" do
    test "small boot disk uses 80/90 fallback" do
      [c] =
        Evaluate.disk_checks([%{"mountpoint" => "/", "used_pct" => 91.0, "total_mb" => 30_000.0}])

      assert c.state == 2
      assert c.key == "disk:/"
      assert c.summary =~ "GB free"
    end

    test "large 2TB volume tolerates more (93/97), so 91% is still OK" do
      [c] =
        Evaluate.disk_checks([
          %{"mountpoint" => "/data", "used_pct" => 91.0, "total_mb" => 2_097_152.0}
        ])

      assert c.state == 0
    end

    test "unknown total falls back to 80/90" do
      [c] = Evaluate.disk_checks([%{"mountpoint" => "/x", "used_pct" => 85.0}])
      assert c.state == 1
    end

    test "one check per volume" do
      checks =
        Evaluate.disk_checks([
          %{"mountpoint" => "/", "used_pct" => 10.0},
          %{"mountpoint" => "/var", "used_pct" => 20.0}
        ])

      assert length(checks) == 2
      assert Enum.map(checks, & &1.key) == ["disk:/", "disk:/var"]
    end
  end

  describe "load_check — per-core saturation, CRIT allowed" do
    test "no-data sentinel: cores<=0 → nil" do
      assert Evaluate.load_check(%{"five" => 3.0, "cores" => 0}) == nil
      assert Evaluate.load_check(nil) == nil
    end

    test "2/4 per-core thresholds on the 5-min average" do
      assert %ServiceCheck{state: 0} = Evaluate.load_check(%{"five" => 3.9, "cores" => 2})
      assert %ServiceCheck{state: 1} = Evaluate.load_check(%{"five" => 4.0, "cores" => 2})
      # Unlike CPU, load CAN crit: 4x cores.
      assert %ServiceCheck{state: 2, key: "load"} =
               Evaluate.load_check(%{"five" => 8.0, "cores" => 2})
    end
  end

  describe "pf_states_check — no-data sentinel (states_limit<=0)" do
    test "direct-poll box (no state table) → nil" do
      assert Evaluate.pf_states_check(%{
               "states_limit" => 0,
               "states_pct" => 0.0,
               "states_current" => 0
             }) ==
               nil
    end

    test "80/95 fill thresholds" do
      base = %{"states_limit" => 100_000, "states_current" => 50_000}
      assert %ServiceCheck{state: 0} = Evaluate.pf_states_check(Map.put(base, "states_pct", 79.0))
      assert %ServiceCheck{state: 1} = Evaluate.pf_states_check(Map.put(base, "states_pct", 80.0))

      assert %ServiceCheck{state: 2, key: "pf_states"} =
               Evaluate.pf_states_check(Map.put(base, "states_pct", 95.0))
    end
  end

  describe "ntp_check — unsynced is WARN never CRIT" do
    test "no-data sentinel: stratum<0 → nil" do
      assert Evaluate.ntp_check(%{"stratum" => -1}) == nil
      assert Evaluate.ntp_check(nil) == nil
    end

    test "synced → OK, unsynced → WARN (freshly booted box never red)" do
      assert %ServiceCheck{state: 0, key: "ntp"} =
               Evaluate.ntp_check(%{
                 "stratum" => 2,
                 "synced" => true,
                 "offset_ms" => 1.2,
                 "peer" => "a"
               })

      assert %ServiceCheck{state: 1} =
               Evaluate.ntp_check(%{"stratum" => 16, "synced" => false})
    end
  end

  describe "gateway_checks — down word ⇒ CRIT, loss 20/80" do
    test "down status is CRIT regardless of loss" do
      [c] = Evaluate.gateway_checks([%{"name" => "WAN", "status" => "down", "loss" => "0%"}])
      assert c.state == 2
      assert c.key == "gateway:WAN"
      assert c.summary == "Gateway WAN down"
    end

    test "loss thresholds when online" do
      online = fn loss -> %{"name" => "WAN", "status" => "online", "loss" => loss} end
      assert [%ServiceCheck{state: 0}] = Evaluate.gateway_checks([online.("5%")])
      assert [%ServiceCheck{state: 1}] = Evaluate.gateway_checks([online.("20%")])
      assert [%ServiceCheck{state: 2}] = Evaluate.gateway_checks([online.("80%")])
    end

    test "missing loss → no perfdata, still OK when up" do
      [c] = Evaluate.gateway_checks([%{"name" => "WAN", "status" => "online"}])
      assert c.state == 0
      assert c.metrics == []
    end
  end

  describe "ipsec_checks — service only when tunnels exist (c37de13)" do
    test "no tunnels → NO service check (never crit an IPsec-less box)" do
      assert Evaluate.ipsec_checks(%{"running" => false, "tunnels" => []}) == []
      assert Evaluate.ipsec_checks(nil) == []
    end

    test "service running/down + tunnel up/down by phase1 status" do
      ipsec = %{
        "running" => true,
        "tunnels" => [
          %{"id" => "con1", "description" => "site-a", "status" => "ESTABLISHED"},
          %{"id" => "con2", "description" => "site-b", "status" => "connecting"}
        ]
      }

      checks = Evaluate.ipsec_checks(ipsec)
      by_key = Map.new(checks, &{&1.key, &1})
      assert by_key["ipsec.service"].state == 0
      assert by_key["ipsec.tunnel:site-a"].state == 0
      assert by_key["ipsec.tunnel:site-b"].state == 2
    end

    test "daemon down but tunnels configured → service CRIT (genuine crash surfaces)" do
      checks =
        Evaluate.ipsec_checks(%{
          "running" => false,
          "tunnels" => [%{"id" => "c", "status" => "down"}]
        })

      assert Enum.find(checks, &(&1.key == "ipsec.service")).state == 2
    end

    test "per-P2 ping: ok/fail/error, 'none' skipped, installed-but-failing is CRIT" do
      ipsec = %{
        "running" => true,
        "tunnels" => [
          %{
            "id" => "t",
            "description" => "site",
            "status" => "installed",
            "children" => [
              %{
                "name" => "c1",
                "remote_ts" => "10.0.0.0/24",
                "ping_state" => "ok",
                "ping_rtt_ms" => 4.2
              },
              %{
                "name" => "c2",
                "remote_ts" => "10.0.1.0/24",
                "ping_state" => "fail",
                "ping_loss_pct" => 100.0
              },
              %{"name" => "c3", "remote_ts" => "10.0.2.0/24", "ping_state" => "error"},
              %{"name" => "c4", "remote_ts" => "10.0.3.0/24", "ping_state" => "none"}
            ]
          }
        ]
      }

      by_key = ipsec |> Evaluate.ipsec_checks() |> Map.new(&{&1.key, &1})
      assert by_key["ipsec.tunnel:site"].state == 0
      assert by_key["ipsec.tunnel_ping:site/10.0.0.0/24"].state == 0
      # Installed child SA but ping fails → CRIT (the whole point).
      assert by_key["ipsec.tunnel_ping:site/10.0.1.0/24"].state == 2
      # Misconfigured probe → WARN, not a false outage.
      assert by_key["ipsec.tunnel_ping:site/10.0.2.0/24"].state == 1
      # Unconfigured child (none) → no check.
      refute Map.has_key?(by_key, "ipsec.tunnel_ping:site/10.0.3.0/24")
    end
  end

  describe "firmware_check — security vs routine vs failed" do
    test "no section → nil" do
      assert Evaluate.firmware_check(nil) == nil
    end

    test "security update ⇒ WARN, names the count" do
      c =
        Evaluate.firmware_check(%{
          "upgrade_available" => true,
          "security_updates" => 2,
          "updates_available" => 5
        })

      assert c.state == 1
      assert c.summary =~ "2 security update(s)"
    end

    test "version upgrade (no security) ⇒ WARN with arrow" do
      c =
        Evaluate.firmware_check(%{
          "upgrade_available" => true,
          "security_updates" => 0,
          "product_version" => "2.7.2",
          "product_latest" => "2.8.1"
        })

      assert c.state == 1
      assert c.summary =~ "2.7.2 → 2.8.1"
    end

    test "failed check ⇒ WARN (never green up-to-date)" do
      c = Evaluate.firmware_check(%{"check_failed" => true, "product_version" => "2.8.1"})
      assert c.state == 1
      assert c.summary =~ "check failed"
    end

    test "routine non-security updates ⇒ OK but counted (§25)" do
      c = Evaluate.firmware_check(%{"updates_available" => 3, "security_updates" => 0})
      assert c.state == 0
      assert c.summary =~ "3 update(s) pending, none security"
    end

    test "clean ⇒ OK up to date" do
      c = Evaluate.firmware_check(%{"product_version" => "2.8.1"})
      assert c.state == 0
      assert c.summary =~ "up to date"
    end
  end

  describe "service_checks — vital present-only, DNS group, systemd failed" do
    test "empty → [] (absent service never invents a red check)" do
      assert Evaluate.service_checks([]) == []
    end

    test "vital services checked only when present; stopped ⇒ CRIT" do
      checks =
        Evaluate.service_checks([
          %{"name" => "sshd", "running" => true},
          %{"name" => "configd", "running" => false}
        ])

      by = Map.new(checks, &{&1.key, &1.state})
      assert by["service:sshd"] == 0
      assert by["service:configd"] == 2
    end

    test "DNS is a group: CRIT only when NO resolver runs" do
      one_up =
        Evaluate.service_checks([
          %{"name" => "unbound", "running" => true},
          %{"name" => "dnsmasq", "running" => false}
        ])

      assert Enum.find(one_up, &(&1.key == "service:dns")).state == 0

      none_up = Evaluate.service_checks([%{"name" => "unbound", "running" => false}])
      assert Enum.find(none_up, &(&1.key == "service:dns")).state == 2
    end

    test "linux systemd failed unit ⇒ WARN, not crit" do
      [c] = Evaluate.service_checks([%{"name" => "foo.service", "failed" => true}])
      assert c.state == 1
      assert c.summary =~ "failed"
    end
  end

  describe "cert_checks — 30/7 day expiry" do
    test "valid / warn / crit / expired by days remaining" do
      mk = fn days -> %{"name" => "c", "refid" => "r#{days}", "days_remaining" => days} end
      assert [%ServiceCheck{state: 0}] = Evaluate.cert_checks([mk.(31)])
      assert [%ServiceCheck{state: 1}] = Evaluate.cert_checks([mk.(29)])
      assert [%ServiceCheck{state: 2}] = Evaluate.cert_checks([mk.(6)])
      [expired] = Evaluate.cert_checks([mk.(-1)])
      assert expired.state == 2
      assert expired.summary =~ "EXPIRED"
    end

    test "GUI marker + refid-based key" do
      [c] =
        Evaluate.cert_checks([
          %{"name" => "web", "refid" => "abc", "days_remaining" => 100, "is_gui" => true}
        ])

      assert c.key == "cert:abc"
      assert c.summary =~ "[GUI]"
    end
  end

  describe "connectivity_checks — categorical ping semantics" do
    test "ok/fail/error, none skipped, keyed by monitor id" do
      results = [
        %{"id" => 1, "name" => "m1", "destination" => "8.8.8.8", "ping_state" => "ok"},
        %{"id" => 2, "name" => "m2", "destination" => "1.1.1.1", "ping_state" => "fail"},
        %{"id" => 3, "name" => "m3", "destination" => "9.9.9.9", "ping_state" => "error"},
        %{"id" => 4, "name" => "m4", "destination" => "x", "ping_state" => "none"}
      ]

      by = results |> Evaluate.connectivity_checks() |> Map.new(&{&1.key, &1.state})
      assert by["connectivity:1"] == 0
      assert by["connectivity:2"] == 2
      assert by["connectivity:3"] == 1
      refute Map.has_key?(by, "connectivity:4")
    end
  end

  describe "severity ordering (UNKNOWN below WARN)" do
    test "CRIT > WARN > UNKNOWN > OK" do
      ranks = Enum.map([2, 1, 3, 0], &ServiceCheck.severity/1)
      assert ranks == [3, 2, 1, 0]
    end
  end

  describe "iface_error_checks — error rate as a % of total packets" do
    test "the rate, not the raw count, decides WARN (0.05%) and CRIT (0.1%)" do
      ifaces = [
        # 0 / 1M = 0.0% -> OK
        %{
          "name" => "em0",
          "status" => "up",
          "in_errors" => 0,
          "out_errors" => 0,
          "in_packets" => 1_000_000,
          "out_packets" => 0
        },
        # 700 / 1M = 0.07% -> WARN
        %{
          "name" => "em1",
          "status" => "up",
          "in_errors" => 500,
          "out_errors" => 200,
          "in_packets" => 1_000_000,
          "out_packets" => 0
        },
        # 2000 / 1M = 0.2% -> CRIT
        %{
          "name" => "em2",
          "status" => "up",
          "in_errors" => 2000,
          "out_errors" => 0,
          "in_packets" => 1_000_000,
          "out_packets" => 0
        }
      ]

      by_key = ifaces |> Evaluate.iface_error_checks() |> Map.new(&{&1.key, &1.state})

      assert by_key["iface_errors:em0"] == 0
      assert by_key["iface_errors:em1"] == 1
      assert by_key["iface_errors:em2"] == 2
    end

    test "a huge raw count on a huge-traffic link stays OK — the whole point" do
      # 1_237_904 errors would have been CRIT under the old absolute levels;
      # against 2e10 packets it is 0.006% and healthy.
      ifaces = [
        %{
          "name" => "ix0",
          "status" => "up",
          "in_errors" => 1_237_904,
          "out_errors" => 0,
          "in_packets" => 20_000_000_000,
          "out_packets" => 0
        }
      ]

      assert [%{key: "iface_errors:ix0", state: 0, metrics: [m]}] =
               Evaluate.iface_error_checks(ifaces)

      assert m.name == "iface_error_rate"
      assert m.unit == "%"
      assert_in_delta m.value, 0.00618952, 0.0001
    end

    test "no error counters ⇒ no check (Securepoint and some poll paths)" do
      # Absent data must never alarm and never fake an OK (c37de13).
      assert Evaluate.iface_error_checks([%{"name" => "A1", "status" => "up"}]) == []
    end

    test "no packet counters ⇒ no check — the rate cannot be formed" do
      ifaces = [%{"name" => "B1", "status" => "up", "in_errors" => 50, "out_errors" => 0}]
      assert Evaluate.iface_error_checks(ifaces) == []
    end

    test "zero packets ⇒ no check — no traffic to rate against, never div-by-zero" do
      ifaces = [
        %{
          "name" => "em4",
          "status" => "up",
          "in_errors" => 3,
          "out_errors" => 0,
          "in_packets" => 0,
          "out_packets" => 0
        }
      ]

      assert Evaluate.iface_error_checks(ifaces) == []
    end

    test "a down interface is skipped — its errors are a symptom, not a second incident" do
      ifaces = [
        %{
          "name" => "em3",
          "status" => "down",
          "in_errors" => 9999,
          "out_errors" => 0,
          "in_packets" => 1000,
          "out_packets" => 0
        }
      ]

      assert Evaluate.iface_error_checks(ifaces) == []
    end

    test "present-but-zero errors on a link with traffic is a real OK, not absent data" do
      ifaces = [
        %{
          "name" => "em0",
          "status" => "up",
          "in_errors" => 0,
          "out_errors" => 0,
          "in_packets" => 5_000_000,
          "out_packets" => 0
        }
      ]

      assert [%{key: "iface_errors:em0", state: 0}] = Evaluate.iface_error_checks(ifaces)
    end

    test "the key is a registered selection category" do
      # A colon-keyed family: category/1 splits on ":" so the rules and the
      # export tree see "iface_errors" (the metric renamed, the family did not).
      [check] =
        Evaluate.iface_error_checks([
          %{
            "name" => "em0",
            "status" => "up",
            "in_errors" => 1,
            "out_errors" => 0,
            "in_packets" => 1000,
            "out_packets" => 0
          }
        ])

      assert Orbit.Selection.valid_selector?("checkmk", check.key)
    end
  end

  describe "collect_check — agent cycle duration" do
    test "a slow cycle WARNs, a quick one is OK" do
      assert %{key: "agent.collect", state: 1} = Evaluate.collect_check(12_500)
      assert %{key: "agent.collect", state: 0} = Evaluate.collect_check(4_100)
    end

    test "summary reports seconds, and the metric carries the warn level" do
      check = Evaluate.collect_check(12_500)
      assert check.summary =~ "12.5s"
      assert [%{name: "collect_seconds", warn: 10.0}] = check.metrics
    end

    test "no data ⇒ no check (a direct-polled box has no agent)" do
      # Absent data must never alarm and must never fake an OK (c37de13).
      assert Evaluate.collect_check(nil) == nil
      assert Evaluate.collect_check(0) == nil
      assert Evaluate.collect_check("slow") == nil
    end
  end

  describe "evaluate/1 over a full cache entry" do
    test "collects non-nil family checks from raw sections" do
      entry = %{
        "status" => %{
          "cpu" => %{"total_pct" => 12.0},
          "memory" => %{"used_pct" => 40.0, "swap_total_mb" => 0.0, "swap_used_pct" => 0.0},
          "disks" => [%{"mountpoint" => "/", "used_pct" => 30.0}]
        }
      }

      keys = entry |> Evaluate.evaluate() |> Enum.map(& &1.key) |> Enum.sort()
      # swap absent (no device) → not emitted.
      assert keys == ["cpu", "disk:/", "memory"]
    end
  end
end
