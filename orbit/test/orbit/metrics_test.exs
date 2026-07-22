defmodule Orbit.MetricsTest do
  @moduledoc """
  Metrics read path (metrics/store.py parity): range → bucket mapping, the
  MariaDB bucketing SQL (FROM_UNIXTIME/DIV — UTC-pinned sessions), and the
  counter → per-second rate derivation. SQL is asserted as text (house style);
  the thin Repo.query! wrapper stays untested.
  """
  use ExUnit.Case, async: true

  alias Orbit.Metrics

  describe "range_bucket/1" do
    test "maps the five UI ranges to window + bucket seconds" do
      assert {3_600, 0} = Metrics.range_bucket("1h")
      assert {21_600, 60} = Metrics.range_bucket("6h")
      assert {86_400, 300} = Metrics.range_bucket("24h")
      assert {604_800, 900} = Metrics.range_bucket("7d")
      assert {2_592_000, 3_600} = Metrics.range_bucket("30d")
    end

    test "an unknown range falls back to 24h" do
      assert Metrics.range_bucket("nope") == Metrics.range_bucket("24h")
    end
  end

  describe "read/3" do
    test "an unreachable database yields no points instead of killing the caller" do
      # No DB connection is checked out here, so the pool checkout fails
      # exactly as it would against a stressed one — and it EXITS rather
      # than raising, which is why `rescue` alone was not enough. The guard
      # used to live only in the detail LiveView, leaving every other caller
      # (hub, exports, anything added later) unprotected.
      assert Metrics.read(7, "cpu.total", "24h") == []
    end
  end

  describe "build_query/3" do
    test "raw query (bucket 0) selects ordered rows without grouping" do
      {sql, params} = Metrics.build_query(7, "cpu.total", 0)
      assert sql =~ "SELECT ts, value FROM metrics"
      assert sql =~ "ORDER BY ts"
      refute sql =~ "GROUP BY"
      assert [7, "cpu.total", %NaiveDateTime{}, %NaiveDateTime{}] = params
    end

    test "bucketed query groups via FROM_UNIXTIME DIV with an inlined literal" do
      {sql, params} = Metrics.build_query(7, "cpu.total", 300)
      assert sql =~ "FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV 300 * 300)"
      assert sql =~ "avg(value)"
      assert sql =~ "GROUP BY 1 ORDER BY 1"
      assert [7, "cpu.total", %NaiveDateTime{}, %NaiveDateTime{}] = params
    end

    test "start/end params span the requested window" do
      {_sql, [_, _, start_naive, end_naive]} = Metrics.build_query(1, "m", 300, window: 3600)
      assert NaiveDateTime.diff(end_naive, start_naive) == 3600
    end
  end

  describe "uptime_to_seconds/1" do
    test "parses the real-world shapes from all three sources" do
      # agent relays the uptime binary; direct poll pre-formats; Securepoint clock.
      assert Metrics.uptime_to_seconds("18 days, 22:03") == 18 * 86_400 + 22 * 3600 + 3 * 60
      assert Metrics.uptime_to_seconds("5 mins") == 300
      assert Metrics.uptime_to_seconds("1:02") == 3720
      assert Metrics.uptime_to_seconds("1d 18h 18m") == 86_400 + 18 * 3600 + 18 * 60
      assert Metrics.uptime_to_seconds("13 days, 4:07:32") == 13 * 86_400 + 4 * 3600 + 7 * 60 + 32
    end

    test "unparseable strings yield nil — never a fake 0-uptime reboot" do
      assert Metrics.uptime_to_seconds(nil) == nil
      assert Metrics.uptime_to_seconds("") == nil
      assert Metrics.uptime_to_seconds("42") == nil
    end
  end

  describe "rows_for_push/1" do
    # Raw agent push shape (converters.py input) — metric names must stay
    # bit-identical to write_poll_metrics (same table, series continuity).
    defp push do
      %{
        "uptime" => "5 mins",
        "cpu" => %{"total_pct" => 42.5},
        "memory" => %{
          "used_pct" => 25.0,
          "total_mb" => 2000.0,
          "used_mb" => 500.0,
          "swap_total_mb" => 1024.0,
          "swap_used_pct" => 3.0
        },
        "loadavg" => %{"one" => 0.5, "five" => 0.4, "fifteen" => 0.3, "cores" => 4},
        "pf" => %{"states_current" => 900, "states_limit" => 10_000, "states_pct" => 9.0},
        "disks" => [%{"mountpoint" => "/", "used_pct" => 61.0}],
        "interfaces" => [
          %{"name" => "[LAN] vmx0", "bytes_received" => 111, "bytes_transmitted" => 222}
        ],
        "collect_ms" => 1234.5
      }
    end

    test "maps a full push onto the python metric names" do
      rows = Map.new(Metrics.rows_for_push(push()))

      assert rows["system.uptime_seconds"] == 300.0
      assert rows["cpu.total"] == 42.5
      assert rows["memory.used_pct"] == 25.0
      assert rows["load.1m"] == 0.5
      assert rows["memory.swap_used_pct"] == 3.0
      assert rows["pf.states_current"] == 900.0
      assert rows["pf.states_pct"] == 9.0
      assert rows["disk.root.used_pct"] == 61.0
      assert rows["iface.lan_vmx0.bytes_rx"] == 111.0
      assert rows["iface.lan_vmx0.bytes_tx"] == 222.0
      assert rows["agent.collect_ms"] == 1234.5
    end

    test "no-data sentinels write nothing: swap/pf gated, absent collect_ms skipped" do
      data =
        push()
        |> put_in(["memory", "swap_total_mb"], 0)
        |> put_in(["pf", "states_limit"], 0)
        |> Map.delete("collect_ms")
        |> Map.put("uptime", nil)

      metrics = Enum.map(Metrics.rows_for_push(data), &elem(&1, 0))

      refute "memory.swap_used_pct" in metrics
      refute "pf.states_current" in metrics
      refute "pf.states_pct" in metrics
      refute "agent.collect_ms" in metrics
      refute "system.uptime_seconds" in metrics
      assert "cpu.total" in metrics
    end

    test "disk + iface labels sanitize like the python writer" do
      data = %{
        "disks" => [%{"mountpoint" => "/var/log", "used_pct" => 10.0}],
        "interfaces" => [%{"name" => "WAN (PPPoE)", "bytes_received" => 1}]
      }

      metrics = Enum.map(Metrics.rows_for_push(data), &elem(&1, 0))
      assert "disk.var_log.used_pct" in metrics
      assert "iface.wan_pppoe.bytes_rx" in metrics
    end

    test "open registers no vendor_metrics → x_* passthrough is never persisted" do
      data = Map.put(push(), "x_zfs", %{"arc" => %{"hit_ratio_pct" => 90.0}})
      metrics = Enum.map(Metrics.rows_for_push(data), &elem(&1, 0))

      # A downstream build's x_zfs section produces no metric rows in open:
      # the metrics table stays identical, open just never writes these names.
      refute Enum.any?(metrics, &String.starts_with?(&1, "zfs."))
      refute Enum.any?(metrics, &String.starts_with?(&1, "x_"))
      assert "cpu.total" in metrics
    end
  end

  describe "to_rate/1" do
    test "differentiates a monotonic counter into per-second rates" do
      t0 = ~U[2026-07-18 10:00:00Z]
      t1 = ~U[2026-07-18 10:01:00Z]
      t2 = ~U[2026-07-18 10:02:00Z]

      points = [
        %{ts: t0, value: 1_000.0},
        %{ts: t1, value: 7_000.0},
        %{ts: t2, value: 13_000.0}
      ]

      assert [%{ts: ^t1, value: 100.0}, %{ts: ^t2, value: 100.0}] = Metrics.to_rate(points)
    end

    test "clamps counter resets (reboot) to 0 instead of a negative spike" do
      points = [
        %{ts: ~U[2026-07-18 10:00:00Z], value: 9_999.0},
        %{ts: ~U[2026-07-18 10:01:00Z], value: 60.0}
      ]

      assert [%{value: +0.0}] = Metrics.to_rate(points)
    end

    test "empty and single-point series yield no rates" do
      assert Metrics.to_rate([]) == []
      assert Metrics.to_rate([%{ts: ~U[2026-07-18 10:00:00Z], value: 1.0}]) == []
    end
  end
end
