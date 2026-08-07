defmodule OrbitWeb.LogEventsLiveTest do
  @moduledoc "Auth gate (DB-free); scoped fleet log events proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  alias OrbitWeb.LogEventsLive

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/logs")
  end

  # Prod feedback 2026-08-07: RFC5424 boxes (OPNsense syslog-ng/openvpn)
  # stamp ISO-8601 with an offset — those fell through to the raw string
  # and the Last-seen column showed three formats at once.
  describe "device_ts/1" do
    test "parses ISO-8601 with offset, normalised to UTC" do
      assert LogEventsLive.device_ts("2026-08-07T18:29:13+02:00") ==
               ~U[2026-08-07 16:29:13Z]
    end

    test "parses RFC3164 with the current-year heuristic" do
      dt = LogEventsLive.device_ts("Aug  6 20:07:54")
      assert %DateTime{month: 8, day: 6, hour: 20} = dt
      assert dt.year in [DateTime.utc_now().year, DateTime.utc_now().year - 1]
    end

    test "unparseable stamps stay nil (the raw string renders instead)" do
      assert LogEventsLive.device_ts("last reboot") == nil
      assert LogEventsLive.device_ts(nil) == nil
    end

    # RFC3164 has no zone and boxes stamp LOCAL time — read as UTC a fresh
    # CEST entry showed "in 40min" (prod feedback 2026-08-07). A future
    # last-seen is impossible: roll back whole hours (the reconstructed
    # offset); offset-carrying ISO stamps only clamp to now on clock drift.
    test "future RFC3164 stamps roll back whole hours to land in the past" do
      now = ~U[2026-08-07 16:49:00Z]

      # +40min ahead (CEST box, +2h zone, entry 1h20 old) → minus 1h
      assert LogEventsLive.device_ts("Aug  7 17:29:00", now) == ~U[2026-08-07 16:29:00Z]
      # +1h40 ahead → minus 2h
      assert LogEventsLive.device_ts("Aug  7 18:29:00", now) == ~U[2026-08-07 16:29:00Z]
      # already in the past: untouched
      assert LogEventsLive.device_ts("Aug  7 15:00:00", now) == ~U[2026-08-07 15:00:00Z]
    end

    test "future ISO stamps clamp to now (clock drift, offset already exact)" do
      now = ~U[2026-08-07 16:49:00Z]
      assert LogEventsLive.device_ts("2026-08-07T18:51:00+02:00", now) == now
    end
  end
end
