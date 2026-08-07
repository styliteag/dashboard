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
  end
end
