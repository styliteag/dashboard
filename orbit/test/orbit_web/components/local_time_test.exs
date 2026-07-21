defmodule OrbitWeb.Components.LocalTimeTest do
  @moduledoc """
  The `<time data-localtime>` contract that app.js localises client-side.

  The load-bearing assertion is the `datetime` attribute: it must be an
  unambiguous UTC instant. A `NaiveDateTime` (how MariaDB `UtcDateTime` columns
  read back — naive-but-UTC) MUST get a trailing `Z`; without it the browser
  parses it as local time and every stamp silently shifts by the viewer's
  offset — invisible to a developer sitting at UTC+0, two hours wrong for the
  German operators this was built for.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.CoreComponents

  describe "iso_utc/1" do
    test "a naive UtcDateTime read-back is tagged Z so the browser reads it as UTC" do
      assert CoreComponents.iso_utc(~N[2026-07-21 20:53:10]) == "2026-07-21T20:53:10Z"
    end

    test "a UTC DateTime serialises as a UTC instant, never zoneless" do
      iso = CoreComponents.iso_utc(~U[2026-07-21 20:53:10Z])
      assert String.ends_with?(iso, "Z") or String.contains?(iso, "+00:00")
      refute iso == "2026-07-21T20:53:10"
    end
  end

  describe "local_time_tag/2" do
    test "renders a <time> carrying the UTC datetime attr, the fmt, and a UTC fallback body" do
      html =
        CoreComponents.local_time_tag(~N[2026-07-21 20:53:10], "datetime-sec")
        |> Phoenix.HTML.safe_to_string()

      assert html =~ "data-localtime"
      assert html =~ ~s(data-fmt="datetime-sec")
      assert html =~ ~s(datetime="2026-07-21T20:53:10Z")
      # The no-JS fallback stays honest: explicit UTC, not a wrong local guess.
      assert html =~ "2026-07-21 20:53:10 UTC"
    end

    test "the minute and time-only formats drop seconds / date as expected" do
      assert CoreComponents.local_time_tag(~N[2026-07-21 20:53:10], "datetime")
             |> Phoenix.HTML.safe_to_string() =~ "2026-07-21 20:53 UTC"

      assert CoreComponents.local_time_tag(~N[2026-07-21 20:53:10], "time-sec")
             |> Phoenix.HTML.safe_to_string() =~ ">20:53:10 UTC<"

      assert CoreComponents.local_time_tag(~N[2026-07-21 20:53:10], "date")
             |> Phoenix.HTML.safe_to_string() =~ ">2026-07-21<"
    end

    test "nil renders a dash, not a crash" do
      assert CoreComponents.local_time_tag(nil) == "—"
    end
  end
end
