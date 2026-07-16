defmodule Orbit.Ecto.UtcDateTimeTest do
  use ExUnit.Case, async: true

  alias Orbit.Ecto.UtcDateTime

  test "load tags naive MariaDB datetimes as UTC (incident 195e9da)" do
    naive = ~N[2026-07-17 12:34:56]
    assert {:ok, %DateTime{time_zone: "Etc/UTC"} = dt} = UtcDateTime.load(naive)
    assert DateTime.to_naive(dt) == naive
  end

  test "dump strips the zone from UTC datetimes" do
    dt = ~U[2026-07-17 12:34:56Z]
    assert {:ok, ~N[2026-07-17 12:34:56]} = UtcDateTime.dump(dt)
  end

  test "dump refuses non-UTC datetimes instead of silently shifting" do
    berlin = DateTime.from_naive!(~N[2026-07-17 14:34:56], "Etc/UTC")
    shifted = %{berlin | utc_offset: 7200, time_zone: "Europe/Berlin", zone_abbr: "CEST"}
    assert :error = UtcDateTime.dump(shifted)
  end

  test "cast accepts iso8601 strings with offset" do
    assert {:ok, %DateTime{}} = UtcDateTime.cast("2026-07-17T12:34:56+00:00")
    assert :error = UtcDateTime.cast("not a date")
  end

  test "roundtrip load(dump(dt)) is identity for UTC" do
    dt = ~U[2026-01-02 03:04:05Z]
    {:ok, naive} = UtcDateTime.dump(dt)
    assert {:ok, ^dt} = UtcDateTime.load(naive)
  end
end
