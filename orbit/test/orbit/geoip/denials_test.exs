defmodule Orbit.GeoIP.DenialsTest do
  @moduledoc """
  Pure buffer-transition tests (DB-free house style) — the flood-proofing
  contract of DR-G9: the aggregate counts EVERY denial, the event sample is
  hard-capped, fail-open allows land in stats only. The flush/prune DB path
  is proven live against the dev stack.
  """

  use ExUnit.Case, async: true

  alias Orbit.GeoIP.Denials

  @now ~U[2026-07-17 12:00:00Z]

  defp record_n(buffers, n, ip_fn) do
    Enum.reduce(1..n, buffers, fn i, acc ->
      Denials.add_denial(acc, ip_fn.(i), "RU", "/instances", "country_blocked", @now)
    end)
  end

  test "aggregate counts every denial; the event sample is capped at 50" do
    buffers = record_n(Denials.empty_buffers(), 500, &"1.2.3.#{rem(&1, 250)}")

    assert buffers.agg == %{{"country_blocked", "RU"} => 500}
    assert length(buffers.events) == 50
    # deque(maxlen) parity: the NEWEST samples survive a flood.
    assert hd(buffers.events).ip == "1.2.3.#{rem(500, 250)}"
  end

  test "nil country buckets as ?? and nil ip stores as ?" do
    buffers = Denials.add_denial(Denials.empty_buffers(), nil, nil, "/x", "no_country", @now)
    assert buffers.agg == %{{"no_country", "??"} => 1}
    assert [%{ip: "?", country: nil}] = buffers.events
  end

  test "long fields are truncated to their column widths" do
    buffers =
      Denials.add_denial(
        Denials.empty_buffers(),
        String.duplicate("1", 60),
        "DE",
        String.duplicate("/p", 200),
        String.duplicate("r", 40),
        @now
      )

    [e] = buffers.events
    assert String.length(e.ip) == 45
    assert String.length(e.path) == 255
    assert String.length(e.reason) == 32
  end

  test "fail-open allows count in stats only, never as an event row" do
    buffers = Denials.empty_buffers() |> Denials.add_fail_open() |> Denials.add_fail_open()
    assert buffers.agg == %{{"fail_open", "??"} => 2}
    assert buffers.events == []
  end

  describe "blocked_count/0 — the footer badge" do
    test "reads the ETS counter, and answers 0 when the table is absent" do
      # The table is created in init/1, so a plain unit run has none — the
      # footer renders on every page and must never raise because the gate
      # process is not up yet (boot, or a test without the supervisor).
      table = :orbit_geoip_denial_count
      if :ets.whereis(table) != :undefined, do: :ets.delete(table)

      assert Orbit.GeoIP.Denials.blocked_count() == 0

      # With the table present it reports what the gate counted.
      :ets.new(table, [:named_table, :public, :set])
      :ets.insert(table, {:blocked, 0})
      assert Orbit.GeoIP.Denials.blocked_count() == 0

      :ets.update_counter(table, :blocked, 1)
      :ets.update_counter(table, :blocked, 1)
      assert Orbit.GeoIP.Denials.blocked_count() == 2

      :ets.delete(table)
    end
  end
end
