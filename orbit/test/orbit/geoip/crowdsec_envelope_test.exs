defmodule Orbit.GeoIP.CrowdsecEnvelopeTest do
  @moduledoc """
  The LAPI stream body is foreign input. A malformed envelope (new/deleted
  not lists, entries not maps, values not strings) must be skipped — a crash
  here would take down the GenServer that owns the ban table, i.e. drop
  every ban.
  """
  use ExUnit.Case, async: true

  alias Orbit.GeoIP.Crowdsec

  setup do
    {:ok, t: :ets.new(:crowdsec_env_test, [:public, :set])}
  end

  test "non-list deltas are ignored", %{t: t} do
    assert :ok = Crowdsec.apply_decisions(t, %{"value" => "203.0.113.7"}, "junk")
    assert :ets.tab2list(t) == []
  end

  test "non-map entries are skipped, good ones applied", %{t: t} do
    assert :ok =
             Crowdsec.apply_decisions(
               t,
               [1, "x", nil, %{"value" => %{}}, %{"value" => "203.0.113.7"}],
               []
             )

    assert length(:ets.tab2list(t)) == 1
  end
end
