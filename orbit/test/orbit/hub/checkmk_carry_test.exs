defmodule Orbit.Hub.CheckmkCarryTest do
  @moduledoc """
  A Linux agent runs the Checkmk script on its own clock (at most once per
  `interval`, 60 s), not on every push. A push in between carries no
  `checkmk_raw`; the status sections the last run produced must stay, or a
  Linux node read "no CPU, no memory, no disks" on every other push and its
  checks vanished and came back each cycle. Bounded: after three intervals
  without a run the carried values expire, so a broken script still shows.
  """

  use ExUnit.Case, async: true

  alias Orbit.Hub.Cache

  @fixture Path.join([__DIR__, "..", "..", "support", "fixtures", "checkmk_linux.b64"])
           |> Path.expand()
           |> File.read!()
           |> String.trim()

  @t0 ~U[2026-11-12 12:00:00Z]

  defp push(cache, raw, now) do
    {data, cpu} = Cache.expand(cache, 7, %{"checkmk_raw" => raw}, now)
    Cache.ingest(cache, 7, data, now, cpu)
  end

  defp fresh, do: %{"output_gz_b64" => @fixture, "interval" => 60}

  defp status(cache), do: Cache.entry(cache, 7)["status"]

  test "a push without a fresh run keeps the last run's status sections" do
    cache = push(%{}, fresh(), @t0)
    before = status(cache)
    assert before["memory"]["total_mb"] == 1895
    assert before["disks"] != []

    later = push(cache, %{}, DateTime.add(@t0, 30))

    assert status(later)["memory"] == before["memory"]
    assert status(later)["disks"] == before["disks"]
    assert status(later)["interfaces"] == before["interfaces"]
  end

  test "carried interfaces keep their rates instead of reading zero" do
    cache = push(%{}, fresh(), @t0)

    # Rates as a second real run would have computed them.
    cache =
      update_in(cache, [7, "status", "interfaces"], fn ifaces ->
        Enum.map(ifaces, &Map.put(&1, "rx_rate", 123.0))
      end)

    later = push(cache, %{}, DateTime.add(@t0, 30))

    assert Enum.all?(status(later)["interfaces"], &(&1["rx_rate"] == 123.0))
  end

  test "after three intervals without a run the carried values expire" do
    cache = push(%{}, fresh(), @t0)

    stale = push(cache, %{}, DateTime.add(@t0, 181))

    refute Map.has_key?(status(stale), "memory")
  end

  test "a fresh run reports its interval; without one nothing is carried" do
    {data, _cpu} = Cache.expand(%{}, 7, %{"checkmk_raw" => fresh()}, @t0)
    assert data["checkmk_interval"] == 60

    {plain, :unchanged} = Cache.expand(%{}, 7, %{"checkmk_raw" => %{}}, @t0)
    refute Map.has_key?(plain, "memory")
  end
end
