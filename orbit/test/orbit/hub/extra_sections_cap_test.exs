defmodule Orbit.Hub.ExtraSectionsCapTest do
  @moduledoc """
  Vendor `x_*` sections are stored verbatim in the hub cache (and persisted
  in status_snapshot). An agent must not grow that without bound: at most
  16 distinct x_ sections per instance, each at most 1 MB (external term
  size). Over-cap keys/values are dropped, known ones keep updating.
  WebSocket upgrades carry a max_frame_size.
  """
  use ExUnit.Case, async: true

  alias Orbit.Hub.Cache

  @now ~U[2026-11-08 12:00:00Z]

  test "no more than 16 distinct x_ sections are kept" do
    data = Map.new(1..40, fn i -> {"x_s#{i}", %{"v" => i}} end)
    entry = Cache.ingest(%{}, 1, data, @now) |> Cache.entry(1)
    assert entry |> Map.keys() |> Enum.count(&String.starts_with?(&1, "x_")) == 16
  end

  test "known sections keep updating once the cap is reached" do
    first = Map.new(1..16, fn i -> {"x_s#{i}", %{"v" => 0}} end)
    cache = Cache.ingest(%{}, 1, first, @now)
    cache = Cache.ingest(cache, 1, %{"x_s1" => %{"v" => 1}, "x_new" => %{"v" => 1}}, @now)
    entry = Cache.entry(cache, 1)
    assert entry["x_s1"] == %{"v" => 1}
    refute Map.has_key?(entry, "x_new")
  end

  test "an oversized section is dropped" do
    big = %{"blob" => String.duplicate("a", 2_000_000)}
    entry = Cache.ingest(%{}, 1, %{"x_big" => big, "x_ok" => %{"a" => 1}}, @now) |> Cache.entry(1)
    refute Map.has_key?(entry, "x_big")
    assert entry["x_ok"] == %{"a" => 1}
  end

  test "websocket upgrades set max_frame_size" do
    for mod <- [
          OrbitWeb.AgentWSController,
          OrbitWeb.ShellWSController,
          OrbitWeb.CaptureWSController
        ] do
      assert is_integer(mod.ws_options()[:max_frame_size]), inspect(mod)
    end
  end
end
