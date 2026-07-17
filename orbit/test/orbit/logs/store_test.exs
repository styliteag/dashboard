defmodule Orbit.Logs.StoreTest do
  @moduledoc "Pure retention/sanitize helpers (DB path verified live — test DB is schemaless)."
  use ExUnit.Case, async: true

  alias Orbit.Logs.Store

  test "clamp keeps only the last max chars" do
    assert Store.clamp("abcdef", 4) == "cdef"
    assert Store.clamp("abc", 4) == "abc"
  end

  test "sanitize drops empty name/content, trims + caps name, clamps content" do
    raw = [
      %{"name" => "  system.log  ", "content" => "line"},
      %{"name" => "", "content" => "x"},
      %{"name" => "no-content", "content" => ""},
      %{"name" => String.duplicate("a", 80), "content" => "y"}
    ]

    result = Store.sanitize(raw)
    assert {"system.log", "line"} in result
    assert length(result) == 2
    {long_name, _} = Enum.find(result, fn {n, _} -> String.starts_with?(n, "a") end)
    assert String.length(long_name) == 64
  end

  test "surplus returns ids beyond the keep window (newest-first input)" do
    assert Store.surplus([9, 8, 7, 6, 5]) == [6, 5]
    assert Store.surplus([3, 2]) == []
    assert Store.keep_per_name() == 3
  end
end
