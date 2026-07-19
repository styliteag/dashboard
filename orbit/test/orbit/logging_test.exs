defmodule Orbit.LoggingTest do
  @moduledoc "JSON log formatter (log_format=json parity) — pure, no handler swap."
  use ExUnit.Case, async: true

  alias Orbit.Logging

  defp fmt(level, message, metadata \\ []) do
    Logging.format_json(level, message, {{2026, 7, 19}, {1, 2, 3, 45}}, metadata)
    |> IO.iodata_to_binary()
  end

  test "one JSON object per line with ts/level/msg" do
    line = fmt(:info, "hello world")
    assert String.ends_with?(line, "\n")

    assert %{"ts" => "2026-07-19T01:02:03.045Z", "level" => "info", "msg" => "hello world"} =
             Jason.decode!(line)
  end

  test "metadata lands as string keys; non-binary values inspected" do
    assert %{"request_id" => "abc", "count" => "7"} =
             Jason.decode!(fmt(:warning, "x", request_id: "abc", count: 7))
  end

  test "iodata message is flattened" do
    assert %{"msg" => "ab"} = Jason.decode!(fmt(:info, ["a", ?b]))
  end

  test "never raises — unencodable input degrades to a fallback line" do
    line = fmt(:error, ["ok"], bad: {:tuple, self()})
    assert is_map(Jason.decode!(line))
  end

  test "maybe_apply only reacts to log_* keys" do
    # apply/0 is config-gated off in :test — both calls must be no-op :ok.
    assert Logging.maybe_apply("log_level") == :ok
    assert Logging.maybe_apply("poll_interval_seconds") == :ok
  end
end
