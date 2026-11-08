defmodule Orbit.MonitorsInputTest do
  @moduledoc """
  Phase-2 monitor keys (tunnel id, child name, traffic selectors) come from
  DOM attributes of the monitor dialog. They are refused before any DB write
  when they are not strings, too long for their column, or carry control
  characters.
  """
  use ExUnit.Case, async: true

  alias Orbit.Monitors

  defp attrs(over),
    do:
      Map.merge(
        %{
          "tunnel_id" => "con1",
          "child_name" => "con1-child",
          "local_ts" => "10.0.0.0/24",
          "remote_ts" => "10.1.0.0/24",
          "destination" => "10.1.0.1"
        },
        over
      )

  test "an overlong child name is refused" do
    assert {:error, msg} =
             Monitors.create_ipsec(1, attrs(%{"child_name" => String.duplicate("a", 129)}))

    assert msg =~ "child"
  end

  test "control characters in a traffic selector are refused" do
    assert {:error, msg} = Monitors.create_ipsec(1, attrs(%{"remote_ts" => "10.1.0.0/24\n"}))
    assert msg =~ "selector"
  end

  test "a non-string tunnel id is refused" do
    assert {:error, msg} = Monitors.create_ipsec(1, attrs(%{"tunnel_id" => %{"x" => 1}}))
    assert msg =~ "tunnel"
  end

  test "validate_targets/2 is public for callers that bypass create/update" do
    assert :ok = Monitors.validate_targets(%{"source" => "10.0.0.1"}, "10.1.0.1")
    assert {:error, _} = Monitors.validate_targets(%{"source" => ""}, "-f")
  end
end
