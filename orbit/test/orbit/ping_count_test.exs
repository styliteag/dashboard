defmodule Orbit.PingCountTest do
  @moduledoc """
  The ping count typed into a monitor editor reaches `ping -c` on the box —
  over SSH as a shell string on a Securepoint. Only an integer 1..20 may ever
  get there; anything else falls back to the default 3.
  """
  use ExUnit.Case, async: true

  alias Orbit.Monitors
  alias Orbit.Securepoint.SSH

  describe "Monitors.clamp_ping_count/1" do
    test "integers and integer strings inside 1..20 pass" do
      assert Monitors.clamp_ping_count(1) == 1
      assert Monitors.clamp_ping_count(20) == 20
      assert Monitors.clamp_ping_count("5") == 5
      assert Monitors.clamp_ping_count(" 7 ") == 7
    end

    test "out of range, garbage and shell payloads fall back to 3" do
      for v <- [0, 21, -1, "0", "100", "1;id #", "3 && reboot", "$(id)", nil, "", 2.5, %{}],
          do: assert(Monitors.clamp_ping_count(v) == 3, inspect(v))
    end
  end

  describe "SSH.ping_command/3" do
    test "an integer count is used as is" do
      assert SSH.ping_command(nil, "10.0.0.1", 4) =~ "-c 4 -W 4 10.0.0.1"
    end

    test "a non-integer count never reaches the shell string" do
      cmd = SSH.ping_command(nil, "10.0.0.1", "1;id #")
      refute cmd =~ "id"
      assert cmd =~ "-c 3 "
    end

    test "out-of-range counts are clamped to the default" do
      assert SSH.ping_command(nil, "10.0.0.1", 999) =~ "-c 3 "
      assert SSH.ping_command(nil, "10.0.0.1", 0) =~ "-c 3 "
    end
  end
end
