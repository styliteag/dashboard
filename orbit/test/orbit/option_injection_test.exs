defmodule Orbit.OptionInjectionTest do
  @moduledoc """
  Server-side half of the option-injection hotfix (agent half:
  agent/tests/test_option_injection.py).

  Monitor sources/destinations and capture interfaces/filters are typed by
  operators and end up in the argv of `ping` / `tcpdump`, run as root on the
  box (agent) or over SSH (Securepoint). A value with a leading `-` becomes
  an OPTION there — `-f` (flood ping), tcpdump `-w file … -z cmd` (write a
  file, run a post-rotate command). Refused at the dashboard before anything
  is stored or sent, so an old agent is protected as well.
  """
  use ExUnit.Case, async: true

  alias Orbit.Capture.Params
  alias Orbit.Monitors
  alias Orbit.Net
  alias Orbit.Securepoint.SSH

  describe "Net.host_arg?/1" do
    test "IP literals and plain names pass" do
      for v <- ["10.1.1.5", "2001:db8::1", "::1", "fw.example.com", "host-1_a"],
          do: assert(Net.host_arg?(v), v)
    end

    test "option-like and shell-ish values are refused" do
      for v <- ["-f", "-oProxyCommand=x", "10.0.0.1 -f", "a;b", "$(id)", "", nil, 42],
          do: refute(Net.host_arg?(v), inspect(v))
    end
  end

  describe "monitors refuse option-like targets before touching the DB" do
    test "connectivity create/update: destination and source" do
      assert {:error, msg} =
               Monitors.create_connectivity(1, %{"name" => "x", "destination" => "-f"})

      assert msg =~ "destination"

      assert {:error, msg} =
               Monitors.update_connectivity(1, 2, %{
                 "name" => "x",
                 "destination" => "10.0.0.1",
                 "source" => "-I"
               })

      assert msg =~ "source"
    end

    test "ipsec create/update" do
      assert {:error, _} =
               Monitors.create_ipsec(1, %{"child_name" => "c", "destination" => "-s65000"})

      assert {:error, _} =
               Monitors.update_ipsec(1, 2, %{"destination" => "10.0.0.1", "source" => "-f"})
    end

    test "ping test refuses before reaching any box" do
      inst = %Orbit.Instances.Instance{id: 1, transport: "push"}
      assert {:error, msg} = Monitors.ping_test(inst, "", "-f", 3)
      assert msg =~ "destination"
    end
  end

  describe "Securepoint SSH shell_arg/1" do
    test "a leading '-' is refused like any other unsafe value" do
      assert SSH.shell_arg("10.0.0.1") == "10.0.0.1"
      assert SSH.shell_arg("fw.example") == "fw.example"
      # "--" is the existing refusal sentinel: ping then has no target and
      # fails as a misconfiguration instead of taking an option.
      assert SSH.shell_arg("-f") == "--"
      assert SSH.shell_arg("-s65000") == "--"
      assert SSH.shell_arg("a;b") == "--"
    end
  end

  describe "Capture.Params.validate/2" do
    test "plain interface and ordinary BPF filters pass" do
      assert :ok = Params.validate("em0", "host 10.0.0.1 and port 443")
      assert :ok = Params.validate("vlan0.100", "")
      assert :ok = Params.validate("", "(tcp) and not port 22")
    end

    test "a filter starting with '-' is refused" do
      assert {:error, msg} = Params.validate("em0", "-w /tmp/x -C 1 -z /bin/sh")
      assert msg =~ "filter"
      assert {:error, _} = Params.validate("em0", "  -z sh")
    end

    test "an option-like interface is refused" do
      assert {:error, msg} = Params.validate("-zsh", "")
      assert msg =~ "interface"
      assert {:error, _} = Params.validate("em0 -w x", "")
    end
  end
end
