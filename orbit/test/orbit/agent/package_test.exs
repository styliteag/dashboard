defmodule Orbit.Agent.PackageTest do
  @moduledoc "Version parse + params shape (real agent files exercised by the live E2E)."
  # async: false — the tests mutate the global AGENT_DIR env; parallel runs would race.
  use ExUnit.Case, async: false

  alias Orbit.Agent.Package

  setup do
    # A throwaway AGENT_DIR with a fake agent script + sig, so the unit test
    # doesn't depend on the mounted real agent.
    dir = Path.join(System.tmp_dir!(), "orbit-agent-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    File.write!(
      Path.join(dir, "orbit_agent.py"),
      ~s(#!/usr/bin/env python3\n__version__ = "9.9.9"\n)
    )

    File.write!(Path.join(dir, "orbit_agent.py.sig"), "  ZmFrZS1zaWc=  \n")
    prev = System.get_env("AGENT_DIR")
    System.put_env("AGENT_DIR", dir)

    on_exit(fn ->
      if prev, do: System.put_env("AGENT_DIR", prev), else: System.delete_env("AGENT_DIR")
      File.rm_rf!(dir)
    end)

    %{dir: dir}
  end

  test "served_version parses __version__" do
    assert Package.served_version() == "9.9.9"
  end

  test "update_params has version, hex sha256, base64 code, trimmed signature" do
    assert {:ok, params} = Package.update_params()
    assert params["version"] == "9.9.9"
    assert params["sha256"] =~ ~r/^[0-9a-f]{64}$/
    assert Base.decode64!(params["code"]) =~ "__version__"
    assert params["signature"] == "ZmFrZS1zaWc="
  end

  test "missing signature file yields an empty signature, not a crash", %{dir: dir} do
    File.rm!(Path.join(dir, "orbit_agent.py.sig"))
    assert {:ok, %{"signature" => ""}} = Package.update_params()
  end

  test "missing script is reported, not raised", %{dir: dir} do
    File.rm!(Path.join(dir, "orbit_agent.py"))
    assert {:error, :unavailable} = Package.update_params()
    assert Package.served_version() == nil
  end
end
