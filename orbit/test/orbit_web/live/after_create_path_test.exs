defmodule OrbitWeb.AfterCreatePathTest do
  @moduledoc """
  Where a freshly created instance lands — the branch that decides whether an
  enroll code is minted at all.

  The flag carries intent, never the code: a secret in a URL survives in
  browser history, proxy logs and referrers, so `enroll=1` must stay a plain
  marker. A polled instance has no agent and must not ask for one.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.InstanceCreateLive

  test "an agent-mode box opens on its agent tab and asks for a code" do
    path = InstanceCreateLive.after_create_path(%Instance{id: 7, transport: "push"})

    assert path == "/instances/7?tab=agent&enroll=1"
  end

  test "a polled box just opens" do
    path = InstanceCreateLive.after_create_path(%Instance{id: 7, transport: "direct"})

    assert path == "/instances/7"
  end

  test "the code itself never rides the url" do
    path = InstanceCreateLive.after_create_path(%Instance{id: 7, transport: "push"})

    refute path =~ "code"
  end
end
