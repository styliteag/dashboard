defmodule OrbitWeb.S4InputTest do
  @moduledoc """
  Small input hardenings: GUI-proxy method allow-list (no atom per request
  method), handoff `next` path and agent-supplied cookie names/values, shell
  resize bounds, the raw-logfile Content-Disposition filename, and the
  agent hello's version/sha strings.
  """
  use ExUnit.Case, async: true

  test "GUI proxy: only standard methods map to an atom" do
    assert OrbitWeb.GuiProxy.method_atom("GET") == :get
    assert OrbitWeb.GuiProxy.method_atom("PATCH") == :patch
    assert OrbitWeb.GuiProxy.method_atom("XYZ123") == nil
    assert OrbitWeb.GuiProxy.method_atom("PROPFIND") == nil
  end

  test "safe_next: control characters, tab and backslash anywhere collapse to /" do
    for bad <- ["/\t/evil.example", "/\\evil.example", "/a\r\nSet-Cookie: x", "/%0a", "/\u0000x"] do
      assert Orbit.GUI.safe_next(bad) == "/", inspect(bad)
    end

    assert Orbit.GUI.safe_next("/ui/firewall?x=1") == "/ui/firewall?x=1"
  end

  test "agent-supplied cookies: only token names and safe values" do
    assert Orbit.GUI.safe_cookie?({"PHPSESSID", "abc123"})
    refute Orbit.GUI.safe_cookie?({"a b", "x"})
    refute Orbit.GUI.safe_cookie?({"a;b", "x"})
    refute Orbit.GUI.safe_cookie?({"PHPSESSID", "x; Domain=evil"})
    refute Orbit.GUI.safe_cookie?({"PHPSESSID", "x\r\nSet-Cookie: y"})
    refute Orbit.GUI.safe_cookie?({nil, "x"})
  end

  test "shell resize: integers 1..1000 only" do
    assert OrbitWeb.ShellSocket.resize_dims(40, 120) == {:ok, 40, 120}

    for {r, c} <- [{0, 80}, {40, 1001}, {"40", 80}, {-1, 80}, {40.5, 80}],
        do: assert(OrbitWeb.ShellSocket.resize_dims(r, c) == :error)
  end

  test "logfile download filename is sanitised" do
    assert OrbitWeb.LogsController.disposition_name("system.log") == "system.log"
    assert OrbitWeb.LogsController.disposition_name("a\"; x=\"y\r\n") == "a___x__y__"
    assert OrbitWeb.LogsController.disposition_name("") == "log.txt"
  end

  test "agent hello: version and sha strings are format-checked" do
    assert OrbitWeb.AgentSocket.hello_field(:version, "4.8.0") == "4.8.0"
    assert OrbitWeb.AgentSocket.hello_field(:version, "4.8.0\n<script>") == nil
    assert OrbitWeb.AgentSocket.hello_field(:version, %{}) == nil
    sha = String.duplicate("a", 64)
    assert OrbitWeb.AgentSocket.hello_field(:sha256, sha) == sha
    assert OrbitWeb.AgentSocket.hello_field(:sha256, "zz") == nil
  end
end
