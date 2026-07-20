defmodule Orbit.Securepoint.DiagnoseTest do
  @moduledoc """
  Securepoint IPsec diagnose bundle — the parser half (the SSH half needs a
  box). Shapes are taken from real `swanctl` output.
  """

  use ExUnit.Case, async: true

  alias Orbit.Securepoint.Diagnose

  @plain "Connection config (swanctl --list-conns)"
  @raw "Configured crypto proposals (swanctl --list-conns --raw)"

  test "sections split on the marker and keep their order" do
    out = """
    @@SEC@@#{@plain}
    line one
    line two
    @@SEC@@Peer reachability
    ping 1.2.3.4:
    2 packets transmitted
    """

    assert [first, second] = Diagnose.parse_sections(out)
    assert first["title"] == @plain
    assert first["content"] == "line one\nline two"
    assert second["title"] == "Peer reachability"
    assert second["content"] =~ "2 packets transmitted"
  end

  test "output before the first marker is dropped, not mislabelled" do
    # A login banner or an motd would otherwise become a nameless section.
    assert [%{"title" => "Peer reachability"}] =
             Diagnose.parse_sections("motd noise\n@@SEC@@Peer reachability\nok")
  end

  test "the plain listing is sliced down to the requested tunnel" do
    # swanctl --list-conns has no per-connection filter, so the block comes
    # back whole-box; showing every tunnel in a per-tunnel diagnosis is the
    # bug this slicing prevents.
    content = """
    other-tunnel: IKEv2, no reauthentication
      local:  10.0.0.1
      remote: 10.0.0.2
    bonis-test: IKEv2, rekeying every 7200s
      local:  %any
      remote: %any
      bonis-test: TUNNEL, rekeying every 28260s
        local:  10.21.0.0/22
    third-tunnel: IKEv1
      local:  192.0.2.1
    """

    sliced = Diagnose.slice_plain(content, "bonis-test")

    assert sliced =~ "bonis-test: IKEv2, rekeying every 7200s"
    assert sliced =~ "10.21.0.0/22"
    refute sliced =~ "other-tunnel"
    refute sliced =~ "third-tunnel"
    refute sliced =~ "192.0.2.1"
  end

  test "a missing connection says so instead of showing every tunnel" do
    assert Diagnose.slice_plain("other: IKEv2\n  local: 1.2.3.4", "gone") ==
             "(connection not found)"

    assert Diagnose.slice_raw("other=[...]", "gone") == "(connection not found)"
  end

  test "scope_sections only touches the two whole-box config blocks" do
    sections = [
      %{"title" => @plain, "content" => "wanted: IKEv2\nother: IKEv1"},
      %{"title" => @raw, "content" => "wanted=[proposals]\nother=[proposals]"},
      %{"title" => "Recent IPsec log (charon)", "content" => "untouched log line"}
    ]

    [plain, raw, log] = Diagnose.scope_sections(sections, "wanted")

    assert plain["content"] =~ "wanted: IKEv2"
    refute plain["content"] =~ "other: IKEv1"
    assert raw["content"] == "wanted=[proposals]"
    # Log and SA blocks are already scoped (or deliberately whole) — pass through.
    assert log["content"] == "untouched log line"
  end

  test "the tunnel id is checked before it reaches a shell" do
    # The id lands in a shell command; anything outside strongSwan's legal
    # name charset is refused rather than quoted-and-hoped.
    inst = %Orbit.Instances.Instance{id: 1, device_type: "securepoint"}

    for evil <- ["a; rm -rf /", "$(id)", "`id`", "a b", "a'b"] do
      assert [%{"title" => "Diagnostics unavailable", "content" => content}] =
               Diagnose.run(inst, evil)

      assert content =~ "unsafe tunnel id"
    end
  end

  test "the script names every section the agent bundle names" do
    script = Diagnose.script("t1")

    # Titles must match the agent's so the UI renders one shape per transport.
    assert script =~ @plain
    assert script =~ @raw
    assert script =~ "Live IKE / CHILD SAs"
    assert script =~ "Recent IPsec log (charon)"
    assert script =~ "Peer reachability"
    # Our own vici polling must not drown the log tail.
    assert script =~ "vici client"
  end
end
