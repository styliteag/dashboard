defmodule Orbit.Securepoint.SwanctlTest do
  @moduledoc """
  Parser parity with the deleted `securepoint/swanctl.py`.

  The fixtures are the ones live-captured from a Securepoint UTM 14.1.6 in
  `backend/tests/test_securepoint_swanctl.py`. The SAS fixture deliberately
  contains the established SA *and* a passive `%any` half-open responder SA
  under the same connection name — the case that collapses into a Frankenstein
  record (CREATED/%any host, zeroed responder SPI, yet INSTALLED children)
  when colliding sections are merged instead of kept apart.
  """
  use ExUnit.Case, async: true

  alias Orbit.Securepoint.Swanctl, as: S

  @sas_raw """
  list-sa event {site-a {uniqueid=3 version=2 state=ESTABLISHED \
  local-host=203.0.113.10 local-port=4500 local-id=fw1-vpn.example.net \
  remote-host=203.0.113.20 remote-port=56069 remote-id=peer.example.test initiator=yes \
  initiator-spi=0731875234fa6144 responder-spi=0f1186ba1485124f nat-remote=yes \
  encr-alg=AES_CBC encr-keysize=256 established=556 rekey-time=6187 child-sas \
  {site-a-7 {name=site-a uniqueid=7 reqid=2 state=INSTALLED mode=TUNNEL \
  protocol=ESP spi-in=c8d53263 spi-out=cd2f7951 bytes-in=0 packets-in=0 bytes-out=0 \
  packets-out=0 local-ts=[10.21.0.0/22] remote-ts=[10.99.1.0/24]} \
  site-a-8 {name=site-a uniqueid=8 reqid=1 state=INSTALLED mode=TUNNEL \
  protocol=ESP spi-in=cc619d6b spi-out=ccda13c7 bytes-in=146580 packets-in=1745 \
  bytes-out=80976 packets-out=964 local-ts=[10.21.0.0/22] remote-ts=[10.1.1.0/24]}}}}
  list-sa event {site-a {uniqueid=1 version=2 state=CREATED local-host=%any \
  local-port=500 local-id=%any remote-host=%any remote-port=500 remote-id=%any \
  initiator=yes initiator-spi=ca3f9bef87c9c0d6 responder-spi=0000000000000000 \
  child-sas {}}}
  list-sas reply {}
  """

  @conns_raw """
  list-conn event {site-a {local_addrs=[%any] remote_addrs=[%any] version=IKEv2 \
  rekey_time=7200 children {site-a {mode=TUNNEL local-ts=[10.21.0.0/22] \
  remote-ts=[10.1.1.0/24 10.99.1.0/24]}}}}
  list-conns reply {}
  """

  describe "the half-open collision" do
    test "drops the %any responder instead of merging it over the live SA" do
      assert [t] = S.parse_ipsec(@sas_raw, @conns_raw)

      assert t["id"] == "site-a"
      assert t["status"] == "ESTABLISHED"
      # NOT clobbered to %any by the CREATED envelope.
      assert t["local"] == "203.0.113.10"
      assert t["remote"] == "203.0.113.20"
    end

    test "keeps the IKE cookie pair — the NAT-proof key for pairing tunnel ends" do
      [t] = S.parse_ipsec(@sas_raw, @conns_raw)

      assert t["ike_init_spi"] == "0731875234fa6144"
      assert t["ike_resp_spi"] == "0f1186ba1485124f"
      refute t["ike_resp_spi"] == "0000000000000000"
    end
  end

  test "counts and sums the phase-2 children" do
    [t] = S.parse_ipsec(@sas_raw, @conns_raw)

    assert {t["phase2_up"], t["phase2_total"]} == {2, 2}
    assert t["bytes_in"] == 146_580
    assert t["bytes_out"] == 80_976
    assert t["seconds_established"] == 556
    assert t["unique_id"] == "3"
  end

  test "carries the ESP SPIs per child (A.spi_out == B.spi_in across ends)" do
    [t] = S.parse_ipsec(@sas_raw, @conns_raw)
    by_remote = Map.new(t["children"], &{&1["remote_ts"], &1})

    assert by_remote["10.1.1.0/24"]["spi_in"] == "cc619d6b"
    assert by_remote["10.1.1.0/24"]["spi_out"] == "ccda13c7"
    assert by_remote["10.99.1.0/24"]["spi_in"] == "c8d53263"
    assert Enum.all?(t["children"], &(&1["state"] == "INSTALLED"))
  end

  test "empty input yields no tunnels" do
    assert S.parse_ipsec("", "") == []
    assert S.parse_ipsec("list-sas reply {}\n", "list-conns reply {}\n") == []
  end

  describe "unescape_conn_name/1" do
    test "decodes the space escape" do
      assert S.unescape_conn_name("Broken$20Connection") == "Broken Connection"
      assert S.unescape_conn_name("Vendor$20Tunnel$20IKEv2") == "Vendor Tunnel IKEv2"
      assert S.unescape_conn_name("KC$20RM$20OPNSE") == "KC RM OPNSE"
    end

    test "passes an unescaped name through" do
      assert S.unescape_conn_name("site-a") == "site-a"
      assert S.unescape_conn_name("TI") == "TI"
      assert S.unescape_conn_name("") == ""
    end

    test "reassembles a multi-byte UTF-8 escape instead of splitting it" do
      assert S.unescape_conn_name("M$C3$BCller$20VPN") == "Müller VPN"
    end

    test "leaves non-hex and partial escapes literal" do
      assert S.unescape_conn_name("cost$ZZplan") == "cost$ZZplan"
      assert S.unescape_conn_name("trailing$2") == "trailing$2"
      assert S.unescape_conn_name("bare$") == "bare$"
    end
  end

  test "the tunnel id stays raw while the description is decoded" do
    conns =
      "list-conn event {Broken$20Connection {local_addrs=[%any] remote_addrs=[1.2.3.4] " <>
        "children {c1 {mode=TUNNEL local-ts=[10.0.0.0/24] remote-ts=[10.1.0.0/24]}}}}"

    assert [t] = S.parse_ipsec("", conns)
    # raw — `swanctl --ike` and the diagnose slicing need it verbatim
    assert t["id"] == "Broken$20Connection"
    # decoded — what the UI shows
    assert t["description"] == "Broken Connection"
    assert t["status"] == "down"
  end

  test "policy shunts (PASS/DROP children) are not tunnels" do
    conns =
      "list-conn event {shunt-a {local_addrs=[%any] remote_addrs=[%any] " <>
        "children {c1 {mode=PASS local-ts=[10.0.0.0/8] remote-ts=[10.0.0.0/8]}}}}"

    assert S.parse_ipsec("", conns) == []
  end

  test "status/3 wraps the tunnels in the agent's section shape" do
    assert %{"running" => true, "tunnels" => [_]} = S.status(@sas_raw, @conns_raw, true)
    assert %{"running" => false} = S.status("", "", false)
  end
end
