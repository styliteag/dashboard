"""Tests for platform detection and the OPNsense/pfSense collector dispatch."""

from __future__ import annotations

import orbit_agent as agent
import pytest


class FakePath:
    """Minimal pathlib.Path stand-in driven by a class-level registry."""

    registry: dict[str, str | None] = {}

    def __init__(self, p: object) -> None:
        self._p = str(p)

    def exists(self) -> bool:
        return self._p in FakePath.registry

    def read_text(self, *args: object, **kwargs: object) -> str:
        content = FakePath.registry.get(self._p)
        if content is None:
            raise OSError(f"no such file: {self._p}")
        return content


@pytest.fixture
def fake_fs(monkeypatch: pytest.MonkeyPatch):
    FakePath.registry = {}
    monkeypatch.setattr(agent, "Path", FakePath)
    return FakePath.registry


def test_detect_opnsense(fake_fs: dict) -> None:
    fake_fs["/usr/local/opnsense/version/core"] = "25.7\n"
    assert agent.detect_platform() == "opnsense"


def test_detect_pfsense_via_platform_marker(fake_fs: dict) -> None:
    fake_fs["/etc/platform"] = "pfSense\n"
    assert agent.detect_platform() == "pfsense"


def test_detect_pfsense_via_upgrade_binary(fake_fs: dict) -> None:
    fake_fs["/usr/local/sbin/pfSense-upgrade"] = "binary"
    assert agent.detect_platform() == "pfsense"


def test_detect_unknown(fake_fs: dict) -> None:
    assert agent.detect_platform() == "unknown"


def test_read_pfsense_version(fake_fs: dict) -> None:
    fake_fs["/etc/version"] = "26.03-RELEASE\n"
    assert agent._read_pfsense_version() == "26.03-RELEASE"


# Real /usr/local/opnsense/version/core format: a pretty-printed JSON object.
# Taking line 0 yields "{" — the bug this guards against.
_OPN_CORE_JSON = (
    "{\n"
    '    "product_abi": "25.7",\n'
    '    "product_arch": "amd64",\n'
    '    "product_id": "opnsense",\n'
    '    "product_name": "OPNsense",\n'
    '    "product_version": "25.7.11_9"\n'
    "}\n"
)


def test_read_opnsense_version_parses_json(fake_fs: dict) -> None:
    fake_fs["/usr/local/opnsense/version/core"] = _OPN_CORE_JSON
    assert agent._read_opnsense_version() == "25.7.11_9"


def test_read_opnsense_version_legacy_plaintext(fake_fs: dict) -> None:
    # Older builds stored a bare version string — still supported.
    fake_fs["/usr/local/opnsense/version/core"] = "25.7.11_9\n"
    assert agent._read_opnsense_version() == "25.7.11_9"


def test_read_opnsense_version_falls_through_empty_product_version(fake_fs: dict) -> None:
    # core has empty product_version → fall through to opnsense file.
    fake_fs["/usr/local/opnsense/version/core"] = '{"product_version": ""}'
    fake_fs["/usr/local/opnsense/version/opnsense"] = '{"product_version": "25.7.11_9"}'
    assert agent._read_opnsense_version() == "25.7.11_9"


def test_collect_firmware_pfsense_reads_version(
    fake_fs: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    # Pretend a check ran recently so the version-only path is taken (no subprocess).
    monkeypatch.setattr(agent, "_last_fw_check_ts", agent.time.monotonic())
    fake_fs["/etc/version"] = "26.03-RELEASE\n"
    assert agent.collect_firmware() == {"product_version": "26.03-RELEASE"}


def test_pfsense_update_detection() -> None:
    # Confirmed negative sample from pfSense Plus 26.03.
    assert agent._pfsense_update_available("Messages:\nYour system is up to date") is False
    assert agent._pfsense_update_available("The following packages will be upgraded") is True
    assert agent._pfsense_update_available("") is False  # unknown/error → no false alarm


# Real return_gateways_status() sample captured on pfSense Plus 26.03.
_PF_GW_JSON = (
    '{"PPPOE_WAN":{"monitorip":"62.156.244.38","srcip":"87.191.183.135","name":"PPPOE_WAN",'
    '"delay":"0ms","stddev":"0ms","loss":"100%","status":"down","substatus":"highloss"},'
    '"IPSec_GW":{"monitorip":"10.10.80.254","srcip":"10.10.80.254","name":"IPSec_GW",'
    '"delay":"","loss":"","status":"online","substatus":"none","monitor_disable":true}}'
)


def test_collect_gateways_pfsense_parses_php_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: _PF_GW_JSON)
    gws = agent.collect_gateways()
    assert {g["name"] for g in gws} == {"PPPOE_WAN", "IPSec_GW"}
    pppoe = next(g for g in gws if g["name"] == "PPPOE_WAN")
    assert pppoe["address"] == "62.156.244.38"
    assert pppoe["status"] == "down"
    assert pppoe["loss"] == "100%"
    ipsec = next(g for g in gws if g["name"] == "IPSec_GW")
    assert ipsec["status"] == "online"
    assert ipsec["stddev"] == ""  # missing key → empty string, no KeyError


def test_collect_gateways_pfsense_handles_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "PHP Warning: something\n")
    assert agent.collect_gateways() == []


# Verbatim `swanctl --list-sas --raw` captured on a production OPNsense box
# (2026-06-24, box 10.21.7.100). Note the `list-sa event { … }` envelope +
# `list-sas reply {}` trailer + the leading config warning — the parser must see
# through all of it. The active SA is keyed by a connection UUID (5fe62ba0…) and
# phase-1 state is ESTABLISHED while the child-sas is INSTALLED.
_SWANCTL_SAS = (
    "no files found matching '/usr/local/etc/strongswan.opnsense.d/*.conf'\n"
    "list-sa event {5fe62ba0-5099-4510-91c7-b2d4e868b39b {uniqueid=1 version=2 "
    "state=ESTABLISHED local-host=10.21.7.100 local-port=4500 local-id=10.21.7.100 "
    "remote-host=10.21.7.101 remote-port=4500 remote-id=10.21.7.101 initiator=yes "
    "initiator-spi=f5b966b91adb2c0b responder-spi=1b43a005a4e044e0 encr-alg=AES_CBC "
    "encr-keysize=128 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 "
    "dh-group=ECP_256 established=1235 rekey-time=12815 "
    "child-sas {4778be38-7a28-4e84-9e4e-59f988737044-1 "
    "{name=4778be38-7a28-4e84-9e4e-59f988737044 uniqueid=1 reqid=1 state=INSTALLED "
    "mode=TUNNEL protocol=ESP spi-in=caf6619d spi-out=cc660f24 encr-alg=AES_GCM_16 "
    "encr-keysize=128 bytes-in=0 packets-in=0 bytes-out=0 packets-out=0 "
    "rekey-time=2013 life-time=2725 install-time=1235 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}}\n"
    "list-sas reply {}"
)

# Verbatim `swanctl --list-conns --raw` (same family of boxes). The configured
# connection is keyed by its UUID (34595782…) which differs from the active SA's
# name above — OPNsense regenerates connection UUIDs on every config apply. Heavily
# nested (proposals/esp_proposals/children) to exercise the brace tokenizer.
_SWANCTL_CONNS = (
    "no files found matching '/usr/local/etc/strongswan.opnsense.d/*.conf'\n"
    "list-conn event {34595782-ae4a-41b8-8722-2d52eb487475 "
    "{local_addrs=[10.21.7.100] remote_addrs=[10.21.7.101] local_port=500 remote_port=500 "
    "version=IKEv2 reauth_time=0 rekey_time=14400 unique=UNIQUE_NO "
    "proposals {0 {encr=[AES_CBC_128 AES_CBC_192] integ=[HMAC_SHA2_256_128] "
    "prf=[PRF_HMAC_SHA2_256] ke=[ECP_256 CURVE_25519]}} dpd_delay=10 "
    "local-1 {id=10.21.7.100 class=pre-shared key groups=[] certs=[] cacerts=[]} "
    "remote-1 {id=10.21.7.101 class=pre-shared key groups=[] certs=[] cacerts=[]} "
    "children {0d68b529-eeca-4db4-9e17-5d6a008f9164 "
    "{mode=TUNNEL rekey_time=3600 dpd_action=none close_action=none "
    "esp_proposals {0 {encr=[AES_GCM_16_128] ke=[ECP_256]}} ah_proposals {} "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}}\n"
    "list-conns reply {}"
)


def test_parse_swanctl_sas_single_record() -> None:
    # The `list-sa event` envelope + `list-sas reply` trailer must NOT become rows.
    sas = agent._parse_swanctl_sas(_SWANCTL_SAS)
    assert len(sas) == 1
    s = sas[0]
    assert s["name"] == "5fe62ba0-5099-4510-91c7-b2d4e868b39b"
    assert s["remote"] == "10.21.7.101"
    assert s["local"] == "10.21.7.100"
    assert s["unique_id"] == "1"  # stable handle for --terminate --ike-id


def test_parse_swanctl_sas_status_is_ike_level() -> None:
    # Regression: the child SA is INSTALLED, but the status must be the IKE-level
    # ESTABLISHED so the frontend paints it up / offers Disconnect.
    assert agent._parse_swanctl_sas(_SWANCTL_SAS)[0]["status"] == "ESTABLISHED"


def test_parse_swanctl_sas_no_raw_blob_in_name() -> None:
    # The original bug: a greedy regex put the whole raw dump into the id field.
    s = agent._parse_swanctl_sas(_SWANCTL_SAS)[0]
    assert "version=" not in s["name"]
    assert "state=" not in s["name"]
    assert len(s["name"]) < 60


def test_parse_swanctl_sas_uptime_and_phase2_count() -> None:
    # Phase-1 uptime comes from the IKE-level `established=1235` (seconds);
    # phase-2 is counted across the nested child SAs (one INSTALLED here).
    s = agent._parse_swanctl_sas(_SWANCTL_SAS)[0]
    assert s["seconds_established"] == 1235
    assert s["phase2_up"] == 1
    assert s["phase2_total"] == 1


def test_parse_swanctl_sas_counts_multiple_children() -> None:
    # Two children, one down → "1/2 up".
    raw = (
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "established=42 child-sas {a-1 {state=INSTALLED bytes-in=1 bytes-out=2} "
        "a-2 {state=REKEYING bytes-in=0 bytes-out=0}}}"
    )
    s = agent._parse_swanctl_sas(raw)[0]
    assert s["phase2_up"] == 1
    assert s["phase2_total"] == 2


def test_parse_swanctl_conns_counts_phase2() -> None:
    # The configured connection contributes the "n" (one child in the fixture).
    assert agent._parse_swanctl_conns(_SWANCTL_CONNS)[0]["phase2_total"] == 1


def test_tunnel_carries_uptime_and_phase2() -> None:
    # The merged dashboard row must surface the new fields when an SA is present
    # and zero them for a configured-but-down tunnel.
    sa = agent._parse_swanctl_sas(_SWANCTL_SAS)[0]
    up = agent._tunnel("conn", None, sa, {})
    assert up["seconds_established"] == 1235
    assert up["phase2_up"] == 1
    assert up["phase2_total"] == 1  # falls back to live child count when no conn
    # the configured conn count ("n") is preferred over the live SA count
    preferred = agent._tunnel("conn", {"phase2_total": 2}, sa, {})
    assert preferred["phase2_up"] == 1
    assert preferred["phase2_total"] == 2
    down = agent._tunnel("conn", {"local": "", "remote": "", "phase2_total": 2}, None, {})
    assert down["seconds_established"] == 0
    assert down["phase2_up"] == 0
    assert down["phase2_total"] == 2


def test_parse_swanctl_sas_sums_child_bytes() -> None:
    raw = (
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "child-sas {a-1 {state=INSTALLED bytes-in=10 bytes-out=20} "
        "a-2 {state=INSTALLED bytes-in=5 bytes-out=7}}}"
    )
    s = agent._parse_swanctl_sas(raw)[0]
    assert s["bytes_in"] == 15
    assert s["bytes_out"] == 27


def test_parse_swanctl_sas_ike_without_child() -> None:
    # Connecting tunnel with no child-sas yet: status from IKE, zero bytes.
    s = agent._parse_swanctl_sas("conn-x {uniqueid=3 state=CONNECTING remote-host=3.3.3.3}")[0]
    assert s["status"] == "CONNECTING"
    assert s["bytes_in"] == 0


def test_parse_swanctl_sas_empty() -> None:
    assert agent._parse_swanctl_sas("") == []
    assert agent._parse_swanctl_sas("   \n  ") == []


def test_parse_swanctl_conns_single_record() -> None:
    # Envelope + deep nesting (proposals/children) must not spawn extra records,
    # and addr lists must parse despite the glued `local_addrs=[…]`.
    conns = agent._parse_swanctl_conns(_SWANCTL_CONNS)
    assert len(conns) == 1
    c = conns[0]
    assert c["name"] == "34595782-ae4a-41b8-8722-2d52eb487475"
    assert c["local"] == "10.21.7.100"
    assert c["remote"] == "10.21.7.101"


def test_parse_swanctl_conns_empty() -> None:
    assert agent._parse_swanctl_conns("") == []


def test_merge_ipsec_matches_by_name() -> None:
    conns = [{"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1"}]
    sas = [{"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1",
            "status": "ESTABLISHED", "bytes_in": 4, "bytes_out": 8, "unique_id": "7"}]
    tunnels = agent._merge_ipsec(conns, sas, {})
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t["id"] == "c1"
    assert t["status"] == "ESTABLISHED"
    assert t["unique_id"] == "7"
    assert t["bytes_in"] == 4


def test_merge_ipsec_matches_by_endpoint_when_names_differ() -> None:
    # The SA name drifted from the configured name; endpoints still match.
    conns = [{"name": "cfg-uuid", "local": "10.21.7.100", "remote": "10.21.7.101"}]
    sas = [{"name": "sa-uuid", "local": "10.21.7.100", "remote": "10.21.7.101",
            "status": "ESTABLISHED", "bytes_in": 0, "bytes_out": 0, "unique_id": "1"}]
    tunnels = agent._merge_ipsec(conns, sas, {})
    assert len(tunnels) == 1  # not two — the orphan SA was matched by endpoint
    assert tunnels[0]["id"] == "cfg-uuid"  # connect uses the configured name
    assert tunnels[0]["unique_id"] == "1"
    assert tunnels[0]["status"] == "ESTABLISHED"


def test_merge_ipsec_unmatched_conn_is_down() -> None:
    conns = [{"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1"}]
    t = agent._merge_ipsec(conns, [], {})[0]
    assert t["status"] == "down"
    assert t["unique_id"] == ""
    assert t["remote"] == "1.1.1.1"


def test_merge_ipsec_surfaces_orphan_sa() -> None:
    sas = [{"name": "orphan", "local": "9.9.9.9", "remote": "1.1.1.1",
            "status": "ESTABLISHED", "bytes_in": 0, "bytes_out": 0, "unique_id": "2"}]
    t = agent._merge_ipsec([], sas, {})[0]
    assert t["id"] == "orphan"
    assert t["status"] == "ESTABLISHED"


def test_merge_ipsec_uses_description_falls_back_to_uuid() -> None:
    conns = [
        {"name": "uuid-named", "local": "9.9.9.9", "remote": "1.1.1.1"},
        {"name": "uuid-bare", "local": "9.9.9.9", "remote": "2.2.2.2"},
    ]
    tunnels = agent._merge_ipsec(conns, [], {"uuid-named": "Office VPN"})
    by_id = {t["id"]: t for t in tunnels}
    assert by_id["uuid-named"]["description"] == "Office VPN"  # human name shown
    assert by_id["uuid-bare"]["description"] == "uuid-bare"  # no desc → UUID


# config.xml shape confirmed on the box: <Connection uuid="…"><description>…
_CONFIG_XML = (
    "<opnsense><OPNsense><Swanctl><Connections>"
    '<Connection uuid="5fe62ba0-5099-4510-91c7-b2d4e868b39b">'
    "<description>test1</description></Connection>"
    '<Connection uuid="5a9952eb-9ffe-425f-b438-149c2971e5f1">'
    "<description>broken</description></Connection>"
    '<Connection uuid="no-desc-uuid"><description></description></Connection>'
    "</Connections></Swanctl></OPNsense></opnsense>"
)


def test_ipsec_descriptions_parses_config(tmp_path) -> None:
    p = tmp_path / "config.xml"
    p.write_text(_CONFIG_XML)
    descriptions = agent._ipsec_descriptions(str(p))
    assert descriptions == {
        "5fe62ba0-5099-4510-91c7-b2d4e868b39b": "test1",
        "5a9952eb-9ffe-425f-b438-149c2971e5f1": "broken",
    }  # the empty description is omitted → caller falls back to the UUID


def test_ipsec_descriptions_missing_file_returns_empty() -> None:
    assert agent._ipsec_descriptions("/nonexistent/config.xml") == {}


# pfSense config.xml shape confirmed on the box (2.8.1-RELEASE): legacy <ipsec>
# with phase1/phase2 entries keyed by ikeid; swanctl names the connection "conN".
_PFSENSE_CONFIG_XML = (
    "<pfsense><ipsec>"
    "<phase1><ikeid>1</ikeid><descr>opn1</descr></phase1>"
    "<phase2><ikeid>1</ikeid><descr>opn1-p2</descr></phase2>"
    "<phase1><ikeid>2</ikeid><descr>site-b</descr></phase1>"
    "</ipsec></pfsense>"
)


def test_ipsec_descriptions_pfsense_phase1_not_phase2(tmp_path) -> None:
    p = tmp_path / "config.xml"
    p.write_text(_PFSENSE_CONFIG_XML)
    descriptions = agent._ipsec_descriptions(str(p))
    # con1 must be the phase1 name "opn1", NOT the phase2 name "opn1-p2".
    assert descriptions == {"con1": "opn1", "con2": "site-b"}


def test_collect_ipsec_merges_conns_and_sas(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if "--list-conns" in cmd:
            return _SWANCTL_CONNS
        if "--list-sas" in cmd:
            return _SWANCTL_SAS
        if cmd[0] == "pgrep":
            return "1234\n"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(
        agent, "_ipsec_descriptions",
        lambda *a, **k: {"34595782-ae4a-41b8-8722-2d52eb487475": "Site A"},
    )
    result = agent.collect_ipsec()
    assert result["running"] is True
    assert len(result["tunnels"]) == 1  # conn + SA matched by endpoint, not duplicated
    t = result["tunnels"][0]
    assert t["id"] == "34595782-ae4a-41b8-8722-2d52eb487475"  # configured name → connect
    assert t["description"] == "Site A"  # human name from config.xml
    assert t["status"] == "ESTABLISHED"  # live status overlaid
    assert t["unique_id"] == "1"  # → disconnect
    assert "version=" not in t["id"]  # blob regression guard


def test_collect_ipsec_falls_back_to_statusall(monkeypatch: pytest.MonkeyPatch) -> None:
    statusall = "myconn{1}:  INSTALLED, TUNNEL, reqid 1"

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if cmd[0] == "swanctl":
            return ""  # neither conns nor sas → fallback path
        if cmd[0] == "ipsec":
            return statusall
        if cmd[0] == "pgrep":
            return "1234\n"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    tunnels = agent.collect_ipsec()["tunnels"]
    assert len(tunnels) == 1
    assert tunnels[0]["id"] == "myconn"  # connection name, not the {N} uniqueid
    assert tunnels[0]["status"] == "installed"


def test_ipsec_disconnect_uses_ike_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        captured["cmd"] = cmd
        return "terminate completed successfully"

    monkeypatch.setattr(agent, "_run", fake_run)
    result = agent.execute_command("ipsec.disconnect", {"tunnel_id": "1"})
    assert result["success"] is True
    assert captured["cmd"] == ["swanctl", "--terminate", "--ike-id", "1"]


def test_system_info_includes_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "test")
    info = agent.collect_system_info()
    assert info["platform"] == "opnsense"
    assert info["agent_version"] == agent.__version__
