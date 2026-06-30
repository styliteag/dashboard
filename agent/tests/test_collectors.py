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

    def glob(self, pattern: str):
        import fnmatch

        prefix = self._p.rstrip("/") + "/"
        for key in sorted(FakePath.registry):
            if key.startswith(prefix):
                rest = key[len(prefix) :]
                if "/" not in rest and fnmatch.fnmatch(rest, pattern):
                    yield FakePath(key)

    def __str__(self) -> str:
        return self._p

    def __lt__(self, other: object) -> bool:
        return self._p < str(other)


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


def test_collect_firmware_throttled_preserves_verdict(
    fake_fs: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: pushes happen every ~30s but the network check only every 10 min.
    # The throttled (cheap) push must refresh product_version yet KEEP the last
    # upgrade verdict + latest, otherwise it blanks a detected update to "up to date".
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_last_fw_check_ts", agent.time.monotonic())
    monkeypatch.setattr(
        agent,
        "_last_fw_verdict",
        {
            "branch": "26.03",
            "known_branches": ["26.03"],
            "upgrade_available": True,
            "product_latest": "26.04-RELEASE",
            "update_check_output": "will be upgraded",
        },
    )
    fake_fs["/etc/version"] = "26.03-RELEASE\n"
    out = agent.collect_firmware()
    assert out["product_version"] == "26.03-RELEASE"  # recomputed every push
    assert out["upgrade_available"] is True  # verdict preserved, not blanked
    assert out["product_latest"] == "26.04-RELEASE"


def test_opnsense_update_check_detects_pkg_point_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # opnsense-update -c misses pkg point releases (26.1.9 -> 26.1.10); the pkg
    # compare after a catalogue refresh must catch it and report the real latest.
    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if cmd[:2] == ["/usr/local/sbin/opnsense-update", "-c"]:
            return ""  # base set is current -> no signal here
        if cmd[:3] == ["pkg", "query", "%v"]:
            return "26.1.9\n"
        if cmd[:3] == ["pkg", "rquery", "%v"]:
            return "26.1.10\n"
        return ""  # pkg update -q

    monkeypatch.setattr(agent, "_run", fake_run)
    upgrade, latest, out = agent._opnsense_update_check("26.1.9")
    assert upgrade is True
    assert latest == "26.1.10"
    assert "26.1.10" in out


def test_opnsense_update_check_up_to_date(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if cmd[:3] == ["pkg", "query", "%v"] or cmd[:3] == ["pkg", "rquery", "%v"]:
            return "26.1.10\n"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    upgrade, latest, _ = agent._opnsense_update_check("26.1.10")
    assert upgrade is False
    assert latest == "26.1.10"  # latest still reported even with no update


def test_opnsense_update_check_stale_catalogue_no_false_uptodate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If rquery comes back empty (stale/missing catalogue) we must NOT claim an
    # update; latest falls back to installed rather than going blank.
    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if cmd[:3] == ["pkg", "query", "%v"]:
            return "26.1.9\n"
        return ""  # rquery empty, update -q noop

    monkeypatch.setattr(agent, "_run", fake_run)
    upgrade, latest, _ = agent._opnsense_update_check("26.1.9")
    assert upgrade is False
    assert latest == "26.1.9"


_REPO_DIR = "/usr/local/etc/pfSense/pkg/repos/"
# Verbatim url lines captured on real boxes (CE 2.8.1 / Plus 26.03 / old CE 2.7.0).
_CONF_CE = 'pfSense: {\n  url: "pkg+https://pkg.pfsense.org/pfSense_v2_8_1_amd64-core",\n}'
_CONF_PLUS = (
    'pfSense: {\n  url: "pkg+https://pfsense-plus-pkg.netgate.com/'
    'pfSense_plus-v26_03_aarch64-core",\n}'
)
_CONF_OLD = 'pfSense: {\n  url: "pkg+https://pkg.pfsense.org/pfSense_v2_7_0_amd64-core",\n}'


def test_pfsense_branch_from_conf_ce_url(fake_fs: dict) -> None:
    # Index-slot filename ("0000") is meaningless; the train comes from the URL.
    fake_fs[_REPO_DIR + "pfSense-repo-0000.conf"] = _CONF_CE
    assert agent._pfsense_branch_from_conf(_REPO_DIR + "pfSense-repo-0000.conf") == "2_8_1"


def test_pfsense_branch_from_conf_plus_url(fake_fs: dict) -> None:
    # Plus uses a different url shape ("pfSense_plus-v26_03_aarch64") — same train.
    fake_fs[_REPO_DIR + "pfSense-repo-0001.conf"] = _CONF_PLUS
    assert agent._pfsense_branch_from_conf(_REPO_DIR + "pfSense-repo-0001.conf") == "26_03"


def test_pfsense_branch_from_conf_old_layout_url(fake_fs: dict) -> None:
    # Old 2.6/2.7 box: bare pfSense-repo.conf, no .name file — URL still works.
    base = "/usr/local/share/pfSense/pkg/repos/pfSense-repo"
    fake_fs[base + ".conf"] = _CONF_OLD
    assert agent._pfsense_branch_from_conf(base + ".conf") == "2_7_0"


def test_pfsense_branch_from_conf_falls_back_to_descr(fake_fs: dict) -> None:
    # No parseable URL → human descriptor (matches pfSense's GUI branch label).
    base = _REPO_DIR + "pfSense-repo-0000"
    fake_fs[base + ".conf"] = "pfSense: {}"  # no url
    fake_fs[base + ".descr"] = "Current Stable Version (2.8.1)\n"
    assert agent._pfsense_branch_from_conf(base + ".conf") == "Current Stable Version (2.8.1)"


def test_list_pfsense_branches_only_conf_files(fake_fs: dict) -> None:
    # Two repo slots resolve to train ids; .abi/.altabi metadata are NOT branches.
    fake_fs[_REPO_DIR + "pfSense-repo-0000.conf"] = (
        'url: "pkg+https://pfsense-plus-pkg.netgate.com/pfSense_plus-v26_03_1_aarch64-core"'
    )
    fake_fs[_REPO_DIR + "pfSense-repo-0001.conf"] = (
        'url: "pkg+https://pfsense-plus-pkg.netgate.com/pfSense_plus-v26_03_aarch64-core"'
    )
    fake_fs[_REPO_DIR + "pfSense-repo-0000.abi"] = "FreeBSD:15:amd64\n"
    fake_fs[_REPO_DIR + "pfSense-repo-0000.altabi"] = "freebsd:15:x86:64\n"
    assert agent._list_pfsense_branches() == ["26_03_1", "26_03"]


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


# Two `list-sa event` envelopes share the SAME connection name: the live
# ESTABLISHED SA and a passive `%any`/CREATED half-open responder SA. Merging
# repeated section keys (the old behavior) collapsed them and let the half-open
# clobber the established record's host + IKE cookie → a Frankenstein tunnel
# showing CREATED/%any with a zeroed responder SPI.
_SWANCTL_SAS_HALFOPEN = (
    "list-sa event {tun-a {uniqueid=3 version=2 state=ESTABLISHED "
    "local-host=10.0.0.1 local-port=4500 remote-host=10.0.0.2 remote-port=4500 "
    "initiator=yes initiator-spi=aaaa1111bbbb2222 responder-spi=cccc3333dddd4444 "
    "established=100 child-sas {tun-a-1 {name=tun-a uniqueid=5 state=INSTALLED "
    "mode=TUNNEL protocol=ESP spi-in=11112222 spi-out=33334444 bytes-in=10 "
    "bytes-out=20 local-ts=[10.1.0.0/24] remote-ts=[10.2.0.0/24]}}}}\n"
    "list-sa event {tun-a {uniqueid=1 version=2 state=CREATED local-host=%any "
    "remote-host=%any initiator=yes initiator-spi=ffff0000ffff0000 "
    "responder-spi=0000000000000000 child-sas {}}}\n"
    "list-sas reply {}"
)


def test_parse_swanctl_sas_halfopen_does_not_clobber_established() -> None:
    # Regression: the established record must keep its real host + IKE cookie,
    # not be overwritten by the same-named %any half-open.
    by_name: dict = {s["name"]: s for s in agent._parse_swanctl_sas(_SWANCTL_SAS_HALFOPEN)}
    # Both records survive as separate entries (no merge); pick the established one.
    est = next(
        s for s in agent._parse_swanctl_sas(_SWANCTL_SAS_HALFOPEN) if s["status"] == "ESTABLISHED"
    )
    assert est["local"] == "10.0.0.1"  # NOT %any
    assert est["ike_init_spi"] == "aaaa1111bbbb2222"
    assert est["ike_resp_spi"] == "cccc3333dddd4444"
    assert est["children"][0]["spi_in"] == "11112222"
    assert "tun-a" in by_name


def test_merge_ipsec_drops_halfopen_keeps_established() -> None:
    # The agent's rank/merge surfaces ONE up tunnel for the connection, not the
    # transient %any half-open.
    sas = agent._parse_swanctl_sas(_SWANCTL_SAS_HALFOPEN)
    tuns = agent._merge_ipsec([], sas, {})
    up = [t for t in tuns if t["status"] == "ESTABLISHED"]
    assert len(up) == 1
    assert up[0]["local"] == "10.0.0.1"
    assert up[0]["ike_init_spi"] == "aaaa1111bbbb2222"


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
    # The merged dashboard row counts Phase-2 from the merged selector-pair rows:
    # total = configured pairs (or live pairs when no conn), up = INSTALLED rows.
    sa = agent._parse_swanctl_sas(_SWANCTL_SAS)[0]
    up = agent._tunnel("conn", None, sa, {})
    assert up["seconds_established"] == 1235
    assert up["phase2_up"] == 1
    assert up["phase2_total"] == 1  # falls back to live child count when no conn
    # Two configured pairs, one of them live → "1/2": the configured-but-down pair
    # survives as a down row and still counts toward the denominator.
    conn = {"children": [
        {"name": "c", "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24"},  # live (sa)
        {"name": "c", "local_ts": "10.9.9.0/24", "remote_ts": "10.2.2.0/24"},  # down
    ]}
    preferred = agent._tunnel("conn", conn, sa, {})
    assert preferred["phase2_up"] == 1
    assert preferred["phase2_total"] == 2
    down_conn = {"local": "", "remote": "", "children": [
        {"name": "c", "local_ts": "a", "remote_ts": "b"},
        {"name": "c", "local_ts": "x", "remote_ts": "y"},
    ]}
    down = agent._tunnel("conn", down_conn, None, {})
    assert down["seconds_established"] == 0
    assert down["phase2_up"] == 0
    assert down["phase2_total"] == 2


# A single configured Phase-2 child with multiple local subnets. strongSwan
# splits it into one CHILD_SA per (local x remote) selector pair, and every split
# SA carries the SAME child name. The conn side must expand to one row per pair so
# the live SAs overlay 1:1 by selector. Regression: the dashboard showed "2/1"
# with the first local net repeated and the second net dropped (BadVilbel tunnel).
_SWANCTL_CONNS_MULTINET = (
    "bv {local_addrs=[93.0.0.1] remote_addrs=[80.0.0.1] version=IKEv2 "
    "children {0246d00e {mode=TUNNEL "
    "local-ts=[10.110.0.0/16 192.168.0.0/24] remote-ts=[192.168.200.0/24]}}}"
)
# Peer that splits: two CHILD_SAs, one per local subnet, sharing name=0246d00e.
_SWANCTL_SAS_MULTINET_SPLIT = (
    "bv {uniqueid=2 state=ESTABLISHED remote-host=80.0.0.1 local-host=93.0.0.1 established=99 "
    "child-sas {0246d00e-12 {name=0246d00e uniqueid=2092 state=INSTALLED bytes-in=1 bytes-out=2 "
    "local-ts=[10.110.0.0/16] remote-ts=[192.168.200.0/24]} "
    "0246d00e-4 {name=0246d00e uniqueid=2094 state=INSTALLED bytes-in=3 bytes-out=4 "
    "local-ts=[192.168.0.0/24] remote-ts=[192.168.200.0/24]}}}"
)
# Peer that does NOT split: one CHILD_SA carrying both local subnets in its ts list.
_SWANCTL_SAS_MULTINET_SINGLE = (
    "bv {uniqueid=2 state=ESTABLISHED remote-host=80.0.0.1 local-host=93.0.0.1 established=99 "
    "child-sas {0246d00e-1 {name=0246d00e state=INSTALLED bytes-in=1 bytes-out=2 "
    "local-ts=[10.110.0.0/16 192.168.0.0/24] remote-ts=[192.168.200.0/24]}}}"
)

_MULTINET_PAIRS = [
    ("10.110.0.0/16", "192.168.200.0/24"),
    ("192.168.0.0/24", "192.168.200.0/24"),
]


def test_parse_conns_expands_multinet_child_to_pairs() -> None:
    conn = agent._parse_swanctl_conns(_SWANCTL_CONNS_MULTINET)[0]
    pairs = {(c["local_ts"], c["remote_ts"]) for c in conn["children"]}
    assert pairs == set(_MULTINET_PAIRS)
    assert conn["phase2_total"] == 2  # two selector pairs, not one configured child


def test_tunnel_multinet_split_sas_show_distinct_pairs() -> None:
    # Regression for "2/1" + duplicate local net: each split SA must map to its own
    # configured pair (by selector, never by the shared name) → two distinct rows.
    conn = agent._parse_swanctl_conns(_SWANCTL_CONNS_MULTINET)[0]
    sa = agent._parse_swanctl_sas(_SWANCTL_SAS_MULTINET_SPLIT)[0]
    t = agent._tunnel("bv", conn, sa, {})
    assert sorted((c["local_ts"], c["remote_ts"]) for c in t["children"]) == _MULTINET_PAIRS
    assert all(c["state"] == "INSTALLED" for c in t["children"])
    assert (t["phase2_up"], t["phase2_total"]) == (2, 2)


def test_tunnel_multinet_single_sa_membership_no_double_count() -> None:
    # Non-splitting peer: one CHILD_SA carries both subnets. Both configured pairs
    # match that SA by ts-list membership, yet its byte counter is summed once at
    # the tunnel level (the latent _first() bug on the SA side, made robust).
    conn = agent._parse_swanctl_conns(_SWANCTL_CONNS_MULTINET)[0]
    sa = agent._parse_swanctl_sas(_SWANCTL_SAS_MULTINET_SINGLE)[0]
    t = agent._tunnel("bv", conn, sa, {})
    assert sorted((c["local_ts"], c["remote_ts"]) for c in t["children"]) == _MULTINET_PAIRS
    assert (t["phase2_up"], t["phase2_total"]) == (2, 2)
    assert (t["bytes_in"], t["bytes_out"]) == (1, 2)  # counted once, not doubled


# --- Duplicate Phase-2 detection -------------------------------------------
# A customer-reported failure mode: more than one INSTALLED child SA exists for
# the SAME traffic-selector pair of one connection. It shows up two ways — both
# children under a single IKE_SA, or one child each across two IKE_SAs to the
# same peer (duplicate phase1). _dedupe_children collapses the display row, so
# the duplicate count is carried separately (installed_n → dup_count) and the
# cross-IKE flavor is aggregated before _merge_ipsec picks the single best SA.

# Two INSTALLED children, identical selector pair, under ONE IKE_SA.
_SWANCTL_SAS_DUP_WITHIN = (
    "conn-d {uniqueid=7 state=ESTABLISHED remote-host=2.2.2.2 local-host=1.1.1.1 established=50 "
    "child-sas {d-1 {name=d state=INSTALLED bytes-in=1 bytes-out=2 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]} "
    "d-2 {name=d state=INSTALLED bytes-in=3 bytes-out=4 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
)
# Two separate IKE_SAs (same name + endpoint), one INSTALLED child each, same pair.
_SWANCTL_SAS_DUP_CROSS = (
    "conn-x {uniqueid=8 state=ESTABLISHED remote-host=2.2.2.2 local-host=1.1.1.1 established=60 "
    "initiator-spi=aaaa1111bbbb2222 responder-spi=cccc3333dddd4444 "
    "child-sas {x-1 {name=x state=INSTALLED bytes-in=1 bytes-out=2 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}\n"
    "conn-x {uniqueid=9 state=ESTABLISHED remote-host=2.2.2.2 local-host=1.1.1.1 established=20 "
    "initiator-spi=eeee5555ffff6666 responder-spi=7777aaaa8888bbbb "
    "child-sas {x-9 {name=x state=INSTALLED bytes-in=5 bytes-out=6 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
)


def test_dedupe_children_records_installed_count() -> None:
    # The surviving row carries how many INSTALLED SAs collapsed into it.
    rows = agent._dedupe_children([
        {"local_ts": "a", "remote_ts": "b", "state": "INSTALLED"},
        {"local_ts": "a", "remote_ts": "b", "state": "INSTALLED"},
        {"local_ts": "c", "remote_ts": "d", "state": "INSTALLED"},
    ])
    by_sel = {(r["local_ts"], r["remote_ts"]): r for r in rows}
    assert by_sel[("a", "b")]["installed_n"] == 2
    assert by_sel[("c", "d")]["installed_n"] == 1


def test_merge_ipsec_flags_duplicate_phase2_within_ike() -> None:
    sas = agent._parse_swanctl_sas(_SWANCTL_SAS_DUP_WITHIN)
    tuns = agent._merge_ipsec([], sas, {})
    ch = tuns[0]["children"]
    assert len(ch) == 1  # still one display row (the duplicate is collapsed)
    assert ch[0]["dup_count"] == 2  # but the duplicate is reported
    assert (tuns[0]["phase2_up"], tuns[0]["phase2_total"]) == (1, 1)  # x/n unaffected


def test_merge_ipsec_flags_duplicate_phase2_across_ikes() -> None:
    sas = agent._parse_swanctl_sas(_SWANCTL_SAS_DUP_CROSS)
    assert len(sas) == 2  # two IKE_SAs kept separate (not merged)
    tuns = agent._merge_ipsec([], sas, {})
    up = [t for t in tuns if t["status"] == "ESTABLISHED"]
    assert len(up) == 1  # best-SA collapse → one tunnel row
    dup = [
        c for c in up[0]["children"]
        if (c["local_ts"], c["remote_ts"]) == ("10.1.1.0/24", "10.2.2.0/24")
    ]
    assert dup and dup[0]["dup_count"] == 2


def test_merge_ipsec_no_dup_flag_for_single_phase2() -> None:
    # The healthy single-child case must never carry a duplicate count.
    sas = agent._parse_swanctl_sas(_SWANCTL_SAS)
    tuns = agent._merge_ipsec([], sas, {})
    for t in tuns:
        for c in t["children"]:
            assert c.get("dup_count", 1) <= 1


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


# Regression: swanctl --raw emits one `list-conn event { … }` envelope PER
# configured connection, every one keyed `event` at the same level. A box with
# three tunnels must yield three records — the earlier parser overwrote the
# shared `event` key and surfaced only the last connection (UI showed 1 of 3).
_SWANCTL_CONNS_MULTI = (
    "no files found matching '/usr/local/etc/strongswan.opnsense.d/*.conf'\n"
    "list-conn event {aaaa0000-0000-0000-0000-000000000001 "
    "{local_addrs=[10.21.7.100] remote_addrs=[10.21.7.101] version=IKEv2 "
    "children {c1 {mode=TUNNEL local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}}\n"
    "list-conn event {bbbb0000-0000-0000-0000-000000000002 "
    "{local_addrs=[10.21.7.100] remote_addrs=[2.2.2.2] version=IKEv2 "
    "children {c2 {mode=TUNNEL local-ts=[10.1.1.0/24] remote-ts=[2.2.2.0/24]}}}}\n"
    "list-conn event {cccc0000-0000-0000-0000-000000000003 "
    "{local_addrs=[10.21.7.100] remote_addrs=[10.21.7.102] version=IKEv2 "
    "children {c3 {mode=TUNNEL local-ts=[10.1.1.0/24] remote-ts=[10.3.3.0/24]}}}}\n"
    "list-conns reply {}"
)


def test_parse_swanctl_conns_multiple_records() -> None:
    # Three repeated `event` envelopes must not collapse into one.
    conns = agent._parse_swanctl_conns(_SWANCTL_CONNS_MULTI)
    assert len(conns) == 3
    assert [c["name"] for c in conns] == [
        "aaaa0000-0000-0000-0000-000000000001",
        "bbbb0000-0000-0000-0000-000000000002",
        "cccc0000-0000-0000-0000-000000000003",
    ]
    assert [c["remote"] for c in conns] == ["10.21.7.101", "2.2.2.2", "10.21.7.102"]


# Verbatim `swanctl --list-conns --raw` from a pfSense box (10.20.1.200): a real
# tunnel `con1` plus the auto-generated `bypass` connection whose `bypasslan`
# child is mode=PASS (exclude local nets from IPsec). The bypass shunt must not
# surface as a permanently-down UI row.
_SWANCTL_CONNS_PFSENSE_BYPASS = (
    "list-conn event {bypass {local_addrs=[%any] remote_addrs=[127.0.0.1] "
    "version=IKEv1/2 reauth_time=0 rekey_time=14400 unique=UNIQUE_NO "
    "local-1 {groups=[] certs=[] cacerts=[]} remote-1 {groups=[] certs=[] cacerts=[]} "
    "children {bypasslan {mode=PASS rekey_time=3600 dpd_action=none close_action=none "
    "local-ts=[10.20.0.0/22|/0] remote-ts=[10.20.0.0/22|/0]}}}}\n"
    "list-conn event {con1 {local_addrs=[10.21.7.102] remote_addrs=[10.21.7.100] "
    "version=IKEv2 children {con1-p2 {mode=TUNNEL "
    "local-ts=[10.3.3.0/24] remote-ts=[10.1.1.0/24]}}}}\n"
    "list-conns reply {}"
)


def test_parse_swanctl_conns_skips_pfsense_bypass() -> None:
    # The `bypass` PASS-policy shunt is dropped; the real tunnel `con1` survives.
    conns = agent._parse_swanctl_conns(_SWANCTL_CONNS_PFSENSE_BYPASS)
    assert [c["name"] for c in conns] == ["con1"]
    assert conns[0]["remote"] == "10.21.7.100"


def test_is_shunt_conn() -> None:
    assert agent._is_shunt_conn({"bypasslan": {"mode": "PASS"}}) is True
    assert agent._is_shunt_conn({"x": {"mode": "DROP"}}) is True
    assert agent._is_shunt_conn({"p2": {"mode": "TUNNEL"}}) is False
    # Mixed: a real TUNNEL child keeps the connection.
    assert agent._is_shunt_conn({"a": {"mode": "PASS"}, "b": {"mode": "TUNNEL"}}) is False
    # No children / missing mode → not a shunt (don't drop real tunnels).
    assert agent._is_shunt_conn({}) is False
    assert agent._is_shunt_conn(None) is False


def test_parse_swanctl_sas_multiple_records() -> None:
    # Same envelope-per-record shape for live SAs.
    raw = (
        "list-sa event {conn-a {uniqueid=1 state=ESTABLISHED "
        "local-host=9.9.9.9 remote-host=1.1.1.1 established=10}}\n"
        "list-sa event {conn-b {uniqueid=2 state=ESTABLISHED "
        "local-host=9.9.9.9 remote-host=2.2.2.2 established=20}}\n"
        "list-sas reply {}"
    )
    sas = agent._parse_swanctl_sas(raw)
    assert len(sas) == 2
    assert {s["name"] for s in sas} == {"conn-a", "conn-b"}
    assert {s["unique_id"] for s in sas} == {"1", "2"}


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


def test_merge_ipsec_prefers_established_over_rekey_dup() -> None:
    # Make-before-break: one connection, two live SAs for a few seconds — an old
    # ESTABLISHED SA carrying the installed child + traffic, and a new CONNECTING
    # SA mid-handshake. Last-wins would surface CONNECTING (red) even though the
    # tunnel is up and passing bytes. The established SA must win.
    conns = [{"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1"}]
    established = {"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1",
                  "status": "ESTABLISHED", "phase2_up": 1, "bytes_in": 860,
                  "bytes_out": 1600, "unique_id": "73"}
    connecting = {"name": "c1", "local": "9.9.9.9", "remote": "1.1.1.1",
                  "status": "CONNECTING", "phase2_up": 0, "bytes_in": 0,
                  "bytes_out": 0, "unique_id": "74"}
    # CONNECTING listed last (newest SA) — the order that defeated last-wins.
    tunnels = agent._merge_ipsec(conns, [established, connecting], {})
    assert len(tunnels) == 1  # the dup is not surfaced as a second row
    assert tunnels[0]["status"] == "ESTABLISHED"
    assert tunnels[0]["unique_id"] == "73"  # disconnect targets the live SA
    assert tunnels[0]["bytes_out"] == 1600


def test_merge_ipsec_prefers_established_by_endpoint_dup() -> None:
    # Same as above but matched by endpoint (SA name drifted from conn name).
    conns = [{"name": "cfg", "local": "9.9.9.9", "remote": "1.1.1.1"}]
    connecting = {"name": "sa-new", "local": "9.9.9.9", "remote": "1.1.1.1",
                  "status": "CONNECTING", "phase2_up": 0, "bytes_in": 0,
                  "bytes_out": 0, "unique_id": "74"}
    established = {"name": "sa-old", "local": "9.9.9.9", "remote": "1.1.1.1",
                  "status": "ESTABLISHED", "phase2_up": 1, "bytes_in": 5,
                  "bytes_out": 7, "unique_id": "73"}
    tunnels = agent._merge_ipsec(conns, [connecting, established], {})
    assert tunnels[0]["status"] == "ESTABLISHED"
    assert tunnels[0]["unique_id"] == "73"


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


# Real `df -T -h` from an OPNsense ZFS box: one zroot pool spread over many
# datasets, plus a devfs, an msdosfs EFI partition, and unbound nullfs binds.
_DF_OPN = """\
Filesystem                 Type       Size    Used   Avail Capacity  Mounted on
zroot/ROOT/default         zfs         11G    1.5G    9.6G    14%    /
devfs                      devfs      1.0K      0B    1.0K     0%    /dev
/dev/gpt/efiboot0          msdosfs    260M    1.3M    259M     1%    /boot/efi
zroot/var/log              zfs        9.6G     10G     9.6G    52%    /var/log
zroot/tmp                  zfs        9.6G    1.4M    9.6G     0%    /tmp
zroot                      zfs        9.6G     96K    9.6G     0%    /zroot
/usr/local/lib/python3.13  nullfs   11G   1.5G  9.6G  14%  /var/unbound/usr/local/lib/python3.13
"""

# Real `df -T -h` from a pfSense UFS box: a ufs root, a tmpfs, and two devfs.
_DF_PF = """\
Filesystem                   Type     Size    Used   Avail Capacity  Mounted on
/dev/ufsid/6a3b8c56991e8004  ufs       14G    2.2G     11G    17%    /
devfs                        devfs    1.0K      0B    1.0K     0%    /dev
tmpfs                        tmpfs    4.0M    172K    3.8M     4%    /var/run
devfs                        devfs    1.0K      0B    1.0K     0%    /var/dhcpd/dev
"""


def test_collect_disk_collapses_zfs_pool_and_drops_pseudo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", lambda *a, **k: _DF_OPN)
    disks = agent.collect_disk()
    mounts = {d["mountpoint"] for d in disks}
    # devfs + nullfs gone; the whole zroot pool collapses to its root mount "/".
    assert mounts == {"/", "/boot/efi"}
    root = next(d for d in disks if d["mountpoint"] == "/")
    # Label stays "/", but the value is the pool's WORST dataset (/var/log at 52%),
    # not the near-empty root dataset (14%) — a filling /var/log must not be hidden.
    assert root["used_pct"] == 52.0
    assert all("fstype" not in d for d in disks)


def test_collect_disk_keeps_ufs_and_tmpfs_drops_devfs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", lambda *a, **k: _DF_PF)
    disks = agent.collect_disk()
    mounts = {d["mountpoint"] for d in disks}
    # Both devfs entries dropped; real ufs root and the tmpfs survive.
    assert mounts == {"/", "/var/run"}
