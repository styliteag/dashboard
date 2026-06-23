"""Tests for platform detection and the OPNsense/pfSense collector dispatch."""

from __future__ import annotations

import opnsense_agent as agent
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


def test_system_info_includes_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "test")
    info = agent.collect_system_info()
    assert info["platform"] == "opnsense"
    assert info["agent_version"] == agent.__version__
