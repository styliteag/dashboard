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


def test_collect_firmware_pfsense_reports_version(
    fake_fs: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    fake_fs["/etc/version"] = "26.03-RELEASE\n"
    assert agent.collect_firmware() == {"product_version": "26.03-RELEASE"}


def test_collect_gateways_pfsense_is_empty_until_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    assert agent.collect_gateways() == []


def test_system_info_includes_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "test")
    info = agent.collect_system_info()
    assert info["platform"] == "opnsense"
    assert info["agent_version"] == agent.__version__
