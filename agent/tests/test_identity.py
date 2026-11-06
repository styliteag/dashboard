"""Firewall agent identity claims: per-interface MAC + derived machine_id."""

from __future__ import annotations

import hashlib
import hmac

import orbit_agent as agent
import pytest

_IFCONFIG = """\
em0: flags=8963<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> metric 0 mtu 1500
\toptions=4e100bb<RXCSUM,TXCSUM>
\tether 00:0C:29:AA:BB:CC
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
\tmedia: Ethernet autoselect (1000baseT <full-duplex>)
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
em1: flags=8963<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 00:0c:29:aa:bb:dd
\thwaddr 00:0c:29:aa:bb:de
"""

_VECTOR_UUID = "8d2f0b6e-1111-2222-3333-444455556666"


def _fake_run(outputs: dict[str, str]):
    def fake(cmd: list[str], timeout: int = 5) -> str:
        return outputs.get(cmd[0], "")

    return fake


def _expected(raw: str) -> str:
    return hmac.new(raw.encode(), b"stylite-orbit-identity-v1", hashlib.sha256).hexdigest()


def test_interfaces_report_mac_lowercase_and_omit_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", _fake_run({"ifconfig": _IFCONFIG}))
    by_name = {i["name"]: i for i in agent.collect_interfaces()}
    assert by_name["em0"]["mac"] == "00:0c:29:aa:bb:cc"
    assert by_name["em1"]["mac"] == "00:0c:29:aa:bb:dd"
    assert "mac" not in by_name["lo0"]


def test_interface_first_ether_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    out = "em0: flags=8963<UP,RUNNING> mtu 1500\n\tether 00:0c:29:00:00:01\n\tether 00:0c:29:00:00:02\n"
    monkeypatch.setattr(agent, "_run", _fake_run({"ifconfig": out}))
    assert agent.collect_interfaces()[0]["mac"] == "00:0c:29:00:00:01"


def test_machine_id_is_hmac_of_hostuuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", _fake_run({"sysctl": _VECTOR_UUID + "\n"}))
    mid = agent.collect_system_info()["machine_id"]
    assert mid == _expected(_VECTOR_UUID)
    assert _VECTOR_UUID not in mid


def test_machine_id_known_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fixed vector: must equal the linux drop-in derivation (60-identity.py).
    monkeypatch.setattr(agent, "_run", _fake_run({"sysctl": "abc\n"}))
    assert agent.collect_system_info()["machine_id"] == (
        "9b8916c5185d105e9ce5c0290b3b4384e6cd197f5c9551be9909ebf9d4415617"
    )


@pytest.mark.parametrize(
    "value",
    ["", "\n", "  ", "00000000-0000-0000-0000-000000000000\n"],
)
def test_machine_id_omitted_when_missing_or_zero(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(agent, "_run", _fake_run({"sysctl": value}))
    assert "machine_id" not in agent.collect_system_info()
