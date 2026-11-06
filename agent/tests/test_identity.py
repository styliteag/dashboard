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


# Reference vector: fingerprint equals `ssh-keygen -lf -E sha256` of this key.
_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINhPjntGXfvWzLJgmFRFzEmDu0zr+E1qrpNkv5B3/AW1 root@host"
_FP = "ssh-ed25519 SHA256:D0OArjDyLtVfrZcRB1w3HQTTinCXgN4Zo5gKaaP1ZBM"


def _key_dir(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return str(tmp_path / "ssh_host_*_key.pub")


def test_ssh_host_keys_known_vector_sorted_deduped(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    pattern = _key_dir(
        tmp_path,
        {
            "ssh_host_ed25519_key.pub": _PUB + "\n",
            "ssh_host_ed25519_copy_key.pub": _PUB + "\n",
            "ssh_host_x_key.pub": _PUB.replace("ssh-ed25519", "ecdsa-sha2-nistp256", 1) + "\n",
            "ssh_host_bad_key.pub": "garbage\n",
            "ssh_host_b64_key.pub": "ssh-rsa !!!notbase64!!! c\n",
        },
    )
    monkeypatch.setattr(agent, "_SSH_HOST_KEY_GLOB", pattern)
    keys = agent._ssh_host_keys()
    assert _FP in keys
    assert keys == sorted(set(keys))
    assert keys.count(_FP) == 1
    assert len(keys) == 2
    assert all(k.startswith(("ssh-ed25519 SHA256:", "ecdsa-sha2-nistp256 SHA256:")) for k in keys)


def test_ssh_host_keys_unreadable_skipped(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    pattern = _key_dir(tmp_path, {"ssh_host_ed25519_key.pub": _PUB})
    (tmp_path / "ssh_host_dir_key.pub").mkdir()  # open() raises IsADirectoryError
    monkeypatch.setattr(agent, "_SSH_HOST_KEY_GLOB", pattern)
    assert agent._ssh_host_keys() == [_FP]


def test_system_info_ssh_host_keys_present_and_omitted(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", _fake_run({}))
    monkeypatch.setattr(agent, "_SSH_HOST_KEY_GLOB", str(tmp_path / "none_*"))
    assert "ssh_host_keys" not in agent.collect_system_info()
    pattern = _key_dir(tmp_path, {"ssh_host_ed25519_key.pub": _PUB})
    monkeypatch.setattr(agent, "_SSH_HOST_KEY_GLOB", pattern)
    assert agent.collect_system_info()["ssh_host_keys"] == [_FP]
