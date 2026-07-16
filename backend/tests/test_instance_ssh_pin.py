"""Trust-on-first-use host-key capture wired into instance create/update.

Guards the silent failure mode: if this helper never stores the key, every
SSH-enabled instance stays on the spcgi fallback forever (the degradation the
fail-closed change introduces is meant to be transient, not permanent).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.instances.service as service
from app.securepoint.ssh import SecurepointSSHError


def _inst(**over) -> SimpleNamespace:
    base = dict(
        id=1,
        ssh_enabled=True,
        ssh_key_enc=b"enc",
        ssh_host_key=None,
        ssh_host="1.2.3.4",
        ssh_port=22,
        ssh_user="root",
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_pin_captures_and_stores_host_key(monkeypatch) -> None:
    seen: dict[str, object] = {}

    async def fake_probe(host, port, user, key):
        seen.update(host=host, port=port, user=user, key=key)
        return "ssh-ed25519 AAAACAPTURED host"

    monkeypatch.setattr(service, "probe_host_key", fake_probe)
    monkeypatch.setattr(service, "decrypt", lambda b: "DECRYPTED")

    inst = _inst()
    await service._maybe_pin_host_key(inst)

    assert inst.ssh_host_key == "ssh-ed25519 AAAACAPTURED host"
    assert seen == {"host": "1.2.3.4", "port": 22, "user": "root", "key": "DECRYPTED"}


@pytest.mark.asyncio
async def test_pin_swallows_probe_failure_and_stays_unpinned(monkeypatch) -> None:
    async def boom(*a, **k):
        raise SecurepointSSHError("box unreachable")

    monkeypatch.setattr(service, "probe_host_key", boom)
    monkeypatch.setattr(service, "decrypt", lambda b: "K")

    inst = _inst()
    await service._maybe_pin_host_key(inst)  # must not raise
    assert inst.ssh_host_key is None  # unpinned → spcgi fallback, retried on next save


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "over",
    [
        {"ssh_enabled": False},  # enrichment off
        {"ssh_key_enc": None},  # no key uploaded
        {"ssh_host_key": "ssh-ed25519 ALREADY pinned"},  # already pinned
    ],
)
async def test_pin_is_noop_when_not_applicable(monkeypatch, over) -> None:
    called = False

    async def fake_probe(*a, **k):
        nonlocal called
        called = True
        return "x"

    monkeypatch.setattr(service, "probe_host_key", fake_probe)
    monkeypatch.setattr(service, "decrypt", lambda b: "K")

    inst = _inst(**over)
    before = inst.ssh_host_key
    await service._maybe_pin_host_key(inst)

    assert called is False  # never probes
    assert inst.ssh_host_key == before  # unchanged
