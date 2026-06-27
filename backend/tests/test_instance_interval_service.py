"""Per-instance interval-override update semantics (DB-free).

The clearing case is the bug-prone one: an explicit ``null`` must reset the
override to the global default, while *omitting* the field leaves it untouched —
distinguished via ``model_fields_set``, not None-ness.
"""

from __future__ import annotations

from types import SimpleNamespace

import app.instances.service as svc
from app.instances.schemas import InstanceUpdate


class _FakeSession:
    async def flush(self) -> None:  # update_instance flushes before invalidating
        return None


async def _noop_invalidate(_instance_id: int) -> None:
    return None


def _inst(**over) -> SimpleNamespace:
    base = {
        "id": 1,
        "name": "fw",
        "poll_interval_seconds": None,
        "push_interval_seconds": None,
        # SSH fields so the colleague's _maybe_pin_host_key short-circuits (disabled).
        "ssh_enabled": False,
        "ssh_key_enc": None,
        "ssh_host_key": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


async def test_sets_poll_override(monkeypatch) -> None:
    monkeypatch.setattr(svc.registry, "invalidate", _noop_invalidate)
    inst = _inst()
    await svc.update_instance(_FakeSession(), inst, InstanceUpdate(poll_interval_seconds=60))
    assert inst.poll_interval_seconds == 60


async def test_sets_push_override(monkeypatch) -> None:
    monkeypatch.setattr(svc.registry, "invalidate", _noop_invalidate)
    inst = _inst()
    await svc.update_instance(_FakeSession(), inst, InstanceUpdate(push_interval_seconds=120))
    assert inst.push_interval_seconds == 120


async def test_explicit_null_clears_override(monkeypatch) -> None:
    monkeypatch.setattr(svc.registry, "invalidate", _noop_invalidate)
    inst = _inst(poll_interval_seconds=300)
    await svc.update_instance(_FakeSession(), inst, InstanceUpdate(poll_interval_seconds=None))
    assert inst.poll_interval_seconds is None


async def test_omitted_field_leaves_override_untouched(monkeypatch) -> None:
    monkeypatch.setattr(svc.registry, "invalidate", _noop_invalidate)
    inst = _inst(poll_interval_seconds=300)
    await svc.update_instance(_FakeSession(), inst, InstanceUpdate(name="renamed"))
    assert inst.poll_interval_seconds == 300
    assert inst.name == "renamed"
