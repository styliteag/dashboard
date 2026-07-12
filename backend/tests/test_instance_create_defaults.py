"""Creation defaults for new instances (schema + service pass-through).

Regression: ``shell_enabled``/``gui_login_enabled`` existed only on
InstanceUpdate — new instances always landed with the DB default (off) and
every box needed a manual edit to enable the browser terminal / GUI login
replay. The operator-requested default is ON at the API boundary (the
server-wide DASH_SHELL_ENABLED gate still applies to the shell; GUI login
degrades gracefully without a provisioned credential); the DB column
defaults stay off.

DB-free house style: encrypt/_slug_taken monkeypatched, fake session.
"""

from __future__ import annotations

import app.instances.service as svc
from app.instances.schemas import InstanceCreate


def test_create_schema_defaults_shell_and_gui_login_on() -> None:
    m = InstanceCreate(name="fw", base_url="https://a.example")
    assert m.shell_enabled is True
    assert m.gui_login_enabled is True


def test_create_schema_shell_and_gui_login_can_be_disabled() -> None:
    m = InstanceCreate(
        name="fw", base_url="https://a.example", shell_enabled=False, gui_login_enabled=False
    )
    assert m.shell_enabled is False
    assert m.gui_login_enabled is False


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


async def _never_taken(session, slug: str, exclude_id) -> bool:  # noqa: ANN001
    return False


async def test_create_instance_passes_shell_enabled_through(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _never_taken)
    monkeypatch.setattr(svc, "encrypt", lambda v: b"enc")
    session = _FakeSession()
    payload = InstanceCreate(name="fw", base_url="https://a.example")
    inst = await svc.create_instance(session, payload, group_id=1)  # type: ignore[arg-type]
    assert inst.shell_enabled is True
    assert inst.gui_login_enabled is True
    assert session.added == [inst]


async def test_create_instance_respects_explicit_shell_off(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _never_taken)
    monkeypatch.setattr(svc, "encrypt", lambda v: b"enc")
    payload = InstanceCreate(
        name="fw", base_url="https://a.example", shell_enabled=False, gui_login_enabled=False
    )
    inst = await svc.create_instance(_FakeSession(), payload, group_id=1)  # type: ignore[arg-type]
    assert inst.shell_enabled is False
    assert inst.gui_login_enabled is False
