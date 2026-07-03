"""Group notification-channel config API (guard, validation, masking).

DB-free in the house style — fake AsyncSession; encrypt/decrypt patched to
reversible fakes; write_audit and the SSRF resolver patched.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

import app.groups.channels as channels_mod
from app.groups.channels import (
    GroupChannelPut,
    delete_group_channel,
    list_group_channels,
    set_group_channel,
)
from app.notifications.channel_config import MASK


@pytest.fixture(autouse=True)
def _patches(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop(*args: object, **kwargs: object) -> None:
        return None

    async def _ssrf_ok(_url: str) -> str | None:
        return None

    monkeypatch.setattr(channels_mod, "write_audit", _noop)
    monkeypatch.setattr(channels_mod, "_ssrf_block_reason", _ssrf_ok)
    monkeypatch.setattr(channels_mod, "encrypt", lambda s: s.encode())
    monkeypatch.setattr(channels_mod, "decrypt", lambda b: b.decode())


def _request() -> Request:
    return Request({"type": "http", "method": "PUT", "headers": [], "client": ("1.2.3.4", 1234)})


def _superadmin() -> SimpleNamespace:
    return SimpleNamespace(id=1, is_superadmin=True, group_id_set=frozenset())


def _member_admin(*groups: int) -> SimpleNamespace:
    return SimpleNamespace(id=2, is_superadmin=False, group_id_set=frozenset(groups))


def _row(channel: str, config: dict) -> SimpleNamespace:
    return SimpleNamespace(
        channel=channel,
        config_enc=json.dumps(config).encode(),
        updated_at=datetime.now(UTC),
        group_id=1,
    )


class _ScalarsResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarsResult:
        return self

    def all(self) -> list[object]:
        return self._rows

    def scalar_one_or_none(self) -> object:
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, *, group: object = None, rows: list[object] | None = None) -> None:
        self._group = group
        self._rows = rows or []
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.committed = False

    async def get(self, _model: object, _pk: object) -> object:
        return self._group

    async def execute(self, _stmt: object) -> _ScalarsResult:
        return _ScalarsResult(list(self._rows))

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def delete(self, obj: object) -> None:
        self.deleted.append(obj)

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj: object) -> None:
        if getattr(obj, "updated_at", None) is None:
            obj.updated_at = datetime.now(UTC)


_GROUP = SimpleNamespace(id=1, name="branch")


# --- guard --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_member_admin_gets_404() -> None:
    session = _FakeSession(group=_GROUP)
    with pytest.raises(HTTPException) as exc:
        await list_group_channels(
            1,
            session=session,  # type: ignore[arg-type]
            user=_member_admin(2),  # member of group 2, not 1
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_member_admin_and_superadmin_may_list() -> None:
    row = _row("mattermost", {"url": "https://hook.example"})
    for actor in (_member_admin(1), _superadmin()):
        session = _FakeSession(group=_GROUP, rows=[row])
        out = await list_group_channels(1, session=session, user=actor)  # type: ignore[arg-type]
        assert out[0].channel == "mattermost"


# --- masking ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_masks_secrets_passes_plain() -> None:
    row = _row("telegram", {"token": "tg-secret", "chat_id": "42"})
    session = _FakeSession(group=_GROUP, rows=[row])
    out = await list_group_channels(1, session=session, user=_superadmin())  # type: ignore[arg-type]
    assert out[0].config["token"] == MASK
    assert out[0].config["chat_id"] == "42"


# --- PUT validation --------------------------------------------------------------


async def _put(session: _FakeSession, channel: str, config: dict) -> object:
    return await set_group_channel(
        1,
        channel,
        GroupChannelPut(config=config),
        _request(),
        session=session,  # type: ignore[arg-type]
        user=_superadmin(),
    )


@pytest.mark.asyncio
async def test_put_unknown_channel_404() -> None:
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "pager", {"x": "y"})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_put_unknown_field_422() -> None:
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "mattermost", {"url": "https://x", "bogus": "1"})
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_put_missing_required_422() -> None:
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "telegram", {"chat_id": "42"})
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_put_bad_port_and_security_422() -> None:
    base = {"smtp_host": "smtp.x", "from": "a@x", "to": "b@x"}
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "email", {**base, "smtp_port": "99999"})
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "email", {**base, "security": "tls13"})
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_put_ssrf_blocked_url_422(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _blocked(_url: str) -> str | None:
        return "blocked address 169.254.169.254"

    monkeypatch.setattr(channels_mod, "_ssrf_block_reason", _blocked)
    with pytest.raises(HTTPException) as exc:
        await _put(_FakeSession(group=_GROUP), "mattermost", {"url": "http://169.254.169.254/x"})
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_put_creates_row_and_masks_response() -> None:
    session = _FakeSession(group=_GROUP)
    out = await _put(session, "mattermost", {"url": "https://hook.example"})
    assert len(session.added) == 1
    assert json.loads(session.added[0].config_enc.decode()) == {"url": "https://hook.example"}
    assert out.config["url"] == MASK  # secret masked in the response
    assert session.committed


@pytest.mark.asyncio
async def test_put_masked_secret_keeps_stored_value() -> None:
    row = _row("telegram", {"token": "tg-old", "chat_id": "42"})
    session = _FakeSession(group=_GROUP, rows=[row])
    await _put(session, "telegram", {"token": MASK, "chat_id": "43"})
    stored = json.loads(row.config_enc.decode())
    assert stored["token"] == "tg-old"  # mask = keep
    assert stored["chat_id"] == "43"  # non-secret replaced


# --- DELETE -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_missing_404() -> None:
    session = _FakeSession(group=_GROUP, rows=[])
    with pytest.raises(HTTPException) as exc:
        await delete_group_channel(
            1,
            "mattermost",
            _request(),
            session=session,  # type: ignore[arg-type]
            user=_superadmin(),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_delete_removes_row() -> None:
    row = _row("mattermost", {"url": "https://hook.example"})
    session = _FakeSession(group=_GROUP, rows=[row])
    await delete_group_channel(
        1,
        "mattermost",
        _request(),
        session=session,  # type: ignore[arg-type]
        user=_member_admin(1),
    )
    assert row in session.deleted
    assert session.committed
