"""Bootstrap-superadmin lifecycle (mirrors the admin seed, told apart by flag).

DB-free in the house style — ``get_sessionmaker`` is patched to a fake session,
``get_settings`` to a plain namespace. Covers creation, retirement, break-glass
re-enable, forced disable and the two-bootstrap-rows regression (both seed
lookups MUST filter on ``is_superadmin`` or ``scalar_one_or_none`` raises
``MultipleResultsFound`` and breaks startup).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.auth.bootstrap as bootstrap
from app.auth.bootstrap import ensure_admin, ensure_superadmin


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    """Covers only what bootstrap touches: one boot-row lookup via ``execute``
    plus ordered ``scalar`` counts."""

    def __init__(self, *, boot: object = None, scalars: list[int] | None = None) -> None:
        self._boot = boot
        self._scalars = list(scalars or [])
        self.executed: list[object] = []
        self.added: list[object] = []
        self.committed = False

    async def execute(self, stmt: object) -> _Result:
        self.executed.append(stmt)
        return _Result(self._boot)

    async def scalar(self, _stmt: object) -> int:
        return self._scalars.pop(0)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.committed = True


class _Ctx:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _wire(monkeypatch: pytest.MonkeyPatch, session: _FakeSession, **settings: str) -> None:
    base = {
        "admin_password": "admin-secret",
        "admin_disabled": "auto",
        "superadmin_password": "super-secret",
        "superadmin_disabled": "auto",
    }
    base.update(settings)
    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(**base))
    monkeypatch.setattr(bootstrap, "get_sessionmaker", lambda: lambda: _Ctx(session))


def _boot_row(*, disabled: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        username="superadmin", disabled=disabled, password_hash="old", password_version=1
    )


# --- creation ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_created_on_first_start(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession(boot=None, scalars=[0, 0])  # total_users, enabled_superadmins
    _wire(monkeypatch, session)
    await ensure_superadmin()
    assert len(session.added) == 1
    seed = session.added[0]
    assert seed.username == "superadmin"
    assert seed.is_superadmin is True
    assert seed.is_bootstrap is True
    assert seed.role == "view_only"  # least privilege: rights management only
    assert seed.disabled is False
    assert seed.password_hash != "super-secret"  # hashed
    assert session.committed


@pytest.mark.asyncio
async def test_created_on_upgrade_when_no_superadmin_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Existing installation (users present) but nobody is superadmin yet.
    session = _FakeSession(boot=None, scalars=[5, 0])
    _wire(monkeypatch, session)
    await ensure_superadmin()
    assert len(session.added) == 1


@pytest.mark.asyncio
async def test_not_created_when_real_superadmin_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession(boot=None, scalars=[5, 1])
    _wire(monkeypatch, session)
    await ensure_superadmin()
    assert session.added == []


@pytest.mark.asyncio
async def test_not_created_without_password(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession(boot=None)
    _wire(monkeypatch, session, superadmin_password="")
    await ensure_superadmin()
    assert session.added == []


@pytest.mark.asyncio
async def test_not_created_when_forced_disabled_on_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession(boot=None, scalars=[5, 0])
    _wire(monkeypatch, session, superadmin_disabled="1")
    await ensure_superadmin()
    assert session.added == []


# --- lifecycle of the existing seed row -------------------------------------


@pytest.mark.asyncio
async def test_retired_once_real_superadmin_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    boot = _boot_row()
    session = _FakeSession(boot=boot, scalars=[1])  # one real superadmin
    _wire(monkeypatch, session)
    await ensure_superadmin()
    assert boot.disabled is True
    assert session.committed


@pytest.mark.asyncio
async def test_breakglass_reenable_resets_password(monkeypatch: pytest.MonkeyPatch) -> None:
    boot = _boot_row(disabled=True)
    session = _FakeSession(boot=boot, scalars=[0])  # no real superadmin left
    _wire(monkeypatch, session)
    await ensure_superadmin()
    assert boot.disabled is False
    assert boot.password_hash != "old"
    assert boot.password_version == 2  # existing sessions invalidated


@pytest.mark.asyncio
async def test_forced_disabled_wins_over_lockout(monkeypatch: pytest.MonkeyPatch) -> None:
    boot = _boot_row()
    session = _FakeSession(boot=boot, scalars=[0])
    _wire(monkeypatch, session, superadmin_disabled="1")
    await ensure_superadmin()
    assert boot.disabled is True


@pytest.mark.asyncio
async def test_forced_enabled_keeps_seed_on(monkeypatch: pytest.MonkeyPatch) -> None:
    boot = _boot_row()
    session = _FakeSession(boot=boot, scalars=[])  # mode "enabled": no count needed…
    _wire(monkeypatch, session, superadmin_disabled="0")
    # …but _other_enabled_superadmins runs before the mode branch; feed it.
    session._scalars = [3]
    await ensure_superadmin()
    assert boot.disabled is False


# --- two-bootstrap-rows regression ------------------------------------------


@pytest.mark.asyncio
async def test_seed_lookups_disambiguate_by_superadmin_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both seeds are ``is_bootstrap`` rows; without the ``is_superadmin`` filter
    the lookup would raise MultipleResultsFound and crash every startup."""
    admin_session = _FakeSession(boot=None, scalars=[1, 1])
    _wire(monkeypatch, admin_session)
    await ensure_admin()
    super_session = _FakeSession(boot=None, scalars=[1, 1])
    _wire(monkeypatch, super_session)
    await ensure_superadmin()

    admin_lookup = str(admin_session.executed[0])
    super_lookup = str(super_session.executed[0])
    assert "is_superadmin" in admin_lookup
    assert "is_superadmin" in super_lookup
    assert admin_lookup != super_lookup
