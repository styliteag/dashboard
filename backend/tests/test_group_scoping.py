"""Group-based instance visibility scoping (app.auth.scope + consumers).

DB-free in the house style. Covers the scope primitives (scope_clause /
can_access), the principal-aware instance service, creation-target resolution,
the move-group permission matrix and the in-memory connected-agents filter.
The WS tunnel and every by-id route reuse ``service.get_instance`` — the
out-of-scope → None behaviour asserted here is exactly what closes them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

import app.agent_hub.routes.update as update_mod
import app.instances.routes as inst_routes
from app.auth.deps import require_admin_or_superadmin
from app.auth.scope import can_access, scope_clause
from app.db.models import ApiKey, Group, Instance
from app.instances.routes import InstanceMoveGroup, _resolve_create_group, move_group
from app.instances.service import get_instance


def _user(*groups: int, superadmin: bool = False, admin: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        role="admin" if admin else "user",
        is_admin=admin,
        is_superadmin=superadmin,
        group_id_set=frozenset(groups),
    )


def _inst(iid: int = 1, group_id: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=iid, group_id=group_id, deleted_at=None, name=f"fw{iid}")


def _request() -> Request:
    return Request({"type": "http", "method": "PUT", "headers": [], "client": ("1.2.3.4", 1234)})


class _FakeSession:
    """Dispatches ``get`` on the model class: Instance vs Group."""

    def __init__(self, *, instance: object = None, group_ids: set[int] | None = None) -> None:
        self._instance = instance
        self._group_ids = group_ids or set()
        self.committed = False

    async def get(self, model: type, pk: int) -> object:
        if model is Group:
            return SimpleNamespace(id=pk) if pk in self._group_ids else None
        return self._instance

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, _obj: object) -> None:
        return None


# --- scope primitives ---------------------------------------------------------


def test_scope_clause_none_for_machine_and_unbound_apikey() -> None:
    assert scope_clause(None) is None
    # INVERTED empty-set semantics: an ApiKey with zero bindings is GLOBAL
    # (while a User with zero memberships sees nothing, below).
    assert scope_clause(ApiKey()) is None


def test_scope_clause_bound_apikey_filters_on_binding() -> None:
    key = ApiKey(groups=[Group(id=2, name="branch")])
    clause = scope_clause(key)
    assert clause is not None
    assert "group_id" in str(clause)


def test_scope_clause_filters_on_membership() -> None:
    clause = scope_clause(_user(1, 3))
    assert clause is not None
    assert "group_id" in str(clause)


def test_scope_clause_zero_groups_is_false_not_all() -> None:
    clause = scope_clause(_user())
    assert clause is not None
    assert str(clause) == str(__import__("sqlalchemy").false())


def test_can_access_matrix() -> None:
    inst = _inst(group_id=2)
    assert can_access(None, inst) is True  # machine context
    assert can_access(ApiKey(), inst) is True  # unbound orbit_ key = global
    assert can_access(ApiKey(groups=[Group(id=2, name="b")]), inst) is True  # bound, member
    assert can_access(ApiKey(groups=[Group(id=1, name="a")]), inst) is False  # bound, foreign
    assert can_access(_user(2), inst) is True  # member
    assert can_access(_user(1), inst) is False  # other group
    assert can_access(_user(), inst) is False  # zero groups
    # superadmin grants rights management, NOT instance access
    assert can_access(_user(superadmin=True), inst) is False


# --- principal-aware instance service ------------------------------------------


@pytest.mark.asyncio
async def test_get_instance_out_of_scope_is_none() -> None:
    session = _FakeSession(instance=_inst(group_id=2))
    assert await get_instance(session, 1, _user(1)) is None  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_get_instance_member_and_machine_see_it() -> None:
    inst = _inst(group_id=2)
    session = _FakeSession(instance=inst)
    assert await get_instance(session, 1, _user(2)) is inst  # type: ignore[arg-type]
    assert await get_instance(session, 1, None) is inst  # type: ignore[arg-type]


# --- create-target resolution ---------------------------------------------------


@pytest.mark.asyncio
async def test_create_group_implied_for_single_membership() -> None:
    assert await _resolve_create_group(_FakeSession(), _user(5), None) == 5  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_create_group_required_for_multi_membership() -> None:
    with pytest.raises(HTTPException) as exc:
        await _resolve_create_group(_FakeSession(), _user(1, 2), None)  # type: ignore[arg-type]
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_create_group_rejects_foreign_group() -> None:
    with pytest.raises(HTTPException) as exc:
        await _resolve_create_group(_FakeSession(), _user(1), 2)  # type: ignore[arg-type]
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_create_group_superadmin_any_existing_group() -> None:
    session = _FakeSession(group_ids={9})
    assert await _resolve_create_group(session, _user(superadmin=True), 9) == 9  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc:
        await _resolve_create_group(session, _user(superadmin=True), 8)  # type: ignore[arg-type]
    assert exc.value.status_code == 400


# --- move-group permission matrix -------------------------------------------------


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(inst_routes, "write_audit", _noop)


async def _move(user: SimpleNamespace, session: _FakeSession, target_group: int) -> object:
    return await move_group(
        1,
        InstanceMoveGroup(group_id=target_group),
        _request(),
        session=session,  # type: ignore[arg-type]
        user=user,
    )


@pytest.mark.asyncio
async def test_move_superadmin_any_instance_any_group() -> None:
    inst = _inst(group_id=1)
    session = _FakeSession(instance=inst, group_ids={7})
    await _move(_user(superadmin=True), session, 7)
    assert inst.group_id == 7
    assert session.committed


@pytest.mark.asyncio
async def test_move_superadmin_unknown_target_400() -> None:
    session = _FakeSession(instance=_inst(group_id=1), group_ids=set())
    with pytest.raises(HTTPException) as exc:
        await _move(_user(superadmin=True), session, 7)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_move_admin_between_own_groups() -> None:
    inst = _inst(group_id=1)
    session = _FakeSession(instance=inst)
    await _move(_user(1, 2, admin=True), session, 2)
    assert inst.group_id == 2


@pytest.mark.asyncio
async def test_move_admin_foreign_target_403() -> None:
    inst = _inst(group_id=1)
    session = _FakeSession(instance=inst)
    with pytest.raises(HTTPException) as exc:
        await _move(_user(1, admin=True), session, 2)
    assert exc.value.status_code == 403
    assert inst.group_id == 1


@pytest.mark.asyncio
async def test_move_admin_foreign_source_404() -> None:
    # Source instance is outside the admin's groups → invisible, not forbidden.
    session = _FakeSession(instance=_inst(group_id=3))
    with pytest.raises(HTTPException) as exc:
        await _move(_user(1, 2, admin=True), session, 2)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_move_guard_rejects_role_user_but_passes_pure_superadmin() -> None:
    """The move endpoint's guard: role ``user`` is out; a pure superadmin
    (role view_only, no groups — the bootstrap seed) must get through, which
    ``require_write`` would wrongly block."""
    with pytest.raises(HTTPException) as exc:
        await require_admin_or_superadmin(_user(1))  # type: ignore[arg-type]
    assert exc.value.status_code == 403
    pure = _user(superadmin=True)
    assert await require_admin_or_superadmin(pure) is pure  # type: ignore[arg-type]


# --- in-memory connected-agents filter ---------------------------------------------


class _ScalarsResult:
    def __init__(self, ids: list[int]) -> None:
        self._ids = ids

    def scalars(self) -> list[int]:
        return self._ids


class _IdSession:
    def __init__(self, visible: list[int]) -> None:
        self._visible = visible

    async def execute(self, _stmt: object) -> _ScalarsResult:
        return _ScalarsResult(self._visible)


@pytest.mark.asyncio
async def test_connected_agents_filtered_by_group(monkeypatch: pytest.MonkeyPatch) -> None:
    connected = [
        {"instance_id": 1, "instance_name": "mine", "agent_version": "2.6.4"},
        {"instance_id": 2, "instance_name": "foreign", "agent_version": "2.6.4"},
    ]
    monkeypatch.setattr(update_mod, "hub", SimpleNamespace(list_connected=lambda: list(connected)))
    out = await update_mod.list_connected_agents(
        session=_IdSession([1]),  # type: ignore[arg-type]
        user=_user(1),
    )
    assert [a["instance_id"] for a in out] == [1]


@pytest.mark.asyncio
async def test_connected_agents_unscoped_for_machineless_clause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected = [
        {"instance_id": 1, "instance_name": "a", "agent_version": "2.6.4"},
        {"instance_id": 2, "instance_name": "b", "agent_version": "2.6.4"},
    ]
    monkeypatch.setattr(update_mod, "hub", SimpleNamespace(list_connected=lambda: list(connected)))
    out = await update_mod.list_connected_agents(
        session=_IdSession([]),  # type: ignore[arg-type]
        user=None,  # machine/unscoped principal never filters
    )
    assert len(out) == 2


# --- Instance ORM default keeps pre-scoping code paths working ----------------------


def test_instance_model_defaults_to_group_1() -> None:
    inst = Instance(name="x", slug="x", base_url="https://x", api_key_enc=b"", api_secret_enc=b"")
    # Python-side default (column default=1) applies on flush; the attribute
    # default is what create paths relied on before group_id became explicit.
    assert Instance.group_id.default.arg == 1  # type: ignore[union-attr]
    assert inst is not None
