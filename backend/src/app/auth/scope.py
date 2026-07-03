"""Instance-visibility scoping: users only see instances of their groups.

Two mechanisms, one policy (see docs in app.db.models.Group):

- ``scope_clause(principal)`` — WHERE clause for list/aggregate queries.
- ``can_access(principal, inst)`` — membership assertion for by-id fetches and
  in-memory sources (connected-agents hub, WS tunnel).

Machine principals are unscoped: ``None`` marks internal callers (poller,
hub hydrate, agent WS) and ``ApiKey`` keeps the read-only orbit_ keys global
(Checkmk export — per-key group binding is a deliberate follow-up). There is
NO superadmin bypass: superadmin grants rights management, not instance
access; a pure superadmin without memberships sees zero instances.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.sql.elements import ColumnElement

from app.db.models import ApiKey, Instance, User

# Route principals: a session user, an orbit_ API key, or an internal caller.
Principal = User | ApiKey | None


def scope_clause(principal: Principal) -> ColumnElement[bool] | None:
    """WHERE clause limiting ``Instance`` rows to the principal's groups.

    ``None`` means unscoped (machine context) — callers skip the clause. A user
    with zero groups gets ``false()``: zero instances, not all.
    """
    if principal is None or isinstance(principal, ApiKey):
        return None
    ids = principal.group_id_set
    if not ids:
        return sa.false()
    return Instance.group_id.in_(ids)


def can_access(principal: Principal, inst: Instance) -> bool:
    """Membership assertion for an already-loaded instance."""
    if principal is None or isinstance(principal, ApiKey):
        return True
    return inst.group_id in principal.group_id_set
