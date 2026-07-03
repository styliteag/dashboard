"""Instance-visibility scoping: users only see instances of their groups.

Two mechanisms, one policy (see docs in app.db.models.Group):

- ``scope_clause(principal)`` — WHERE clause for list/aggregate queries.
- ``can_access(principal, inst)`` — membership assertion for by-id fetches and
  in-memory sources (connected-agents hub, WS tunnel).

Machine principals: ``None`` marks internal callers (poller, hub hydrate,
agent WS) and is always unscoped. ``ApiKey`` principals honor their group
binding (``apikey_groups``): a bound key only sees its groups' instances, an
UNBOUND key stays global (backward compat). There is NO superadmin bypass:
superadmin grants rights management, not instance access; a pure superadmin
without memberships sees zero instances.

!!! The empty set means OPPOSITE things per principal type — never merge the
branches: ApiKey with zero bindings = GLOBAL; User with zero memberships =
NOTHING.
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
    if principal is None:
        return None
    ids = principal.group_id_set
    if isinstance(principal, ApiKey):
        # INVERTED vs the User branch below: an ApiKey with ZERO bindings is
        # GLOBAL (keys predate groups), while a User with zero memberships
        # sees NOTHING. Do not "simplify" these into one branch.
        return Instance.group_id.in_(ids) if ids else None
    if not ids:
        return sa.false()
    return Instance.group_id.in_(ids)


def can_access(principal: Principal, inst: Instance) -> bool:
    """Membership assertion for an already-loaded instance."""
    if principal is None:
        return True
    if isinstance(principal, ApiKey):
        ids = principal.group_id_set  # empty = global, see scope_clause
        return not ids or inst.group_id in ids
    return inst.group_id in principal.group_id_set
