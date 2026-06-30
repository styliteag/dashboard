"""Route-level guard enforcement for the fixed user roles.

The whole security boundary of the ``view_only`` role is that it cannot reach a
mutating endpoint. A hand audit of "which routes use ``require_write``" rots:
miss one today and ``view_only`` writes through it; every *future* mutating route
added with bare ``current_user`` silently defaults to writable.

So instead of trusting a manual sweep, this test enumerates the live app and
asserts the invariant directly: every human-authenticated mutating route depends
on ``require_write`` or ``require_admin`` — never bare ``current_user``.
"""

from __future__ import annotations

from fastapi.routing import APIRoute

from app.auth.deps import current_user, read_principal, require_admin, require_write
from app.main import create_app

# Self-service routes a logged-in account of ANY role may call on itself — these
# legitimately sit on bare ``current_user`` and are exempt from the write gate.
SELF_SERVICE_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/auth/logout"),
        ("POST", "/api/auth/password"),
        # Every signed-in account manages its own 2FA regardless of role.
        ("POST", "/api/auth/mfa/webauthn/manage/options"),
        ("POST", "/api/auth/mfa/webauthn/manage/verify"),
        ("DELETE", "/api/auth/mfa/passkeys/{cred_id}"),
    }
)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _dependency_calls(dependant: object) -> set[object]:
    """Flatten the full nested dependency tree of a route into its callables."""
    calls: set[object] = set()
    stack = [dependant]
    while stack:
        dep = stack.pop()
        call = getattr(dep, "call", None)
        if call is not None:
            calls.add(call)
        stack.extend(getattr(dep, "dependencies", []))
    return calls


def _mutating_routes() -> list[tuple[str, str, set[object]]]:
    app = create_app()
    out: list[tuple[str, str, set[object]]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        write_methods = set(route.methods or set()) - _SAFE_METHODS
        if not write_methods:
            continue
        calls = _dependency_calls(route.dependant)
        for method in sorted(write_methods):
            out.append((method, route.path, calls))
    return out


def test_mutating_routes_block_view_only() -> None:
    """No mutating route may be guarded by bare ``current_user``.

    A route is acceptable if it requires ``require_write``/``require_admin`` (human
    write gate), is on the self-service allowlist, or is machine-authed (uses
    neither ``current_user`` nor a human gate — e.g. agent enrollment, login).

    ``read_principal`` counts as authed-but-ungated: it admits any logged-in user
    (incl. ``view_only``) and only rejects API keys on non-GET, so a mutating route
    guarded by it would let ``view_only`` write through.
    """
    offenders: list[str] = []
    for method, path, calls in _mutating_routes():
        if (method, path) in SELF_SERVICE_ALLOWLIST:
            continue
        gated = require_write in calls or require_admin in calls
        authed = current_user in calls or read_principal in calls
        if authed and not gated:
            offenders.append(f"{method} {path}")

    assert not offenders, (
        "mutating routes guarded by bare current_user (view_only could write through "
        "them) — switch to require_write/require_admin:\n  " + "\n  ".join(sorted(offenders))
    )
