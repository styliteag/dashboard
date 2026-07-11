---
name: new-scoped-endpoint
description: Scaffold a new backend endpoint (REST or WebSocket) with this repo's security invariants baked in — auth-dependency ladder, group scoping, 404-not-403, audit ordering, DB-free tests including the mandatory out-of-scope negative, and the frontend wiring. Use whenever adding or reviewing an API route that touches instances or mutates state.
---

# /new-scoped-endpoint

Every cross-tenant leak this repo has ever had came from skipping one line of this
recipe (b622b6f: an unauthenticated WS streamed any box's raw traffic to any origin).
Pick the matching template, fill it, then run the checklist.

## 0. Decide the shape

| The endpoint… | Template |
|---|---|
| reads data, humans consume it | REST read (`current_user`) |
| reads data, Checkmk/Prometheus/scripts consume it | REST read (`read_principal`) + `gather_many_cached` if it polls appliances |
| changes anything | REST mutation (`require_write` ladder + audit) |
| streams (terminal, capture, live logs) | WebSocket (special rules — Depends does NOT run) |
| makes the agent do something | REST mutation + agent command (see `/ship-agent-change` Gate 4) |

## 1. REST template

Location: `backend/src/app/<feature>/routes.py` on that feature's
`APIRouter(prefix="/<feature>", tags=["<feature>"])`; new features register in
`create_app()` with `prefix="/api"`. Literal sub-paths (`/defaults`) BEFORE
`/{instance_id}` routes.

```python
@router.get("/{instance_id}/thing", response_model=ThingOut)
async def get_thing(
    instance_id: int,
    user: User = Depends(current_user),          # see ladder below
    session: AsyncSession = Depends(get_session),
) -> ThingOut:
    inst = await get_instance(session, instance_id, user)   # THREE args — always
    if inst is None:
        raise HTTPException(404, "not found")    # 404, never 403 (no existence oracle)
    ...
```

**Auth-dependency ladder** (`app/auth/deps.py`) — pick the *lowest* sufficient rung:
- `current_user` — any session, read-only human endpoints
- `read_principal` — reads that machines consume (session OR `orbit_` API key;
  keys are read-only by construction). Fetch rows via
  `list_instances(session, principal)` so key group-binding applies for free.
- `require_write` — every operational mutation (roles admin|user, excludes view_only)
- `require_admin` — configuration surfaces
- `require_superadmin` / `require_admin_or_superadmin` — rights management only.
  Superadmin has NO instance access; never use it to gate instance data.

`test_role_guards.py` walks the live app and fails any mutating route guarded by bare
`current_user` — so a wrong rung fails the suite, not review.

**Scoping — the two primitives, nothing else:**
- Lists/aggregates: `stmt = stmt.where(clause)` for `clause := scope_clause(principal)`
  when not None. Never merge the User/ApiKey branches or add a superadmin bypass —
  User with zero groups sees NOTHING, ApiKey with zero bindings is GLOBAL.
- By-id: `get_instance(session, id, principal)` — **the 2-arg form compiles and
  silently disables scoping** (None principal = trusted internal caller). In routes,
  always pass the principal.
- In-memory hub data (`hub.list_connected()`, `hub._last_*`) bypasses every WHERE
  clause — filter through `_visible_instance_ids(session, user)` first.

**Mutation extras, in this order:**

```python
    # 1. mutate (service does flush())
    # 2. audit — same session, BEFORE commit, allowlisted detail only:
    await write_audit(session, action="thing.update", result="ok",
                      user_id=user.id, target_type="instance", target_id=inst.id,
                      source_ip=client_ip(request), detail={...})
    # 3. commit, 4. refresh if returning the ORM object:
    await session.commit()
    await session.refresh(obj)
    return obj
```

- Audit denied/error paths too (`result="denied"|"error"`, reason in detail).
- `IntegrityError` → `rollback()` → HTTP 409 with lowercase human detail.
- Credentials/base_url/SSH changed → `await registry.invalidate(inst.id)`.
- Agent command results into audit detail only via `_redact_audit`.

**Response shape:** flat Pydantic model (`ConfigDict(from_attributes=True)` when
serializing ORM), `{"ok": True}` for trivial acks, `items/total/page/page_size` for
pagination. NO `{success,data,error}` envelope — the frontend parses flat models.
Secrets never appear in responses — existence booleans only (`ssh_key_set` pattern).

**Machine-cadence rule:** anything scraped/pulled on a timer that spans multiple
direct-poll instances fetches via `gather_many_cached(rows)` (shared 20s TTL in
`checks/routes.py`) — never `gather_many`/`poll_status` per request.

## 2. WebSocket template

FastAPI `Depends` gates do NOT run on `@router.websocket`. Auth is fully manual and
the ORDER is the security boundary. Path must start `/ws/` on a router mounted at
`/api` — prod nginx only upgrades `/api/ws/` (a mis-prefixed route works in dev and
502s in prod).

```python
@router.websocket("/ws/thing/{instance_id}")
async def thing_websocket(ws: WebSocket, instance_id: int) -> None:
    await ws.accept()
    if not _feature_enabled():                       # global gate BEFORE auth:
        await ws.close(code=4403); return            # don't reveal the capability
    async with get_sessionmaker()() as session:
        user = await _ws_authenticate(ws, session, write=True)  # closes on failure
        if user is None:
            return
        inst = await get_instance(session, instance_id, user)
    if inst is None:
        await ws.close(code=4403); return
    if not inst.thing_enabled:                       # per-instance opt-in, if any
        await ws.close(code=4403); return
    agent = hub.get(instance_id)                     # ONLY NOW touch the hub
    if agent is None:
        await ws.close(code=4404); return
    # audit the open in a fresh session, then stream
```

- `write=True` for anything that bridges to the box (tunnel/shell/capture) —
  mirrors the REST `require_write`.
- Close codes: 4401 unauthenticated · 4403 forbidden/origin/scope/disabled ·
  4404 agent not connected · 4008 concurrency cap.
- Tunnel-style streams: `queue = hub.open_tunnel(stream)` **BEFORE** sending the
  agent the `op:open` frame (else early frames drop); pumps under
  `asyncio.wait(..., return_when=FIRST_COMPLETED)`; `finally:` always
  `hub.close_tunnel(stream)` + send `{"op":"close"}` under
  `contextlib.suppress(Exception)` — verify no orphan process on the box after
  viewer close (`/lab-verify`).
- Long-lived interactive streams: keepalive ping < 60s proxy floor; only real user
  payload resets the idle timer (not pongs); idle + max-lifetime watchdogs.

## 3. Tests (DB-free house style, same commit)

No conftest.py, no database, no sqlite. Copy the pattern of the nearest neighbor file.

Mandatory for any endpoint returning instance data:
- **Out-of-scope negative**: principal outside the instance's group → 404/None/close.
  Pattern: `backend/tests/test_group_scoping.py`.
- Lists: a filtered-vs-unfiltered pair (scoped user sees subset; unbound ApiKey sees all).

Mandatory for WS endpoints (pattern: `test_agent_ws.py`):
- In-process `TestClient.websocket_connect` against the real app; patch
  `start_scheduler`/`ensure_admin`/`ensure_superadmin` to no-ops and
  `get_sessionmaker` in BOTH `app.agent_hub.routes.ws` AND `app.agent_hub.hub`.
- Unauthenticated connect closes AND — monkeypatch `hub.get` to record calls —
  assert the hub was **never consulted** (proves ordering, not just denial).

Mutations: an autouse `_no_audit` fixture (async no-op over `routes.write_audit`) or
the route's audit helper patched; role coverage comes free via `test_role_guards.py`.

For bug fixes: the test must fail on pre-fix code and its docstring names the
incident ("Regression: …").

## 4. Frontend wiring (if the endpoint has a UI consumer)

- Call through `api.get/post/put/patch/del<T>` (`lib/api.ts`) — never raw `fetch()`.
- Type mirror: shared multi-consumer payloads in `lib/types.ts`, single-consumer
  payloads component-local; field names snake_case exactly as the backend emits;
  nullable fields `X | null`. Update both sides in the same change — `tsc -b` is the
  only contract check.
- `refetchInterval` tier: 10s live agent/hub liveness · 30s standard · 60s
  metrics/heavy · 300s slow · sub-10s only for an in-flight user-started operation.
- Instance tab? Register in `TABS` + capability filter in `InstanceDetailPage.tsx`;
  Section takes `instanceId: number`; add `key={nid}` at the render site if it holds
  non-query per-instance state.
- WS client: `wss://${window.location.host}/api/ws/...`, cookie-authenticated —
  **no token in the URL**; map 4401/4403/4404 to readable text; cleanup nulls
  `onopen/onmessage/onclose` before `ws.close()`.
- English labels, `en-US` locale, timestamps via `lib/datetime.ts`.

## 5. Done checklist

- [ ] Auth rung is the lowest sufficient one; `just backend-test` (incl.
      test_role_guards) green
- [ ] `scope_clause`/3-arg `get_instance` present; `grep -n 'get_instance(session, [a-z_]*)$'`
      style check shows no 2-arg calls in the new code; hub reads filtered
- [ ] Out-of-scope → 404 (REST) / close 4403 (WS); negative test exists
- [ ] Mutations: audit → commit → refresh order; secrets allowlisted/redacted
- [ ] WS: order verified by reading the code top-to-bottom; path under `/api/ws/`;
      hub-never-consulted test
- [ ] Machine-cadence paths through `gather_many_cached`
- [ ] Frontend types mirrored; `just frontend-lint` + `just frontend-build` green
- [ ] `just backend-lint` green; CHANGELOG `[Unreleased]` bullet in the same commit
- [ ] Live-verified where it touches real boxes (`/lab-verify`), evidence in the
      commit body
