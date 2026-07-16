# CLAUDE.md

Operating manual for coding agents working in this repository. Every rule in here is
backed by a real incident, a test, or a design record — when a rule contradicts your
instincts or your global preferences, **the rule wins**. When something here seems
wrong, verify against the code and say so; don't silently deviate.

## Project

STYLiTE Orbit — multi-firewall dashboard (OPNsense, pfSense, Securepoint UTM) for a
German MSP fleet (~70 boxes). Three deployable apps in one repo (not a monorepo —
orchestrated by `compose.yml` prod / `compose-dev.yml` dev):

- `backend/` — FastAPI + **async** SQLAlchemy on **MariaDB** (Python 3.12, `uv` + ruff)
- `frontend/` — React 18 + Vite + TypeScript strict + Tailwind + TanStack Query v5 (npm)
- `agent/` — **one stdlib-only file** (`orbit_agent.py`) running as root on
  OPNsense/pfSense (FreeBSD, **Python 3.8 floor**); WebSocket push, relay tunneling,
  signed self-update, enrollment, packet capture, PTY shell
- Sidecars: `checkmk/` (special-agent plugin) and `scripts/sign_agent.py` (Ed25519 signing)

The UI is English. `docs/agent-architecture.md` (the living design record, numbered
§sections + DR-1..DR-7) is German. Code, comments, commits: English.

## Rules that override your defaults

A generic model's reflexes are wrong here. Repo reality beats the user's global
CLAUDE.md and beats common practice:

| Your reflex | This repo |
|---|---|
| `{success, data, error, meta}` envelope | **No envelope.** Flat Pydantic models, `{"ok": true}` acks, `items/total/page/page_size` pagination |
| TDD + 80% coverage + Playwright | **Zero frontend tests by policy** (`tsc -b` is the gate); backend tests are DB-free unit tests; no coverage tooling exists |
| Many small files (200–400 lines) | `orbit_agent.py` is 5000+ lines **on purpose** (self-update swaps exactly one file); big cohesive Sections are accepted |
| black, isort, mypy, bandit | **uv + ruff only** (`ruff check` E,F,I,B,UP,SIM; `ruff format`). Don't add or run other gates |
| `alembic revision --autogenerate` | **Hand-written** sequential `NNN_*.py` migrations |
| Postgres idioms (JSONB, partial indexes, ON CONFLICT, time_bucket) | MariaDB: `INSERT IGNORE`, `FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV n * n)` bucketing, batched `DELETE … ORDER BY ts LIMIT n` |
| Add i18n / German labels for German users | UI strings hardcoded English, `en-US` locale (exception: `fmtRelative` in `lib/datetime.ts` is deliberately German — leave it) |
| `git add -A`, amend, rebase | **Forbidden** — shared working tree (see Git section) |
| "superadmin = root" | Superadmin = rights management **only**, zero instance access |

## Commands (use `just` — nothing else)

All workflows go through the `justfile`. Read it first if a recipe seems missing.

- Backend: `just backend-install` · `just backend-run` · `just backend-test` · `just backend-lint` · `just backend-fmt`
- Agent / sidecars: `just agent-test` · `just checkmk-test` · `just sign-agent` (key auto-loads from gitignored `.env`)
- Frontend: `just frontend-install` · `just frontend-dev` · `just frontend-build` · `just frontend-lint` · `just frontend-fmt`
- Stacks: `just up|down|logs` (prod, combined image) · `just dev-up|dev-down|dev-logs` (dev, bind-mounted src, hot reload)
- Release: `just release patch|minor|major` — **only when the user explicitly asks**; it's interactive (y/N), re-signs the agent, tags, pushes
- Deps changed: `just notices` regenerates THIRD-PARTY-NOTICES.md + sbom.cdx.json (license obligation, baked into the image)
- Misc: `just gen-key` (Fernet master key), `just gen-ssh-key` (Securepoint enrichment)

**There is no CI on pushes to main.** `.github/workflows/release.yml` fires only on
version tags. The local `just` gates are the *only* safety net — skipping them ships
broken code in the next tag. To retry a failed release build: `gh workflow run
release.yml -f tag=X.Y.Z`; never delete or move a pushed tag.

Dev loop: `just dev-up` → backend hot-reloads from `backend/src` bind mount, Vite HMR on
:5173, migrations auto-apply on backend container start (`alembic upgrade head` in the
container CMD / `docker/start.sh`). To apply a new migration: **restart the backend
container**, never run alembic manually (wrong-DB risk via `.env`, races the boot-time
run for its advisory lock). Never touch the `GET_LOCK` + `connection.commit()` block in
`backend/alembic/env.py` — removing the commit makes migrations re-run every boot
(real incident, commit 9767355).

## Git: shared working tree

This checkout on `main` is **shared live** with a colleague and other agent sessions.

- Stage explicit paths only: `git add <file> <file>`. Never `git add -A` / `-u` / `.`
  (would sweep others' in-flight edits and gitignored-but-present secrets).
- Never amend, rebase, or force-push. Never switch branches. Worktrees only after asking.
- Before committing: `git diff <path>` per staged file — confirm it holds only your change.
- Before committing a migration: re-check `ls backend/alembic/versions | sort | tail -1`
  — another session may have claimed your number. Exactly one alembic head, always.
- Commit format: `<type>(<scope>): <lowercase imperative>` — types
  feat|fix|chore|docs|refactor|perf|test|style|security; scopes are feature areas
  (agent, frontend, backend, hub, capture, checks, ui, security, export, firewall, …).
  No co-authored-by trailers. Fix bodies are mini postmortems: symptom → root cause →
  fix → proof (test name, lab-box evidence, or measured numbers).
- One commit = code + regression test + CHANGELOG bullet (for behavioral/user-visible
  changes). Agent commits additionally contain the `__version__` bump + refreshed `.sig`.
- `chore: bump version to X.Y.Z` commits are authored **only** by release.sh.
- Formatting/lint sweeps of unrelated files go in separate chore/style commits, never
  inside feature commits.

## Hard security invariants

1. **Group scoping on every user-facing instance query.** `scope_clause(principal)`
   for lists/aggregates, `get_instance(session, id, principal)` (→ `can_access`) for
   by-id — from `backend/src/app/auth/scope.py`. Out-of-scope answers **404, never
   403** (no existence oracle). The empty-set semantics are *inverted* and must never
   be merged: **User with zero groups sees NOTHING; ApiKey with zero bindings is
   GLOBAL**. There is **no superadmin bypass** — superadmin is rights management only.
   `None` principal = trusted internal caller (poller, hub) and is unscoped:
   `get_instance(session, id)` without the third argument **silently disables scoping**
   — always pass the principal in routes.
2. **WebSocket routes authenticate themselves.** FastAPI `Depends` gates do NOT run on
   `@router.websocket`. Every `/ws/*` route touching an instance must, in this order:
   `await ws.accept()` → feature gate (close 4403) → `_ws_authenticate(ws, session,
   write=…)` (return if None) → `get_instance(session, instance_id, user)` (close 4403
   if None) → per-instance opt-in flag → only then `hub.get(...)` (close 4404).
   Mirror `shell_websocket`/`capture_websocket` in `backend/src/app/agent_hub/routes/ws.py`.
   Regression b622b6f: `/ws/capture/{id}` shipped without this and streamed any box's
   raw traffic to any origin. Close codes: 4401 unauth, 4403 forbidden, 4404 no agent,
   4008 concurrency cap.
3. **Secrets are Fernet-encrypted at rest** (`backend/src/app/crypto/`, key =
   `DASH_MASTER_KEY`) into `*_enc` columns; decrypt only at client construction; API
   responses expose booleans (`ssh_key_set`), never values; update schemas treat
   empty/omitted as "keep existing". Audit `detail` is built from the allowlist
   `_SAFE_AUDIT_FIELDS` — extend the allowlist for new fields, never flip to a denylist.
   Agent command results pass `_redact_audit` before audit storage.
4. **Only anonymized text reaches an external LLM** (`app/llm/anonymize`, char caps in
   `logs/context.py`). Raw log content is admin-only. The anonymizer deliberately keeps
   RFC1918 IPs — don't "anonymize harder".
5. **Hub state is unscoped in-memory data.** Any endpoint iterating
   `hub.list_connected()` or `hub._last_*` must filter through
   `_visible_instance_ids(session, user)` first.
6. Privileged agent actions (mint credentials, curated params: `agent.update`,
   `gui.login`, `relay.enable`, …) get dedicated routes AND their action string added
   to `_INTERNAL_AGENT_ACTIONS` so the generic command passthrough rejects them.

## Backend conventions

- Feature packages: `app/<feature>/{routes.py, schemas.py, service.py|store.py}`;
  router `APIRouter(prefix="/<feature>", tags=[...])` registered in `create_app()` with
  `prefix="/api"`. Literal sub-paths (`/instances/defaults`) before `/{instance_id}`.
- Auth dependency ladder (`app/auth/deps.py`): `current_user` (any session) →
  `require_write` (every operational mutation) → `require_admin` (config surfaces);
  `require_superadmin` / `require_admin_or_superadmin` only for rights management.
  Machine-consumed reads: `read_principal` (session OR `orbit_` API key; API keys are
  read-only by construction). `test_role_guards.py` enumerates all routes and fails any
  mutation guarded by bare `current_user`.
- Mutations: mutate → `write_audit(action="noun.verb", result=..., source_ip=
  client_ip(request), detail=<allowlisted>)` → `await session.commit()`. Audit denied/
  error paths too. Services `flush()`, routes own `commit()`. Returning an ORM object
  after commit: `await session.refresh(obj)` first (else MissingGreenlet).
  `IntegrityError` → rollback → HTTP 409, lowercase human detail.
- Time: columns use the `UtcDateTime` TypeDecorator (never plain `DateTime`); Python
  side always `datetime.now(UTC)`. MariaDB DATETIME reads back **naive-but-UTC** — tag
  with `as_utc()`/`_iso_utc` helpers before comparing or serializing. Never remove the
  `_pin_session_utc` connect listener in `db/base.py` (incident 195e9da: "last seen: in 1h").
- Settings: env defaults in `config.py` (`DASH_` prefix), editable keys get a
  `SettingDef` in `app/settings/registry.py` and are read via `effective_settings()`
  (DB overrides), never `get_settings()`. New `DASH_` vars must be wired into
  `.env.example` + `compose.yml` + `compose-dev.yml` in the same change (incident
  9767355: a var only in dev-compose is impossible to enable in prod).
- Client IP only via `app.net.client_ip(request)`. Logging: structlog only,
  `log = structlog.get_logger("app.<module>")`, dotted event names + kwargs. No print().
- After mutating instance credentials/base_url/SSH fields: `await
  registry.invalidate(inst.id)` or polling continues with stale clients.
- Blocking/CPU work (Fernet on MB blobs, diffs) leaves the event loop via
  `asyncio.to_thread`. Notifications only via `dispatch_async()` **after** the session
  is closed/committed — never awaited on ingest/poll paths.
- Middleware: pure ASGI only (`BaseHTTPMiddleware` breaks streaming/WS).
- Process-local singletons (settings cache, LoginLimiter, export TTL cache, agent hub)
  assume ONE worker. Don't add uvicorn workers/replicas.
- Comments are load-bearing incident documentation ("Do not remove.", "Regression: …").
  Never strip them in refactors; when you add a guard, add the why-comment naming the
  failure it prevents.

## Database & migrations

- MariaDB, async-only: `AsyncSession` + `aiomysql`. Never import sync `Session`.
- Migrations: hand-written `backend/alembic/versions/NNN_snake_name.py`, `revision="NNN"`
  (zero-padded string), `down_revision="NNN-1"`, why-docstring, real `downgrade()`.
  Current head must always be exactly one. Heavy DDL must be re-runnable
  (`IF NOT EXISTS` / `IF EXISTS`) — replicas race `upgrade head` at boot. Use
  `/new-migration` to scaffold.
- Big payloads: `mysql.MEDIUMBLOB`/`MEDIUMTEXT` variants (TEXT/BLOB cap at 64KB).
  Counters/rates: `Double`, not `Float` (single precision flatlined byte counters).
- Any table pruned by time needs a **standalone index on `ts`** and batched deletes
  (`_prune_before` pattern: `DELETE … ORDER BY ts LIMIT 10000` + commit + pause).
  Incident: an unbounded DELETE gap-locked the metrics table and 500'd the API for
  ~80s every hour, flapping the whole fleet offline.
- MariaDB downgrade trap: drop FK **before** index (errors 1091/1553).
- There is **no metrics rollup table** — migration 008 dropped `metrics_5m`;
  `read_metrics` buckets the raw table on the fly. Don't recreate it.
- Scheduled jobs: function in `maintenance/jobs.py`, own session via
  `get_sessionmaker()`, idempotent, registered in `start_scheduler()` with explicit
  `id=` and `max_instances=1`, retention windows from `effective_settings()`.

## Checks, alerts, exports

- A check is a **pure, DB-free** function in `checks/evaluate.py` returning
  `ServiceCheck | None`, wired into `evaluate_checks()`. **Never emit a check for
  absent data** — return None on the no-data sentinels (swap_total_mb<=0, cores<=0,
  stratum<0, err_rate<0, empty tunnel list, service not present …). Incident c37de13:
  ipsec.service CRIT'd fleet-wide on boxes without IPsec.
- States: Checkmk convention 0=OK 1=WARN 2=CRIT 3=UNKNOWN; UNKNOWN sorts *below* WARN.
  "Could not check" is WARN, never OK, never CRIT. CPU deliberately can't CRIT.
- New check family = three registrations: `CHECK_CATEGORIES`
  (`selection/model.py`), `CATEGORY_LABELS` (`frontend/.../SelectionTree.tsx`), and —
  for colon-keyed families — `_AGG` (`checks/aggregate.py`). Keys are
  `family:stable-id` (DB id, never a user-editable name).
- Every consumer wraps results as `overlay_checks(inst, evaluate_checks(...),
  effective_settings(), now)` — staleness cap, probe checks, maintenance ceiling. All
  four surfaces (Checkmk export, Prometheus export, Alerts page, per-instance checks)
  must show identical services.
- Machine-driven exports go through `gather_many_cached` (20s TTL,
  `checks/routes.py`) — never `gather_many`/`poll_status` per request (incident
  fce8ccc: scrapes hammered every direct-poll appliance). Interactive views stay live.
- Single-measurement checks (ping-like) get flap debounce (N consecutive fails before
  CRIT, instant recovery) **and** hydrate re-seeding of streaks, or every backend
  restart fires false recovered/CRIT storms.
- Hub cache ingest (`handle_metrics`): every section write is guarded — truthy-guard
  when empty = collector failure, presence-guard when empty is legitimate
  (connectivity). Never unconditional overwrite. New sections go into `_snapshot_for`
  AND `hydrate_instance` symmetrically. Never mutate cached pydantic objects — always
  `model_copy(update={...})`.
- Prometheus: label with `instance_id`/`instance_name` (never `instance` — reserved),
  register HELP text in `_HELP` or the family is never emitted.
- Logs pipeline: agent pushes hourly; `logs/store.py` keeps 3 snapshots per
  (instance, name), `log_events` replaced per ingest. Severity rules in
  `logs/events.py` are calibrated against real prod data — real fleets have **zero
  sev≤2 lines**, never make crit-only the default anywhere.

## Agent (`agent/orbit_agent.py`) — the highest-blast-radius file

It runs as **root on customer firewalls** and updates itself. Use `/ship-agent-change`
for the full done-pipeline. The non-negotiables:

- **Bump `__version__`** (top of file) in every commit that changes the file — strictly
  newer, purely numeric dotted (`2.9.8`; a `-rc1` suffix makes the anti-rollback parser
  refuse ALL updates). Unchanged version = the fix never deploys (backend no-ops the
  push; the agent refuses same-version). Re-align to the next product release version
  when known.
- **Python 3.8 floor.** Test boxes run 3.11+, the test suite runs 3.13 — *no local gate
  catches 3.9+ runtime APIs*. `from __future__ import annotations` makes annotations
  safe; runtime calls break: `removeprefix/removesuffix`, `dict |`/`|=` merge,
  `match/case`, `functools.cache`, `zoneinfo`, `asyncio.to_thread`,
  `from datetime import UTC`, `math.lcm/isqrt`, `int.bit_count`. Incidents: removesuffix
  silenced a pfSense agent; `datetime.UTC` crash-looped 3.8 agents (recovery = manual
  scp per box, because a crash-looping agent cannot self-update).
- **Stdlib only, one file.** No pip deps, no second module, no Linux-isms (no /proc,
  no systemd, no GNU flag spellings — FreeBSD `ping -t/-S`, no `timeout` binary).
- **Re-sign in the same commit**: `just sign-agent` then verify; stage
  `agent/orbit_agent.py.sig` with the `.py`. A stale served .sig makes the whole fleet
  reject all future updates. (Dev stack auto-re-signs via `_sign-if-key` — that .sig
  diff is legitimate, commit it with the agent change, don't revert it.)
- New collector: zero-arg `collect_<name>()`, registered as a **name string** pair in
  `_SNAPSHOT_SECTIONS` (globals()-resolved so tests can monkeypatch); extend
  `test_collect_timing._SECTIONS`/`_STUB_FN`; interval-throttled gates must be zeroed
  in the `refresh.full` handler or "Refresh now" silently serves stale data. Per-item
  try/except inside multi-item collectors — a raising collector blanks the whole push.
- New command: sync `_cmd_<name>(params) -> {"success": bool, "output": str, ...}` in
  `_COMMANDS` (executor-run, must not touch the WS); actions needing the WebSocket or
  process lifecycle are inline branches in `_listen_loop_inner`.
- Platform dispatch via `detect_platform()`; pfSense PHP must `function_exists`-guard
  2.7+ accessors (CE 2.6 fleet!) and guard `write_config()` on a populated `$config`;
  anything registered to run at boot keeps its `>/dev/null 2>&1` redirect (removing it
  **hangs pfSense boot** — incident b218830).
- Secrets on disk via `_write_private()`; root-run /tmp scripts via
  `_write_root_script()` (fixed /tmp names = symlink attack on FreeBSD).
- `run-agent.sh`, `rc.d/orbit_agent`, `install.sh` are **outside the self-update path**
  — changes there need an explicit manual rollout plan; prefer self-healing from inside
  orbit_agent.py. Supervisor contract: exit 42 = update respawn; marker + <60s runtime
  + `.bak` = rollback. Don't rename hello/welcome frames or marker files.
- Security gates are re-read per use (function call), never captured at import
  (incident 37d74e1). Tunnel destinations are pinned on-box; never honor
  server-supplied host/port. IPsec is never restarted via `service strongswan restart`
  (drops every tunnel) — `configctl ipsec reload` / `ipsec_configure()`.
- Rollout: canary ONE box (`POST /instances/{id}/agent/update`), confirm probation
  passes and the new version appears in `/agents/connected`, then update-all.

## Frontend conventions

- **Imports are relative** (`../lib/api`). The `@/*` tsconfig alias is a trap: it
  type-checks but `vite build` fails (no `resolve.alias` configured). Zero files use it.
- All HTTP through the `api` wrapper (`lib/api.ts` — cookie + Bearer fallback, 401 →
  `dash:unauthorized` broadcast, error flattening). Only sanctioned bypass:
  `<a href="/api/...">` downloads and Blob URLs. Errors render via
  `apiErrorText(e, fallback)`.
- Server state only in TanStack Query v5 (object signature). `refetchInterval` tiers:
  10s live agent/hub status, 30s standard, 60s metrics/heavy, 300s slow; <10s only for
  an in-flight user-initiated operation. Reuse shared query keys (`["instances"]`,
  `["agents-connected"]`, `["instance", id]`, …).
- Pages: `src/pages/*Page.tsx` routed in `App.tsx` inside `<ProtectedRoute>` (+
  `<Layout>` unless full-screen). Instance-tab content: `src/components/*Section.tsx`
  taking `instanceId: number`; register in the `TABS` const + device-capability filter
  in `InstanceDetailPage.tsx`. Sections holding non-query per-instance state get
  `key={nid}` at the render site (regression 397b4ff: box A's capture results shown
  under box B).
- Security is the backend's 403. Frontend does exactly three things: hide the nav link
  by role, gate queries with `enabled:`, render a readable fallback/redirect on 403.
- WS clients: `wss://${window.location.host}/api/ws/...` — session cookie + backend
  Origin allowlist, **never a token in the URL**; map close codes 4401/4403/4404 to
  readable text; effect cleanup nulls `onopen/onmessage/onclose` **before** `ws.close()`
  (StrictMode double-mount ghost socket).
- Backend WS routes must live under `/api/ws/` — nginx only upgrades that prefix in
  prod; dev Vite proxies all of `/api`, so a mis-prefixed route is a prod-only failure.
- Types are manual mirrors of backend Pydantic schemas: shared ones in `lib/types.ts`
  ("update both sides together"), single-consumer payloads component-local. `tsc -b`
  is the contract check.
- Component files export only components (Fast Refresh); hooks/contexts/helpers in
  JSX-free `src/lib/*.ts`. Timestamps via `lib/datetime.ts` helpers, relative body +
  absolute `title=` tooltip. Styling: inline Tailwind, slate-950/900/800 surfaces,
  emerald accent, amber=warn red=crit; icons lucide-react; charts recharts. Dark-only.

## Docs & CHANGELOG

- `CHANGELOG.md` follows Keep-a-Changelog: every user-visible change adds a bullet
  under `## [Unreleased]` **in the same commit**, symptom-first operator prose.
  `just release` only promotes the section — it never generates entries. Never edit
  dated sections. Never hand-write bump commits.
- `UPCOMING.md` = non-committal idea backlog; never implement from it unprompted;
  prune items when they ship. Known-gap backlog lives in `docs/agent-architecture.md`
  §11/§14. Don't recreate TODO.md.
- Significant agent architecture changes append to `docs/agent-architecture.md`
  (German, with live-verification evidence), never rewrite its history.

## Named mistakes a model will make here

Each has happened or nearly happened. Name → wrong move → rule.

**Security**
1. *Naked WS route* — new `/ws/...` goes accept()→hub.get(), trusting Depends. → Follow
   the exact WS order (invariant 2) + regression test asserting the hub was never
   consulted on an unauthenticated connect.
2. *Two-arg get_instance* — `get_instance(session, id)` compiles, passes tests, and
   disables scoping (None principal = internal). → grep new routes for two-arg calls.
3. *Scope "simplification"* — merging the ApiKey/User branches in `scope.py` or adding
   a superadmin bypass. → scope.py is change-frozen; `test_group_scoping.py` must keep
   asserting both empty-set semantics and no bypass.
4. *403 for out-of-scope* — creates an existence oracle. → Same 404 for missing and
   forbidden.
5. *Secret in response/log/audit* — returning key material "for convenience". →
   booleans only (`ssh_key_set`), allowlisted audit detail, `_redact_audit` on command
   results.

**Agent**
6. *Silent non-deploy* — agent edited, `__version__` unchanged; all tests green, fix
   never reaches any box. → version bump in the same diff, always.
7. *3.9+ runtime call* — passes every local gate, bricks the 3.8 pfSense fleet on
   self-update. → scan the diff against the API list above; `/ship-agent-change` runs it.
8. *Stale .sig* — fleet rejects all future updates. → `just sign-agent` + `--verify`,
   .sig staged in the same commit.
9. *Supervisor edit "deploys itself"* — run-agent.sh/rc.d never ride self-update. →
   explicit rollout plan or solve it inside orbit_agent.py.
10. *Lab-box survivorship* — works on 2.8.1/3.11 lab boxes, breaks the 2.6/3.8 fleet.
    → `function_exists` shims, version-agnostic interpreter resolution, state the
    tested version range in the commit body.

**Database**
11. *Autogenerated migration* — hash revision IDs, possibly wrong-DB diff. → hand-write
    `NNN_*.py`; `/new-migration`.
12. *Second alembic head* — another session took your number. → re-check the tail +
    single head immediately before committing.
13. *Manual `alembic upgrade head`* — can hit the prod-copy DB on :3307 or race the
    boot-time run. → restart the dev backend container instead.
14. *Naive datetime* — comparing/serializing MariaDB datetimes raw, or "cleaning up"
    `_pin_session_utc`. → `UtcDateTime` columns, `as_utc()` helpers, listener stays.
15. *Unbounded DELETE* — gap-locks the table, fleet flaps offline. → batched
    oldest-first deletes + standalone ts index.

**Checks / data plane**
16. *CRIT on absent feature* — "no data → alarm" monitoring reflex. → no-data branch
    returns None + a not-configured test.
17. *TTL-cache bypass* — new export live-polls appliances per scrape. →
    `gather_many_cached` for anything machine-cadenced.
18. *Cache wipe on empty push* — one failed collector erases known-good state and fires
    alert pairs. → guarded section writes (truthy vs presence), documented per section.
19. *Alert without debounce* — one dropped ping pages someone. → streak debounce +
    hydrate re-seed.
20. *Forgotten overlay / unregistered family* — new surface disagrees with the other
    four; Checkmk explodes into per-item services. → `overlay_checks` wrapper + the
    three-place registration.

**Frontend**
21. *`@/` import* — type-checks, breaks `vite build`. → relative imports; `just
    frontend-build` before done.
22. *Raw fetch()* — loses auth fallback, 401 broadcast, error flattening. → `api.*` only.
23. *German label creep* (or "fixing" fmtRelative's deliberate German). → English
    labels, en-US locale; leave fmtRelative alone.
24. *Missing `key={nid}`* — one customer's data rendered under another's instance page.
25. *Inventing test/build infra* — vitest/Playwright/code-splitting/envelope scaffolds
    the maintainer will not run. → the gates are exactly `frontend-lint` + `frontend-build`.

**Process**
26. *`git add -A` / amend / branch switch* — clobbers the shared tree. → explicit paths,
    roll forward, stay on main.
27. *Changelog theater* — editing released sections, hand-writing bump commits, running
    release unprompted. → your job ends at a non-empty `[Unreleased]`.
28. *WS route outside `/api/ws/`* — works in dev, 502s in prod nginx.
29. *Stale notices* — runtime dep changed without `just notices` (license obligation).
30. *Trusting this file over the code* — docs drift. → verify, then fix the doc in a
    `docs:` commit.

## Quality bars per deliverable (checkable)

**Backend change** — done when:
- [ ] `just backend-lint` exits 0 · `just backend-test` exits 0
- [ ] Model changed → new sequential `NNN_*.py` migration, exactly one alembic head
- [ ] New instance-data endpoint → `scope_clause`/`get_instance(…, principal)` present;
      out-of-scope test asserting 404/None exists
- [ ] Mutation → correct dep from the ladder (test_role_guards stays green), audit
      before commit, refresh before returning ORM
- [ ] Behavioral fix → regression test in the same commit that **fails on pre-fix
      code**, docstring naming the incident
- [ ] User-visible → `[Unreleased]` bullet in the same commit

**Backend tests** — done when:
- [ ] DB-free house style: no conftest.py, no engine/sqlite; `_FakeSession` +
      `SimpleNamespace` principals; external HTTP via respx; SQL asserted as
      captured/compiled text
- [ ] TestClient tests patch `start_scheduler`/`ensure_admin`/`ensure_superadmin`
      first; WS tests patch `get_sessionmaker` in BOTH `routes.ws` and `hub`
- [ ] Env-var tests clear `get_settings.cache_clear()` (+ `_fernet.cache_clear()`)
- [ ] Suite stays fast (whole backend suite runs in single-digit seconds)

**Agent change** — done when `/ship-agent-change` passes end-to-end:
- [ ] `__version__` bumped (strictly newer, numeric dotted) in the same diff
- [ ] `just agent-test` exits 0 (never raw pytest — asyncio_mode comes from the recipe)
- [ ] Diff clean of 3.9+ runtime APIs; no new non-stdlib import; no Linux-isms
- [ ] `just sign-agent` run, `--verify` OK, `.sig` staged with the `.py`
- [ ] New collector/command wired per the checklists above; FreeBSD commands verified
      on a lab box; `[Unreleased]` bullet present; version noted in the commit message

**Frontend change** — done when:
- [ ] `just frontend-lint` exits 0 · `just frontend-build` exits 0 (the only gates)
- [ ] `git diff --name-only` shows no unrelated Prettier churn; no console.log in diff
- [ ] Types mirror updated in the same change; English labels; refetch tier from the
      table; `key={nid}` where sections hold per-instance state

**New check/export** — done when:
- [ ] No-data branch returns None + not-configured test
- [ ] Family registered in all three places (colon families also in `_AGG`)
- [ ] All four surfaces show the identical service (via `overlay_checks`)
- [ ] Machine paths through `gather_many_cached`; flap-prone checks debounced +
      hydrate-re-seeded

**Commit** — done when:
- [ ] `<type>(<scope>): lowercase imperative`; fix body = symptom → cause → fix → proof
- [ ] Only explicitly named paths staged; changelog rides along when user-visible

**Release** (only on explicit user request) — preflight:
- [ ] Tree clean; `[Unreleased]` non-empty; `sign_agent.py --verify` OK
- [ ] `just backend-lint && just backend-test && just agent-test && just checkmk-test
      && just frontend-build` all green (there is no CI to catch you)
- [ ] Run `just release <type>`, answer its interactive prompt; expect one bump commit
      + annotated tag; CI publishes images

**Live verification** (agent behavior, firewall APIs, tunnels, firmware): use
`/lab-verify`. Lab: opn1=10.20.1.198, opn2=10.20.1.199 (OPNsense 2.6.11),
pf1=10.20.1.200 (pfSense CE 2.8.1), pf2=10.20.1.217 (pfSense CE 2.7.2, reusable
series-upgrade tester — full upgrade+rollback cycle proven, docs §26),
pf3=10.20.1.197 (pfSense Plus 22.05, real python-3.8 box, repos EOL-broken); ssh
port 9922 (root shell is tcsh); GUI/API on :4444. Shared with other developers —
record what you verified in the commit body.

## When uncertain: escalation rules

**Stop and ask the user before:**
- Editing semantic content of the change-frozen zones: `auth/scope.py`,
  `alembic/env.py` connection handling, `db/base.py` listeners, `crypto/`,
  `_UPDATE_PUBKEY`/anti-rollback/probation logic in the agent, bootstrap-account logic.
- Running `just release`, pushing tags, or anything that publishes (Docker Hub/GHCR).
- Creating a worktree or touching any branch (CLAUDE.local.md rule).
- Changing `run-agent.sh` / `rc.d/` / `install.sh` (no self-update path — needs a
  fleet rollout plan).
- Rotating/altering `DASH_MASTER_KEY` or the agent signing key — both are
  fleet-bricking operations.
- Adding a DB dependency to tests, a new lint/test framework, uvicorn workers, an API
  response envelope, or an i18n layer — all are deliberate non-choices here.
- Destructive operations on the lab boxes (reboot, firmware apply, uninstall) when
  others might be using them; copy `/tmp` evidence off a box before any reboot.
- Anything involving the prod-DB copy on :3307 beyond read-only queries; never commit
  `compose-db2.yml` or echo its passwords.

**Decide yourself (don't ask) when:**
- The repo already shows the pattern — copy the neighboring file/test/commit style.
- A gate fails because of your change — fix it and re-run; never skip/xfail to pass.
- CLAUDE.md and the code disagree — trust the code, note the doc drift.

**Default-deny when unsure about security semantics:** pick the stricter reading
(scoped, 404, write-gated, audited), implement it, and flag the assumption in your
summary and the commit body — assumptions the user hasn't confirmed are called out,
not buried.

**If you find a security hole:** stop feature work, write the failing regression test,
fix it, grep for the same pattern elsewhere (the b622b6f fix pattern), add a CHANGELOG
`### Security` entry, and say clearly what was exposed and since when.

@CLAUDE.local.md
