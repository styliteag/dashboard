# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Hub observability page (backend self-monitoring).** New admin-only page
  (nav "Hub", `/hub`) backed by `GET /api/hub/stats`: connected agents (with
  per-connection push count and last-push time), a pushes-per-minute chart for
  the last hour, and hub counters (connects/disconnects, auth failures, bad
  JSON frames, handler/WS errors, unknown message types). All numbers are
  in-memory since backend start — a restart resets them, and the page says so.
  The agent list is group-scoped like every other instance surface.

## [2.7.12] - 2026-07-05

### Added

- **Browser terminal for agent-less Securepoint boxes (over SSH).** The terminal
  now works for Securepoint UTM instances that have SSH enrichment configured: the
  backend opens a host-key-verified interactive PTY to the box via asyncssh and
  bridges it to the same xterm.js terminal. `shell_websocket` picks the transport
  automatically (connected agent → agent PTY; else SSH). Same gating (per-instance
  `shell_enabled` + global + write/MFA), and fail-closed on an unpinned host key.
  The Terminal button/icon now appears for SSH-reachable Securepoint boxes too.

## [2.7.11] - 2026-07-05

## [2.7.10] - 2026-07-05

## [2.7.9] - 2026-07-05

### Security

- Browser terminal + GUI-proxy tunnel hardening (agent 2.7.12): both WebSocket
  routes now require a write role plus full session validation (Origin allowlist,
  account-disabled and MFA checks, password-version) — a `view_only` account can
  no longer open a root shell or a GUI bridge. Arming a box's terminal
  (`shell_enabled`) is admin-only. The agent-side gate is on by default (the
  dashboard is the gate, same trust model as the GUI tunnel — works fleet-wide with
  no per-box config); a box operator can hard-disable one box with
  `ORBIT_AGENT_SHELL=0`. Added concurrency caps (5/user, 5/box), an idle timeout and max session
  lifetime, PTY-output backpressure, stream-id audit correlation, and optional
  capped session recording (`DASH_SHELL_RECORD_DIR`).

### Fixed

- **Migrations were silently rolled back since 2.7.6** (visible as migration 035
  re-running on every boot and its Auto-Login → Terminal backfill never landing).
  The `GET_LOCK` serialization added in 2.7.6 opened an implicit SQLAlchemy
  transaction on the migration connection; Alembic then treated the transaction
  as caller-managed and never committed, so closing the connection rolled back
  the version stamp and all data migrations — only DDL survived via MariaDB's
  implicit commit. env.py now ends that transaction before Alembic configures.
  Self-healing on upgrade: the pending 035 run stamps and backfills correctly.
- The browser terminal was impossible to enable in prod: `compose.yml` did not
  pass `DASH_SHELL_ENABLED` through to the app container (only `compose-dev.yml`
  did), so the global gate was always off. Now wired through (default false) and
  documented in `.env.example`.

## [2.7.8] - 2026-07-04

### Added

- **Experimental (SPIKE, off by default): browser terminal to a firewall.** A
  root PTY on the box, streamed through the agent WebSocket to an xterm.js
  terminal (agent 2.7.11, see agent-architecture.md §22). Opens in its own browser
  tab (open several for several independent shells). The agent execs root's own
  login shell exactly as sshd would, so the box shows its **native console menu**
  (pfSense `rc.initial`, OPNsense `opnsense-shell`) rather than a bare prompt. The
  socket has a server-side keepalive so idle sessions survive proxy idle timeouts.
  This is arbitrary root RCE, so it is gated: `DASH_SHELL_ENABLED` (backend,
  default false) is the only server-side gate; `ORBIT_AGENT_SHELL=0` hard-disables
  on the box. Every session open/close is audited with the acting user and source
  IP. Gated per instance too (Edit instance → "Terminal (root shell)"); migration
  035 turns it on for boxes that already have WebUI Auto-Login enabled. A terminal
  icon sits next to the WebGUI icon in the instance list and the VPN, Connectivity,
  Alerts and Firmware overviews. Not production-ready — see the "offen vor Merge"
  list in §22.

### Changed

- KPI tiles (Total/Online/Offline etc.) on the Instances, VPN, Connectivity and
  Firmware compliance overviews are now clickable and filter the list below;
  clicking an active tile (or Total) clears the filter.
- VPN overview now opens on the **Disconnected** filter by default — problems
  first; one click on "Tunnels total" or "All" shows everything.

## [2.7.7] - 2026-07-04

### Changed

- Agent 2.6.5: metrics-push phase is randomized across the push interval and
  reconnects get 0–5s jitter. After a backend restart the whole fleet used to
  reconnect and then push in the same second every cycle (lockstep INSERT
  spikes on the dashboard DB); pushes now spread evenly across the interval.

### Fixed

- Standalone `ts` indexes on `ipsec_tunnel_events` and `check_events`
  (migration 034): their daily retention prunes had the same
  full-scan/next-key-lock pattern fixed for `metrics` in 2.7.4 — preventive,
  both tables are small transition logs today.

## [2.7.6] - 2026-07-04

### Fixed

- **Upgrade to 2.7.5 could crash-loop the app container** on deployments with
  multiple replicas or where the orchestrator killed the container during the
  minutes-long `ix_metrics_ts` index build: the index existed but
  `alembic_version` was never stamped, so every boot retried migration 033 and
  died with `1061 Duplicate key name 'ix_metrics_ts'`. Migration 033 now uses
  MariaDB `CREATE INDEX IF NOT EXISTS` and is safe to re-run.
- Concurrent `alembic upgrade head` runs (multi-replica boots) are now
  serialized via a MariaDB advisory lock (`GET_LOCK`) in the Alembic env —
  Alembic has no built-in migration lock on MySQL.
- `compose.yml`: app healthcheck `start_period` raised 30s → 600s so long
  boot-time migrations aren't killed mid-DDL by health-based restarts.

## [2.7.5] - 2026-07-04

## [2.7.4] - 2026-07-04

### Fixed

- **Metrics retention prune no longer locks writers out.** The hourly prune
  `DELETE FROM metrics WHERE ts < cutoff` could not seek by `ts` (2nd column of
  the `(instance_id, ts, metric)` PK) and full-scanned the table, gap-locking
  every instance's rows under REPEATABLE READ and blocking concurrent poll/push
  inserts until they hit the 50s lock-wait timeout and flipped the box offline
  (`Lock wait timeout exceeded … INSERT IGNORE INTO metrics`). Added a standalone
  `ts` index (migration 033) and made the batched prune delete oldest-first, so
  its locks stay confined to the old rows being removed.

## [2.7.3] - 2026-07-04

### Fixed

- Log events: hex addresses (e.g. kernel `MOD_LOAD (…, 0xffff…, 0)`) are now
  masked as `0xHEX` during normalization, so lines differing only in a memory
  address aggregate into one event instead of one row each.
- Log events: better aggregation — kernel-tagged dmesg lines unify with their
  raw twins (`kernel: GEOM: …` ≙ `GEOM: …`), embedded dates (`Tue Aug 6`),
  negative numbers (`[-1]`), ACME challenge tokens and `orbit-*.php` temp
  names are masked, runs of whitespace collapse.

## [2.7.2] - 2026-07-04

### Added

- **Connectivity checks accept hostnames.** The destination of a ping
  monitor may now be a DNS name (resolved on the firewall by `ping` itself,
  so the box's own DNS view applies); an empty destination falls back to the
  check's name when it is host-shaped (migration 032 widens the column).

### Fixed

- Validation errors in dialogs rendered as `[object Object]` — FastAPI
  validation details are now formatted into readable text.

## [2.7.1] - 2026-07-04

### Added

- **Log snapshot viewer.** The instance Log tab has a new "Log Snapshots"
  section showing the agent-pushed logfile snapshots; clicking a snapshot
  loads its raw content (admin-only, via the new
  `GET /api/instances/{id}/logs/{logfile_id}/content` endpoint). The AI
  analysis flow is unchanged and still only sends anonymized text.
- **Global "Logs" page with critical events.** Critical lines are extracted
  from the agents' log snapshots at ingest (syslog `<PRI>` severity where
  present, curated patterns for PRI-less BSD lines), normalized (IPs/numbers
  masked) and aggregated into one row per message pattern with a count —
  known steady-state noise (dpinger `sendto error`, filterdns
  `failed to resolve`) is dropped. New `log_events` table (migration 031,
  backfilled once at startup), `GET /api/logs/events?max_severity=N`
  (group-scoped, admin-only) and a "Logs" page in the nav with a
  Critical/Errors/Warnings level switch (default: Errors) and instance
  filter.

## [2.7.0] - 2026-07-04

### Added

- **Group-based permission system.** Instances now belong to exactly one
  group; users are members of any number of groups and only see (and act on)
  instances of their groups — this applies to the instance list, detail
  pages, all overviews (VPN, connectivity, firmware), alerts/checks, bulk
  actions, CSV export, connected-agents list and the GUI proxy. A user
  without groups sees no instances. On upgrade, migration 028 puts every
  existing instance and every existing user into group 1 "default", so
  visibility is unchanged; prune memberships afterwards in the new UI.
- **SuperAdmins.** A new per-user flag for rights management only: SuperAdmins
  manage groups (create/rename/delete via the new Groups page and
  `/api/groups`), user accounts and group memberships — and nothing else; the
  flag grants no instance access. The first superadmin is seeded from the new
  `DASH_SUPERADMIN_PASSWORD` env (username `superadmin`, password-only, same
  auto-retire/break-glass lifecycle as the bootstrap admin, controlled by
  `DASH_SUPERADMIN_DISABLED=auto|0|1`).
- **Move instances between groups.** `PUT /api/instances/{id}/group` — 
  superadmins move any instance anywhere; admins move between groups they are
  member of (also available in the Edit-instance dialog and the Groups page).
- **API keys can be bound to instance groups.** A key created with group
  bindings only sees those groups' instances in `/api/checks`,
  `/api/instances/{id}/checks` and `/api/export/checkmk` — one Checkmk key per
  customer/group. Keys without bindings stay global, so existing keys are
  unaffected. Binding is fixed at creation (re-mint to change); the Settings
  UI gets a group picker and a Groups column. Deleting a group that is the
  last binding of an active key is refused (the key would silently turn
  global).
- **Per-group notification channels.** Each group may configure its own
  Mattermost webhook, Telegram bot/chat and email targets
  (`/api/groups/{id}/channels`, editable via the Channels toggle on the
  Groups page — superadmins and member admins). For an alert, a channel kind
  configured on the instance's group replaces the global target; unconfigured
  kinds fall back to the global channel. Selection-rule routing and the
  global mute toggles stay global; test-send stays global-only. Group webhook
  URLs pass the same SSRF guard as the global one, at save and at send time.

### Changed

- **BREAKING for API clients: `/api/users` now requires a superadmin**, not an
  admin — user management (accounts, roles, passwords, 2FA reset) moved to
  the rights-management surface. The Users page in the UI moved accordingly.
- Creating an instance now targets a group: members of exactly one group get
  it implied, otherwise `group_id` is required and must be one of the
  creator's groups (superadmins may target any group).
- `/api/auth/me` and `/api/users` responses now include `is_superadmin` and
  the user's groups; instance responses include `group_id`.

### Security

- **GUI-proxy tunnel (`/ws/tunnel/{id}`) now enforces instance visibility.**
  Previously any authenticated user could tunnel to any firewall's GUI; now
  membership in the instance's group is required (closes with code 4403).
- **API-key management now admits superadmins** (`/api/apikeys` moves to
  admin-or-superadmin). A group-scoped admin must bind new keys to his own
  groups and can reveal only keys bound within his groups — a scoped admin
  can no longer mint or read a global key to bypass instance scoping.

## [2.6.4] - 2026-07-03

### Changed

- **Agent internals reorganized (agent 2.6.4, no behavior change).** The
  dashboard command handler is now a dispatch table, the metrics snapshot is
  driven by a collector registry, and all shared runtime state lives in one
  documented state object instead of scattered module globals. Groundwork for
  future agent features; wire behavior, payloads, and platform handling are
  unchanged.

## [2.6.3] - 2026-07-03

### Changed

- **Agent hits vendor repos and openssl far less often (agent 2.6.3).** The
  firmware update check ran every 10 minutes — 144 Netgate/OPNsense repo
  requests per box per day (pfSense's repoc alone takes 30-40s cold) for
  releases that ship every few weeks. It now runs every ~12h with a
  per-process jitter so fleets don't check in lockstep; the manual "Check
  now" button and firmware updates still check fresh, and the first push
  after an agent (re)start checks immediately. Certificate parsing (one
  `openssl x509` subprocess per cert, previously on every 30s push) now runs
  only when config.xml's mtime changes; the expiry countdown is recomputed
  from the cached `not_after` on every push, so long-unchanged configs still
  trip the warning.

## [2.6.2] - 2026-07-03

### Fixed

- **pfSense CE's update wording is now recognized (false "up to date").**
  CE says "2.7.0 version of pfSense is available" — none of the agent's
  inferred positive patterns matched that, so a box with a pending release
  upgrade reported green (confirmed live on CE 2.6.0 pinned to the 2.7.0
  train). Agent 2.6.2 matches the confirmed wording and also parses the
  named target version, so the dashboard shows "2.6.0 → 2.7.0" instead of
  "2.6.0 → 2.6.0".

### Added

- **Users page shows when an account is disabled.** The bootstrap `admin` is
  retired automatically once another admin exists (`DASH_ADMIN_DISABLED=auto`)
  or forced off via env — but the Users list rendered it like an active
  account. Disabled accounts now show a struck-through name and an amber
  "disabled" badge explaining the bootstrap lifecycle and how to re-enable.

## [2.6.1] - 2026-07-03

### Fixed

- **A broken firmware update check no longer shows as "up to date".** pfSense's
  `pfSense-upgrade -c` exits 0 with "Your system is up to date" even when the
  repository metadata refresh failed (seen live: CE 2.7.0 with a pkg binary
  linked against a missing libssl — the box reported green for years while
  updates piled up). The agent (2.6.1) now flags ERROR/failed check output
  (and, on OPNsense, an empty remote catalogue) as `check_failed`; the
  dashboard renders an amber "Check failed" badge on the firmware
  page/compliance view and the firmware service check goes WARN instead of OK.
  Firmware-compliance counters sort these boxes under "unknown", not
  "up to date".

## [2.6.0] - 2026-07-03

### Added

- **Security/operational events now appear in the backend log.** Logins,
  failed passwords, brute-force IP locks (`auth.ip_blocked`), enrollments and
  every other audited action are mirrored to a dedicated `app.audit` log
  stream; device/agent offline/online and check alerts are logged via the
  notification funnel. The stream stays visible even at
  `DASH_LOG_LEVEL=warning`.
- **`DASH_LOG_FORMAT=console|json`** (default `console`): human-readable
  key=value log lines instead of raw JSON; also editable in Settings → Service
  (restart required). structlog and uvicorn/stdlib records render through one
  unified pipeline.
- **"Restart backend" button on Settings → General.** Applies "needs restart"
  settings without shell access: two-step confirm, then the backend restarts
  itself (`POST /api/settings/restart`, admin-only, audit-logged) and the page
  reloads once `/api/health` answers again. Works in the combined prod
  container (new supervisor loop in `start.sh` restarts uvicorn, nginx stays
  up), the dev container and a bare uvicorn under a restart policy.

### Fixed

- **Login page no longer prefills the username `admin`.** Handing every
  visitor a valid admin username undercut the backend's username-enumeration
  protections; the field starts empty and browser password managers fill it
  per user.

- **"Aggregate services" no longer shows on two Settings tabs.** The Checkmk
  export toggle appeared on both General and Checkmk; it now lives only on
  Settings → Checkmk next to the rest of the export config.

- **HTTP access log shows the external client IP.** uvicorn's access log
  (which only saw the nginx-internal address) is replaced by an app-level
  access log that resolves the client via the trusted-proxy-aware
  `DASH_TRUSTED_PROXY_HOPS` logic; includes method, path, status, duration and
  session user id. WebSocket connects/disconnects are logged with their source
  IP as well. Library plumbing noise (httpx/httpcore, apscheduler job lines,
  asyncssh SSH chatter, WebSocket frame traces) is quieted to WARNING.

- **Hourly metrics prune no longer starves the DB connection pool.** The
  retention job deleted all expired `metrics` rows in one unbounded `DELETE`;
  on a large table that held row locks long enough to block every concurrent
  agent-push INSERT, exhaust the connection pool (default 5 + 10 overflow) and
  fail API requests / health checks with `QueuePool limit … reached` for the
  duration (observed: ~80 s outage every hour with ~60 connected agents). All
  retention pruners (metrics, IPsec events, check events) now delete in
  10 000-row batches with a commit and a short pause between batches, so
  writers interleave and the prune is invisible to agents and the API.

### Changed

- **DB connection pool is configurable and sized for larger fleets.** New
  settings `DASH_DB_POOL_SIZE` (default 20) and `DASH_DB_MAX_OVERFLOW`
  (default 30) replace SQLAlchemy's built-in 5/10 defaults.

## [2.5.9] - 2026-07-03

### Added

- **Flapping filter for connectivity/IPsec Phase-2 ping-monitor notifications.**
  Each agent push is a single ping measurement, so a lone dropped packet used
  to flip a "ping ok" check to "ping FAILED" and back within one push cycle —
  each flip sent a Telegram/e-mail/Mattermost notification and a check-history
  entry, flooding channels with back-to-back down/up pairs. A ping monitor's
  notification and history entry now only fire CRIT after 3 consecutive
  failed pushes; recovery still notifies immediately on the first successful
  ping. Applies uniformly to all three notification channels since the fix
  sits upstream of dispatch. The live Checks/Alerts page and Checkmk export
  are unaffected — they still show the latest single measurement, not the
  debounced value.

## [2.5.8] - 2026-07-03

### Fixed

- **Firmware-locked instances can no longer be checkbox-selected on the
  Instances page.** The bulk-select checkbox (both list and grid view, plus
  the header "select all") is now disabled for a locked instance, matching
  the same restriction already in place on the Firmware compliance page.

## [2.5.7] - 2026-07-02

### Changed

- **Agent offline floor raised from 120s to 300s.** A plain backend restart
  (all agents briefly drop their websocket and reconnect) was enough to trip
  every connected agent's "offline" alert and then immediately "back online"
  it once reconnected, flooding notification channels. 300s comfortably
  covers a restart's reconnect window while still catching a genuinely dead
  agent quickly. Existing deployments that explicitly set `agent_stale_seconds`
  via Settings keep their stored value — this only changes the default floor.

## [2.5.6] - 2026-07-02

### Added

- **Firmware update lock per instance.** A new "Lock firmware updates"
  toggle on the instance's Firmware tab (also settable from Edit instance)
  blocks both the single-instance "Start update" action and the bulk
  "Update all" action for that instance, preventing accidental upgrades on
  boxes pinned to a firmware version. Locked instances show a lock badge on
  the instance list and the Firmware compliance page (excluded from bulk
  selection there).

## [2.5.5] - 2026-07-02

### Added

- **Bulk firmware update ("Update all") on the Firmware compliance page.**
  Rows with a pending update can be selected (individually or all visible at
  once); a type-to-confirm dialog then starts the update on every selected
  instance via the new `firmware_update` bulk action, with a per-instance
  started/failed result list.

### Changed

- **Firmware updates now reboot the box when required (agent 2.5.4).** The
  agent previously only staged updates (`opnsense-update -bkp` /
  `pfSense-upgrade -R`), leaving the new base/kernel inactive until a manual
  reboot. It now runs the vendor's own update path — `configctl firmware
  update` on OPNsense (same as the GUI), `pfSense-upgrade -y` on pfSense —
  which reboots automatically when the update includes base/kernel changes.

### Fixed

- **Bulk actions now work on agent-mode instances.** `/api/bulk/action`
  previously always went through the HTTP API client and silently failed for
  instances managed by the push agent; commands (`firmware_check`,
  `firmware_update`, `ipsec_restart`, `reboot`) are now dispatched over the
  agent hub, with a clear "agent not connected" per-instance error.

## [2.5.4] - 2026-07-02

### Fixed

- **pfSense release updates in a newer train are now detected (agent 2.5.1).**
  pfSense publishes each release in its own pkg train, and `pfSense-upgrade -c`
  only checks the pinned one — a Plus box on 26.03 reported "up to date"
  although 26.03.1 was out. The agent now refreshes Netgate's train catalogue
  itself (`pfSense-repoc`, what the GUI update page does), compares train ids
  numerically and reports the newest one as the available update, including
  the target version. Proven live on pfSense Plus 26.03 (26.03.1 detected).
- **Product names render with proper spelling everywhere in the UI.** Raw
  `device_type`/platform values (and a CSS `capitalize`) produced "Opnsense" /
  "Pfsense"; all UI badges now show "OPNsense" / "pfSense" via a shared label
  helper.

## [2.5.3] - 2026-07-02

### Fixed

- **pfSense (Plus) boxes stored with the wrong device type self-heal on agent
  connect.** Instances default to OPNsense on creation, so a pfSense box
  enrolled without correcting the type was mislabeled and got OPNsense deep
  links (`/ui/ipsec/sessions` instead of `/status_ipsec.php`). The agent's
  platform detection now corrects the stored type on connect — only within the
  opnsense↔pfsense pair; other device types are never touched.

## [2.5.2] - 2026-07-02

### Added

- **Recheck button per VPN connection.** After changing or reconnecting a
  tunnel an admin no longer waits for the 30s cycle: each row in the VPN
  overview (and the instance IPsec section header) has a Recheck action.
  Agent-mode boxes collect and push a fresh snapshot on demand (new agent
  command `status.refresh`, agent 2.5.0); direct-mode boxes are fetched live.
  Older agents degrade gracefully to last-known data.

## [2.5.1] - 2026-07-02

### Added

- **Instance detail: IPsec section catches up with the VPN overview.** Each
  tunnel row now offers the History (state-change log) and Graph (up/down
  timeline) dialogs and shows a Phase-1 uptime column, matching the global VPN
  overview.
- **VPN overview: deep link to the firewall's own IPsec status page.** The
  external-link icon next to an instance name now lands directly on
  `/status_ipsec.php` (pfSense) / `/ui/ipsec/sessions` (OPNsense). Agent-mode
  boxes go through the GUI-proxy handoff (with the optional auto-login);
  direct-mode boxes get a plain link to their configured web UI and log in on
  the firewall itself. The GUI handoff accepts a `next` deep-link path, clamped
  to same-origin absolute paths (no open redirect).

## [2.5.0] - 2026-07-02

### Security

- **Agent token endpoint is now write-gated.** `GET /instances/{id}/agent/token`
  previously required only a logged-in session, so a read-only user could read an
  instance's agent bearer token, evict the real agent, and push forged metrics. It
  now requires the write role, matching agent enable/rotate.
- **Privileged agent actions can no longer ride the generic command passthrough.**
  `agent.update`, `relay.enable`, `http.relay` and `agent.uninstall` are rejected by
  `POST /instances/{id}/agent/command` and must go through their dedicated,
  parameter-curated endpoints — closing a defense-in-depth gap at the agent trust
  boundary.
- **Backend runs as a non-root user in the production container.** uvicorn (which
  parses all untrusted API and agent input) now drops to an unprivileged `orbit`
  account via `gosu`; migrations still run as root, nginx keeps its root master.
- **Agent pfRest install is version-pinned and SHA-256 verified.** The pfSense relay
  bootstrap previously fetched `pfSense-pkg-RESTAPI` from the GitHub `latest` release
  and installed it unverified. It now pins an exact release, verifies each per-version
  asset against a baked hash over TLS, and fails closed on an unpinned version or
  hash mismatch.

## [2.4.3] - 2026-07-02

### Fixed

- **Agent updates no longer show a spurious "update rejected" marker for
  already-current agents.** Overlapping update runs (double "Update all", a
  second browser tab, or a per-instance push) could send the served agent
  version to a box that had just updated and reconnected; the agent's
  anti-rollback then refused ("pushed X not newer than X") and the rejection
  stuck as a persistent badge until the next reconnect. Both update endpoints
  now re-check the live connection's version right before pushing and answer
  "already at X" as a no-op instead.

## [2.4.2] - 2026-07-01

### Fixed

- **Reconnecting an IPsec tunnel now restores Phase 2, not just Phase 1.** The
  agent's `ipsec.connect` ran only `swanctl --initiate --ike`, which establishes
  the IKE_SA but leaves the configured CHILD_SAs down until traffic — so the
  "Restart tunnel" / connect button left tunnels at Phase 1 up / Phase 2 0/N
  (verified on OPNsense). It now also initiates each configured child of the
  connection, bringing the whole tunnel back.

## [2.4.1] - 2026-07-01

### Changed

- **Recency timestamps render as compact relative time.** "Last poll", agent
  "Last seen", config change/backup age, AI-log collection, check-history entries
  and the Checkmk key's last use now show German relative time ("vor 30s",
  "vor 3min", "vor 2h", "vor 4d"; "gerade eben" under 5s), with the absolute ISO
  time on hover. Log/compliance timestamps (audit trail, created/revoked dates,
  certificate expiry) keep their absolute form. Consolidated three ad-hoc
  relative-time helpers into one shared `fmtRelative`.

### Fixed

- **Timestamps now show the correct local time, in ISO format.** MariaDB `DATETIME`
  is timezone-naive, so the API serialized timestamps without a UTC marker and
  browsers parsed them as local time — "Last poll", "Last seen", and the audit /
  check-history times all read ~2h behind actual in CEST. Datetimes now serialize
  as UTC-aware (trailing `Z`) via a `UtcDateTime` column type (storage unchanged,
  no migration), and the UI renders them in ISO 8601 local format
  (`YYYY-MM-DD HH:MM:SS` / `YYYY-MM-DD`) via a shared helper instead of the US
  `M/D/YYYY, h:mm:ss AM` layout. Chart axis ticks stay in their short form.

## [2.4.0] - 2026-07-01

### Fixed

- **pfSense boot no longer hangs at the agent boot hook.** On pfSense the agent is
  started at boot via `afterbootupshellcmd`, which pfSense runs through
  `mwexec()`/`exec()` — a call that reads the command's stdout to EOF. The
  `daemon(8)` supervisor inherited that capture pipe and, being long-lived, never
  released it, so `rc.bootup` blocked forever at "Running afterbootupshellcmd
  /usr/local/etc/rc.d/orbit_agent onestart" and the box never finished booting.
  The rc.d service now passes `daemon -f` (supervisor stdio → `/dev/null`, agent
  output still logged via `-o`), and the registered boot hook now redirects its
  own stdio (`… onestart >/dev/null 2>&1`). Already-deployed agents self-heal:
  startup migrates a legacy un-redirected `afterbootupshellcmd` entry to the fixed
  form. OPNsense was never affected (it starts rc.d services via normal `rc`).

### Added

- **Checkmk service aggregation.** High-fan-out checks (certificates, IPsec tunnels
  and pings, services, interfaces, gateways, connectivity, disks) now collapse into
  one aggregate service per category in the Checkmk export, cutting a busy firewall
  from hundreds of services to a handful. Each aggregate takes the worst member
  state and names the offenders in its summary (with `crit`/`warn`/`total` perfdata),
  so the admin still sees exactly what is wrong. On by default (`DASH_CHECKMK_AGGREGATE`,
  runtime-toggleable on the Checkmk settings tab); the dashboard's own checks stay
  granular. Note: toggling this changes which services Checkmk discovers, so
  re-inventorize the hosts afterwards.

## [2.3.4] - 2026-07-01

### Added

- **All-tunnels "Graph" popup on the VPN overview.** A new Graph button in the
  toolbar opens a single step line of how many tunnels have Phase 1 up over time,
  folded from every tunnel's transition log (same 24h/7d/30d/All window selector).
  Each tunnel end is counted separately, so the value at "now" matches the
  Connected KPI and the Y-axis max matches the total tunnel count.
- **Temporarily mute notifications per channel + Checkmk blackout.** Each channel
  tab (Mattermost / Telegram / Email) now has a manual on/off switch that pauses
  that channel's real alerts; an explicit "Send test" still fires so muting can't
  hide a broken config. The Checkmk tab adds a blackout switch that empties the
  `/api/export/checkmk` output (no instances) so Checkmk sees every service go
  stale/gone during maintenance. Toggles are runtime settings (no restart) and
  stay until switched back.
- **Agent collection runtime is now measured and visible.** The push agent times
  each metrics cycle — the whole collection and each section — so a slow-but-alive
  agent is caught before it goes silent (a degrading collector shows as rising time
  first). A new `agent.collect` check WARNs when a cycle takes ≥ 10s (naming the
  slowest section), the whole-cycle total is graphed under the instance Overview
  tab with a 10s reference line, and the last per-section timings are listed on the
  Agent tab (live snapshot, not stored as history).

### Changed

- **The per-tunnel Graph popup now plots Phase 2 as a number, not up/down.** The
  Phase 2 lane is a numeric step line of installed child SAs (green when all up,
  amber partial, red at none) with a 0..total Y scale; Phase 1 and Ping stay as
  up/down state lines.
- **The IPsec "Analyse with AI" bundle now includes the on-disk swanctl config,
  with secrets stripped on-box.** A new "On-disk swanctl config (secrets stripped)"
  section adds the generated strongSwan config for the tunnel (OPNsense
  `/usr/local/etc/swanctl/swanctl.conf`, pfSense `/var/etc/ipsec/swanctl.conf`).
  The agent slices it to the selected connection and removes the `secrets { }`
  block (with a line-level `secret =`/`*_key` fallback), so no PSK/EAP material
  leaves the box — the strip is on-box because "Copy all" bypasses the backend
  anonymizer. Agent `__version__` → 2.3.4.

## [2.3.2] - 2026-07-01

### Added

- **Per-tunnel "Graph" popup on the VPN overview.** A new action next to History
  opens an up/down timeline with one state line per lane — Phase 1, Phase 2 and
  Ping — green while up, red while down, grey/dashed where there is no data. State
  is reconstructed from the same transition log the History popup uses (with the
  same 24h/7d/30d/All window selector); Phase-2 duplicates are left out. The line
  before a window is seeded from the last transition preceding it (carry-in), and a
  lane with no logged change falls back to the tunnel's current live state.

### Changed

- **Pages use the full browser width, and the VPN overview degrades gracefully when
  narrow.** The page container's `max-w-7xl` cap is removed, so every page (the VPN
  overview in particular) uses the full window width minus the page padding. The
  per-row "Down" action is removed from the VPN overview (Reconnect remains). Below
  the `xl` breakpoint the "Remote" column is hidden to avoid horizontal scrolling,
  and the "dup phase2" badge is shortened to "dup" (full explanation in its tooltip).

## [2.3.1] - 2026-07-01

### Fixed

- **Phase-2 duplicate history no longer repeats every poll.** A tunnel's history
  recorded a fresh "Phase-2 duplicate" entry on every push (once per poll) for a
  multi-subnet Phase-2 with a stuck duplicate SA. The state-change diff matched
  Phase-2 rows by name only, but a multi-subnet Phase-2 is split into several rows
  that share one name and differ only by selector — so a duplicated selector was
  compared against a non-duplicate sibling and re-fired every cycle. Rows are now
  matched by selector pair, so only genuine transitions are stored. Ping ok/fail
  transitions on multi-subnet Phase-2s are attributed correctly for the same reason.

## [2.3.0] - 2026-06-30

### Added

- **Mandatory two-factor authentication (TOTP + passkeys).** Every account must
  have a second factor — a TOTP authenticator app *or* a WebAuthn passkey. Login
  is now two-phase: password, then the factor; a session is minted only after it
  passes. New accounts (and any session predating 2FA) are forced through
  enrollment on next login — scan the QR or register a passkey. Manage your
  passkeys on the new **Security** page. An admin can clear another user's 2FA
  from the Users page to recover a lost authenticator. Passkeys need
  `DASH_WEBAUTHN_RP_ID` / `DASH_WEBAUTHN_ORIGIN` set to your domain in production.
- **Bootstrap admin is a password-only break-glass seed.** The `admin` account
  created from `DASH_ADMIN_PASSWORD` logs in with a password only (exempt from
  mandatory 2FA) and is **disabled automatically as soon as a second admin
  exists** — so the only password-only account never outlives setup. If no other
  enabled admin remains it is re-enabled (password reset from the env) as a way
  back in. `DASH_ADMIN_DISABLED` overrides this: `auto` (default) = the lifecycle
  above, `0` = force the seed enabled, `1` = force it disabled.

### Changed

- **Tunneled-WebUI link icon is now a boxed-arrow (external-link) everywhere.**
  The tunneled-WebUI quick-link next to an instance name switched from the globe
  to the boxed-arrow icon across every list that shows it (the global overview
  lists and the instance list/card views).
- **Tunneled-WebUI link next to the instance name in the list views.** The
  instance list and card views now show that link right beside the instance name
  (agent boxes only), matching the global overview lists — sized a touch smaller
  — and drop the separate grey "WebUI" action button from the row's button
  cluster.

## [2.2.0] - 2026-06-30

### Added

- **User roles: Admin / User / View-Only.** Each account now has a fixed role.
  *Admin* keeps full access incl. configuration (settings, API keys, LLM, log
  config, notification rules) and user management; *User* can perform every
  operational action (firewall instance CRUD, firmware apply, bulk push,
  connectivity, agent ops, system, IPsec) but no configuration; *View-Only*
  reads everything and cannot mutate. Existing admins are unaffected — they map
  to *Admin* on upgrade.
- **More state history.** Building on the IPsec tunnel-history timeline, the
  agent-push ingest now records two more kinds of transition: **duplicate Phase-2**
  appearing/clearing (as `phase2_dup_on`/`phase2_dup_off` events on the tunnel, so
  they show in the existing tunnel-history dialog) and **instance online/offline**
  (recorded under the `availability` check key — the one surface that also covers
  direct-API instances, since the scheduler records its flips too). **Connectivity**
  history is reachable from a per-monitor History button on the overview and the
  per-instance tab; the check-history endpoint takes a `key` (exact, one entity) or
  `key_prefix` (whole category) filter so one timeline renders a single surface. A
  backend restart with an active persistent duplicate Phase-2 no longer emits a
  spurious resolve/re-appear flap (the dup streak is re-seeded on rehydrate). All
  push-mode history stays push-only; availability also covers direct.

### Changed

- **Alerts page defaults to the "Exported" Checkmk filter.** The service-checks
  view now opens showing only checks exported to Checkmk instead of "All";
  switch back to "All" or "Excluded" with the filter as before.

## [2.1.7] - 2026-06-30

### Fixed

- **Connectivity monitors stuck on "no data yet" after an agent reconnect.** On
  every agent (re)connect the backend re-pushed only the IPsec ping-monitor
  config, never the standalone connectivity monitors. Since the agent's monitor
  set starts empty and is only populated by a `config_update`, a reconnect (e.g.
  after a backend restart) left connectivity checks unprobed — every row showed
  "no data yet" with OK/Down/Error all 0. The hello handler now also pushes the
  connectivity monitor set, so probing resumes immediately on reconnect.

## [2.1.6] - 2026-06-30

### Fixed

- **False "ping mismatch" badge on one-sided VPN ping probes.** A paired tunnel
  flagged "ping mismatch" whenever one end had a reachability probe and the other
  had none, because the comparison treated the unconfigured side (`"none"`) as a
  differing state. The badge now only appears when *both* ends actually monitor
  and their ping states differ; a one-sided probe no longer trips it.

## [2.1.5] - 2026-06-30

### Changed

- **Add instance dialog hides TLS options in Agent mode.** The "CA bundle (PEM)"
  field and "Skip SSL verification" checkbox now only show for the Polling (API
  key) path, where the dashboard makes the outbound HTTPS API call. In Agent
  mode the on-box agent collects locally and pushes via the hub, so these had no
  runtime effect and only added noise.

### Fixed

- **Garbled Securepoint VPN tunnel names under SSH enrichment.** With SSH
  enrichment enabled, tunnel names came from `swanctl --list-conns`, where
  Securepoint hex-escapes characters invalid in a strongSwan section id — a space
  becomes `$20`, so "Broken Connection" showed as `Broken$20Connection`. The
  display name is now decoded (`$XX` → byte, UTF-8 reassembled for umlauts) while
  the raw escaped form is kept as the tunnel id (swanctl `--ike` and the diagnose
  slicing need it verbatim). Also allows `$` in the diagnose tunnel-id guard so
  Diagnose works on these tunnels — it stays inert inside the single-quoted shell
  assignment, and `'` remains rejected. Verified live on the fw1 box.

## [2.1.4] - 2026-06-30

### Changed

- **VPN "Diagnose with AI" now scopes every section to the selected tunnel.** The
  on-box diagnostic bundle previously dumped `swanctl --list-conns` for **all**
  tunnels into the AI context; it now filters config + crypto + live SAs + log +
  ping to the one tunnel under inspection. Two sources were added so the AI can
  catch crypto-proposal mismatches (the most common Phase-1/Phase-2 negotiation
  failure): the configured **crypto proposals** from `swanctl --list-conns --raw`
  (the plain listing omits them when left at the strongSwan default), and the
  **user-intent config.xml fragment** for that tunnel. The config.xml snippet is
  redacted on-box — pfSense stores the pre-shared key inline in `<phase1>`, so
  `<pre-shared-key>`/`<private-key>`/`<pkcs11pin>` (and any `*psk*`/`*secret*`/
  `*password*` tag) are blanked before it leaves the box; OPNsense keeps its PSK
  in a separate `<preSharedKeys>` section that is never serialized. (agent
  `__version__` 2.1.4)
- **Securepoint SSH diagnose aligned with the same scoping.** The SSH-based
  diagnose path (`securepoint/ssh.py`) likewise dumped all tunnels' config; it now
  slices the `swanctl --list-conns` block to the selected tunnel and adds the raw
  crypto-proposals block, scoped the same way. Securepoint has no config.xml, so
  no config snippet applies there.

### Added

- **Tunneled-WebGUI icon in the global list views.** Each instance row in the
  **VPN**, **Connectivity**, **Alerts** and **Firmware** overviews now carries a
  small globe icon next to the instance name that opens that box's WebGUI through
  the agent's GUI proxy (the same one-shot handoff as the per-instance "WebUI"
  button) in a new tab. Shown only for agent-mode boxes; proxy-disabled/offline
  errors surface in the icon's tooltip.

## [2.1.3] - 2026-06-30

## [2.1.2] - 2026-06-30

### Added

- **Duplicate Phase-2 note on IPsec tunnels.** When the same traffic-selector pair
  carries more than one installed child SA — whether both sit under one IKE_SA or
  split across two IKE_SAs to the same peer — and the duplicate **persists across
  several consecutive polls**, a neutral "duplicate phase-2" note is shown on the
  tunnel row (and per selector when expanded) in both the **VPN overview** and the
  **instance** IPsec view. It is informational only: no warning, no notification,
  no Checkmk state. Transient make-before-break rekey blips are filtered out, so
  the note marks stuck/orphaned SAs, not routine rekeys. Agent-managed
  OPNsense/pfSense only. Requires agent ≥ 2.0.7.

## [2.1.1] - 2026-06-30

### Added

- **Per-instance comment field** — a free-text **Comment** box on the instance
  Overview tab (saved to the existing `notes` field via PATCH; no schema change).
- **Per-service notify/export toggles on the instance page.** Each row in a single
  instance's **Service Checks** now carries four checkboxes — Mattermost, Telegram,
  Email, Checkmk — to turn that exact service on/off for that box without leaving the
  instance. They edit the same per-instance selection the Settings tree does (shared
  rules/cache); a box-level choice overrides the global category defaults.

## [2.1.0] - 2026-06-30

### Changed

- **Unified, per-host/per-service selection for every notification channel.**
  Mattermost, Telegram and Email now use the **same selection model as the Checkmk
  export**: a per-instance tree where you turn on a whole category globally and then
  add or mute **individual services on individual firewalls** (e.g. alert only on
  `gateway:WAN` of `opn1`). This replaces the old coarse per-category routing. The
  Checkmk export gains the missing direction too — you can now **include a single
  service even when its category is off** (and mute one service inside an included
  category). One shared engine (`app.selection`), one shared UI (`SelectionTree`),
  one table (`selection_rules`), identical behaviour across all four consumers.
- **Selection is now opt-in (base default OFF) everywhere — including the Checkmk
  export.** Nothing is selected until you include it. **Operational note on upgrade:**
  the old `checkmk_export_exclusions` and `notification_routes` tables (and their
  rows) are dropped — after migrating, the Checkmk export emits **nothing** and the
  channels send **nothing** (including instance up/down) until you re-pick what you
  want in **Settings → Checkmk** and each channel tab. This is intentional (a clean,
  consistent slate); re-select your services after deploying.
- Notification alerts now carry the **full check key** (`gateway:WAN`) instead of
  only its category, so channels can be routed per service.

### Removed

- The `availability` notification route is **no longer seeded** — instance up/down
  alerts are off until you enable them per channel (see the opt-in note above).
- Old API endpoints `/api/checkmk/{config,exclusions,preview}` and
  `/api/notifications/{routing,routes,test}` — replaced by
  `/api/selection/{consumer}/{config,rules,preview,test}`.

## [2.0.5] - 2026-06-29

### Added

- **Connectivity checks (standalone ping monitors)** — a new per-instance
  **Connectivity** tab (OPNsense/pfSense, agent mode) where you configure
  tunnel-independent `source → destination` pings. The agent runs them on the
  firewall each push cycle (reusing the same probe the IPsec ping monitors use,
  `ping -S <source>`), and the dashboard turns each result into a
  `connectivity:<id>` check: **ok → OK, no reply → CRIT, misconfigured → WARN**.
  Because the checks flow through the normal evaluation path they **alert on the
  configured notification channels** on a state change and **export to Checkmk**
  (new `connectivity` category, toggleable in the export-exclusion + channel-alert
  settings). A global **Connectivity** overview page (next to VPN) lists every
  monitor across all instances with its live state; stale rows (agent silent) are
  muted, not trusted. A "Test now" dry-run validates source/destination before
  saving. (Agent `__version__` → 2.0.6, Alembic `022`.)

### Fixed

- **Can now add a ping monitor per subnet of a multi-net IPsec Phase-2** — adding a
  second monitor to a tunnel whose configured Phase-2 child carries several local
  subnets was rejected with "a ping monitor for this Phase 2 already exists". The
  uniqueness key was the child name, which strongSwan shares across the sibling
  CHILD_SAs it splits a multi-net child into; it now keys on the selector pair, so
  each `local → remote` subnet gets its own monitor (Alembic `023`).

## [2.0.4] - 2026-06-29

### Fixed

- **IPsec Phase-2 ping monitor no longer binds to the wrong split child** — split
  Phase-2 children share one strongSwan child name, and monitor matching keyed on
  that name, so a monitor pinned to one selector pair showed up on every sibling
  row (same source/destination on both) and the probe could run against the wrong
  subnet. Matching now keys on the selector pair first (name only as a fallback
  for selector-less monitors), on both the agent that runs the ping and the
  dashboard that renders "Edit ping".

## [2.0.3] - 2026-06-29

### Fixed

- **IPsec Phase-2 children with multiple subnets are no longer duplicated/mislabelled**
  — a single configured Phase-2 child with several local nets
  (`10.110.0.0/16, 192.168.0.0/24 → 192.168.200.0/24`) is split by strongSwan into
  one CHILD_SA per subnet, all sharing the child name. The agent matched live SAs
  by name, so the shared name collapsed them: the dashboard showed `2/1` with the
  first net repeated and the second net dropped (BadVilbel tunnel). The agent now
  expands each configured child to one row per `(local × remote)` selector pair and
  matches live SAs by selector-pair membership, so every subnet shows as its own
  independently-pingable Phase-2 row with the correct `up/total` count.
- **Network tab no longer flags virtual-interface errors as faults** — the interface
  table coloured the error counter amber for every interface, so a `bridge0`/`lagg`/`ovpn`
  Oerr count (BUM-flood/ENOBUFS, not a wire fault) lit up as an alarm. The health check
  already skips these prefixes; the frontend now mirrors that list and renders their
  counters neutral (grey) instead of amber.
- **Network tab RX/TX now show a stable throughput in agent mode** — the rate was
  derived client-side by diffing two `/status` reads, but in agent mode those reads
  return the same cached push between agent pushes, so the delta was 0 and RX/TX mostly
  showed `0` (and, when it did fill, divided by the 30 s poll interval instead of the
  real push interval, so the magnitude was wrong too). The agent hub now derives
  `rx_rate`/`tx_rate` (bytes/sec) from two consecutive pushes — the same way it already
  derives the interface error rate — and the UI renders that; it falls back to the
  client-side delta only on the direct-poll path, where it still works.

## [2.0.2] - 2026-06-29

### Fixed

- **pfSense WebUI auto-login without relay** — auto-login on pfSense silently failed
  (`no GUI credentials`) on any box where the relay was never enabled, because pfSense
  drew its WebUI credentials only from the relay-provisioned apikey cache. OPNsense was
  unaffected (it mints its own GUI password on demand). The agent now provisions the
  `orbit` page-all user on demand for pfSense auto-login too — without installing the
  pfRest REST API package — so auto-login works independently of the relay.

## [2.0.1] - 2026-06-29

### Added

- **Agent-staleness overlay (P1)** — when a push agent goes silent past its scaled
  threshold, the dashboard no longer trusts its last-known sub-states as live. A new
  explicit **`agent`** Checkmk service goes WARN ("agent silent for Xs") so the host
  summary turns yellow the moment contact is lost, and while stale every other check
  is capped CRIT→WARN (a "down" verdict on stale data is a guess, not a fact). The
  instance API now exposes `stale` / `stale_seconds`, and the global VPN overview
  mutes stale tunnels with a "stale · agent silent" marker (a stale pair never
  collapses as "both up"); the per-instance IPsec section shows a last-known banner.
  Confidence model: stale = *unknown*, not *down*. (No DB migration.)
  **Deploy note:** the `agent` service is a new Checkmk item — run **service
  discovery** on the affected hosts so it gets monitored; until then a silent agent
  turns the host yellow only after discovery picks the service up.
- **Out-of-band reachability probe (P2)** — each instance gains an optional
  `ping_url` (URL or bare host). A scheduler job probes it independently of the
  agent: **ICMP** (stdlib, no iputils/raw-subprocess — verified working from the
  container) and an **HTTP** GET (TLS-verify off for self-signed certs, redirects not
  followed, `<400` = up). New Checkmk services `ping` / `http` follow the confidence
  model — a confirmed-up signal (agent fresh **or** ICMP reply) caps a failing probe
  at WARN; otherwise it's CRIT (confirmed down). Flap protection: an axis only flips
  to down after `DASH_PROBE_FAIL_THRESHOLD` (default 3) consecutive failures, probed
  every `DASH_PROBE_INTERVAL_SECONDS` (default 60). This distinguishes "box up, agent
  dead" from "box down". Alembic `021`.
- **Maintenance mode (P2)** — an admin can flag an instance `maintenance`: every
  check is then capped at WARN (yellow, never red) and a `maintenance` service makes
  the host visibly yellow with the reason. The flag **auto-clears** the moment the
  agent reports in again (hub heartbeat) or the probe confirms the box up. Edit/Add
  dialogs gain a ping-URL field and a maintenance toggle; the Instances page shows an
  "in maintenance" count + filter so a forgotten yellow box doesn't vanish. New
  Checkmk categories `agent` / `maintenance` / `ping` / `http` are listed in the
  export-exclusion settings (also need **service discovery** to be monitored).

## [2.0.0] - 2026-06-29

### Added

- **LLM provider API keys** — a new Settings → AI tab stores encrypted API keys for
  OpenAI, Anthropic and OpenRouter (extensible: adding a provider is a few lines in
  the backend catalog, no DB migration). Each provider has an editable base URL and
  model (defaults from the catalog) so OpenAI-compatible/self-hosted endpoints work.
  A per-provider "Test key" button validates the stored key against the provider's
  models endpoint (`POST /api/llm/test`). Keys are stored with the existing Fernet
  helper in `app_settings` and never returned in plaintext. Groundwork for the
  AI log analysis below.
- **AI log analysis** — the agent now collects the important logs (system, filter,
  gateways, ipsec, resolver, openvpn) **hourly**, capped to ~1 MB total, and pushes
  them to the backend, which keeps only the **last 3 snapshots per log** (no
  long-term history; Alembic `020`, new `logfiles` table). On a firewall's **Log**
  tab a new *AI Log Analysis* panel lets an admin preview the exact anonymized text,
  pick a configured provider, and send it for analysis — the model flags anomalies
  like ARP flapping / duplicate IPs, interface errors, failing services, IPsec or
  gateway issues. Anonymization keeps internal IPs (they aid diagnosis) but
  pseudonymizes public IPs, strips MAC vendor bits, and redacts hostnames and
  secrets; raw log content never reaches the browser. Log paths are platform-aware
  (OPNsense dated `/var/log/<cat>/…`, pfSense `/var/log/<name>.log`, both plaintext).
  (Agent `__version__` → 1.9.1.)
- **AI analysis in the IPsec Diagnose dialog** — the per-tunnel diagnostics dialog
  (swanctl config + live SAs + charon log + peer ping) gained an *Analyse with AI*
  button next to *Copy all*: pick a provider, optionally preview the anonymized
  bundle, and get findings inline (e.g. "IKE up but no CHILD SAs", "DPD disabled",
  dead/`broken` tunnels).
- **AI analysis is enriched and token-lean** — the analysis payload now includes
  structured telemetry (interfaces with errors, IPsec tunnel states, gateways,
  services, pf, certs) alongside a recent tail of each log, server-bounded
  (down from ~700 KB of full logs). OpenAI-style requests use
  `max_completion_tokens` so newer models (gpt-5.x) work.
- **More collected signals** — the agent now also ships the active firewall ruleset
  (`pfctl -sr`), DHCP lease events (ISC dhcpd / Kea / dnsmasq, auto-detected), and a
  set of cheap diagnostic snapshots the analysis model itself asked for: recent
  kernel messages (`dmesg`, where NIC resets / link flaps / ARP moves show), pf
  state-table counters (`pfctl -si/-sm`), mbuf usage (`netstat -m`), ARP/NDP
  neighbours (`arp`/`ndp`), link/bridge/MTU detail (`ifconfig -a`) and listening
  ports (`sockstat -l`). The payload is ordered by signal density (telemetry →
  state → log tails) and capped (~48 KB, still ~90%+ below raw logs).
  (Agent `__version__` → 1.9.3.)

### Fixed

- **VPN overview: collapsed pairs hid ping failures.** A paired link whose Phase 1
  was established on both ends but whose Phase-2 ping monitor was failing collapsed
  to a green "both up" header — symmetric failure (both ends fail) slipped past the
  ping-*mismatch* check. The pair health now ranks the worst ping across both ends:
  it shows "ping fail" (red) / "ping error" (amber) and stays expanded so the
  per-tunnel red ping badge is visible. (Requires a configured Phase-2 ping monitor;
  tunnels with no monitor still report "both up".)

## [1.9.3] - 2026-06-28

### Changed

- Interface-error alerting now skips bridge, lagg and tunnel pseudo-interfaces
  (`bridge`, `lagg`, `gre`, `ovpn`, `tun`, `tap`, `wg`) in addition to the existing
  `lo/enc/pflog/pfsync/gif/stf`. On FreeBSD (OPNsense/pfSense) these count Oerrs from
  BUM-flood-to-a-down-member and ENOBUFS — not wire faults — so a bridge with dead
  member ports no longer raises a false interface-error check. Real driver errors
  still surface on the physical member interface.

## [1.9.2] - 2026-06-28

### Added

- **Per-instance notification routing with override** — Mattermost/Telegram/Email
  alert routing can now be scoped to a single firewall, not just global. In Settings
  → Notifications each channel gets a scope selector (*All instances* + one per
  firewall); pick an instance to **override** categories for just that box. Matching
  is precedence: a per-instance choice wins over the global one, so a globally-on
  category can be switched **off** for a single firewall (and a globally-off one
  switched on). At instance scope each category is tri-state — inherit the global
  value (shown as "via global"), or an explicit on/off override that can be cleared
  (↺) back to inherit. Existing global routes are unchanged. (Alembic `019`, new
  `notification_routes.enabled` column.)

## [1.9.1] - 2026-06-28

### Fixed

- Agent: cert collector used `str.removesuffix()` (Python 3.9+), crashing on
  older pfSense boxes running Python 3.8 with `AttributeError`. The push loop
  re-raised that error, taking the agent permanently silent ("agent silent for
  >120s") over a single bad field. Replaced with a 3.8-safe suffix strip and
  hardened `_push_loop` so a collector failure now skips one cycle instead of
  killing the loop. (agent `__version__` → 1.8.2)

## [1.9.0] - 2026-06-28

### Added

- **Email (SMTP) notification channel** — alerts can now be delivered by email.
  Configure SMTP host/port, transport security (STARTTLS / implicit TLS / none),
  from + recipient addresses and optional auth in Settings → Email (the password is
  stored encrypted). Email is attempted only when host, from and to are set.
- **Telegram is now configurable in the UI** — the bot token (secret) and chat ID
  moved from env-only into Settings → Telegram, like Mattermost. The env vars still
  seed first-boot defaults.
- **Per-channel alert routing** — each channel (Mattermost / Telegram / Email) now
  chooses *which* alerts it receives, like the Checkmk export selection: a matrix of
  alert categories (`availability` for instance up/down, plus every service-check
  category — cpu, cert, gateway, ipsec…). Subscriptions are opt-in; `availability`
  is enabled for every channel by default so up/down alerts work out of the box.
  Service-check state changes are now emitted as alerts (routed by their category),
  not only recorded in history. (Alembic `017`, new `notification_routes` table.)
- **Settings page split into tabs** — General · Mattermost · Telegram · Email ·
  Checkmk, so each section stays short. Each channel tab carries its connection
  config plus its alert-category selection and a per-channel test button.

### Removed

- **Generic webhook and ntfy notification channels** — dropped in favour of the
  three first-class, UI-configurable channels (Mattermost, Telegram, Email). The
  `DASH_NOTIFY_WEBHOOK_URL` / `DASH_NOTIFY_NTFY_URL` env vars are no longer read.
- **Interface-error check** — the per-interface driver error counters the agent
  already reports are now turned into a rate ((in+out errors)/sec, derived in the
  agent hub from two consecutive pushes) and evaluated per physical interface:
  WARN at ≥1/s, CRIT at ≥10/s. Pseudo interfaces (`lo`/`enc`/`pflog`/`pfsync`/…)
  and down links are skipped, and an interface with only a single sample yet (no
  rate) never invents a check. Surfaced in the dashboard and the Checkmk export.
- **Load-average check** — the agent now also reports the CPU core count
  (`hw.ncpu`), so the 5-minute load average is evaluated normalised per core: WARN
  at ≥2×, CRIT at ≥4× cores (the stable 5-min average is used, so a transient spike
  does not flap). Unlike the CPU check (utilization, WARN-only) this is a saturation
  signal and can go CRIT. Surfaced in the dashboard and the Checkmk export; skipped
  on direct-poll instances and pre-1.8.1 agents (no core count). (Agent
  `__version__` → 1.8.1.)
- **Checkmk export covers the newer checks** — the Settings → Checkmk export panel
  now lists the swap, pf state-table, NTP, vital-service and certificate check
  families as toggleable categories (they already reached Checkmk via the special
  agent, but could not be excluded from the Settings UI before). The category list
  is now documented as an invariant that must track every key `evaluate_checks`
  emits.
- **Third-party license notices** — `THIRD-PARTY-NOTICES.md` now lists every
  open-source component shipped in the production image (backend + frontend
  runtime closures) with its license and full license text, generated by the new
  `just notices` recipe (`scripts/gen_notices.py`, stdlib-only). The notices file
  plus `LICENSE` and `LICENSING.md` are now copied into the container image, so
  the BSL text and all bundled-dependency attributions travel with each copy.
  `LICENSING.md` gained a "Third-party components" section noting that all
  dependencies are permissive except asyncssh (dual EPL-2.0/GPL-2.0-or-later, GPL
  arm used) and certifi (MPL-2.0, used unmodified) — no strong copyleft.
- **SBOM** — the same `just notices` (alias `just sbom`) run now also emits
  `sbom.cdx.json`, a CycloneDX 1.6 Software Bill of Materials of the shipped
  runtime components (PyPI + npm, with purls and SPDX licenses), validated against
  the CycloneDX 1.6 schema and copied into the container image. Covers application
  dependencies; base-image OS packages are out of scope (scan the built image with
  syft for those).

### Fixed

- **Checkmk export preview no longer errors** — `GET /api/checkmk/preview`
  (the live "what the export emits" view in Settings) returned HTTP 500 since the
  service/certificate checks were added, because it unpacked the wrong number of
  values from the gather step and dropped services + certificates. It now mirrors
  the real export exactly.

## [1.8.0] - 2026-06-28

### Added

- **Check / alert history** — every state change of a service check (OK↔WARN↔CRIT) is now recorded as a transition and shown in a new "Check history" panel on the instance Overview (most recent first). The agent-push ingest re-evaluates checks each push and diffs them against the previous states; the previous states survive a backend restart, so a restart does not re-fire every check, and the very first push only records a baseline. Retention is configurable (`DASH_CHECK_EVENT_RETENTION_DAYS`, default 90 days) with a daily prune job. (Alembic `016`, new `check_events` table.)
- **Certificate expiry monitoring** — the agent reads every certificate and CA from `config.xml` (parsed via `openssl`, since the agent is stdlib-only) and the instance Overview now lists them with their expiry and remaining days (soonest first, the active web-GUI certificate flagged). New `cert:*` checks: WARN under 30 days, CRIT under 7 days or already expired — surfaced in the dashboard and the Checkmk export. Works on OPNsense and pfSense.
- **Configuration status** — the instance Overview now shows when `config.xml` was last changed and by whom (from the agent's `<revision>`, incl. the change description) and when a config backup was last downloaded through the dashboard (from the audit log), each with a relative "x ago". Makes config drift and stale backups obvious at a glance.
- **Service status** — a new Services panel on the instance Overview lists every system service and whether it is running (OPNsense via `configctl`, pfSense via `get_services()`), stopped services sorted to the top. Vital-service checks raise CRIT when `sshd`/`configd` are down or when no DNS resolver (`unbound`/`dnsmasq`) is running; services absent on a box are never invented as red checks, and an unused resolver showing as stopped is not an alert.
- **System telemetry: load average, swap, pf state-table, NTP sync, interface errors** — the agent now collects, and the instance Overview/Network tabs now show, the 1/5/15-minute load average, swap usage, the pf state-table fill (current vs hard limit — a real exhaustion/outage signal that was previously invisible), NTP sync state (stratum/offset/peer), and per-interface error/collision counters. New service checks: `pf_states` (WARN ≥80 %, CRIT ≥95 % of the limit), `swap` (WARN ≥50 %, CRIT ≥80 %) and `ntp` (a reachable-but-unsynced clock is WARN, never CRIT, so a freshly booted box does not read red). Load and pf-state fill are also charted over time. Works on OPNsense and pfSense. (Agent `__version__` → 1.8.0.)

### Changed

- **License changed to the Business Source License 1.1 (BSL 1.1).**
  STYLiTE Orbit is now *source-available*: the source stays public and you may run
  it for your own organization, but offering it to third parties as a hosted /
  managed service or reselling it requires a commercial license from STYLiTE. Each
  released version automatically converts to GPL-3.0-or-later four years after its
  release. See [`LICENSE`](LICENSE) and [`LICENSING.md`](LICENSING.md).

## [1.7.0] - 2026-06-28

### Fixed

- **OPNsense firmware updates are detected again (point releases like 26.1.9 → 26.1.10)** — the agent relied on `opnsense-update -c`, which only reports base-set (release) upgrades and misses point releases that ship as the `opnsense` pkg. Its pkg fallback compared `pkg query`/`pkg rquery` but never refreshed the repo catalogue first, so `rquery` read a stale (often empty) cache and reported "Up to date" on boxes that genuinely had an update. The agent now runs `pkg update` before the compare and reports the real available version as `product_latest` (the Firmware tab's "Latest"). Both the periodic push and the on-demand "Check" use one shared code path. (Agent `__version__` → 1.6.9.)
- **A detected firmware update no longer flickers back to "Up to date" between checks** — the agent pushes every ~30 s but only runs the (network) update check every 10 min; the cheap interim pushes returned a stripped payload with no verdict, so the backend reset the instance to "Up to date" until the next full check. The interim pushes now carry the last cached verdict (`upgrade_available` + `product_latest`) and only refresh the installed version.
- **pfSense Branch / Train no longer shows "0000" (or junk like "0000.abi")** — the agent derived the train from the repo *filename*, but pfSense names its repo files `pfSense-repo-NNNN.conf` where `NNNN` is a meaningless index slot (older boxes use a bare `pfSense-repo.conf`), so a box without an explicit `pkg_repo_conf_path` in `config.xml` reported "0000", and `known_branches` leaked metadata files (`.abi`/`.altabi`/`.descr`). The train is now parsed from the package URL inside the active repo `.conf` (e.g. `pfSense_v2_8_1_amd64` → `2_8_1`, `pfSense_plus-v26_03_aarch64` → `26_03`), which is universal across CE/Plus and old/new layouts; `known_branches` is built only from `pfSense-repo*.conf` files. Verified on CE 2.8.1, Plus 26.03 and an old 2.6/2.7 box. (Agent `__version__` → 1.6.10.)

## [1.6.8] - 2026-06-28

## [1.6.7] - 2026-06-28

### Added

- **pfSense software train/branch is now visible in firmware status** — the agent reports the active update branch (from `<pkg_repo_conf_path>` in `config.xml` or the `pfSense.conf` symlink, e.g. "26.03", "26_03_1") plus best-effort `known_branches`. The Firmware tab and compliance view now display "Branch / Train". This makes it obvious which train a box is on; `pfSense-upgrade -c` (and therefore firmware checks) only ever reports updates inside the current train — newer major trains require an explicit branch switch first.

## [1.6.6] - 2026-06-27

### Security

- **Hardened DASH_TRUSTED_PROXY_HOPS validation** — the setting that controls how many X-Forwarded-For entries are trusted for login/enroll rate-limiting and audit source IP is now validated at startup. Negative values are rejected by Pydantic. In non-dev environments, values > 3 cause an immediate hard failure with a clear message (the previous default behaviour silently allowed configurations that let clients spoof IPs and completely bypass brute-force protection). The bundled compose and .env.example comments were tightened. (See also `trusted_proxy_hops` in config + `_validate_security`.)
- **Login no longer leaks which usernames exist via response timing** — the credential check short-circuited, running the (~50 ms) Argon2 verify only when the username existed, so a missing username returned noticeably faster. The login path now always spends one Argon2 verify (against a dummy hash when the account is absent), removing the enumeration oracle.
- **Notification webhook URLs are screened against SSRF to dangerous targets** — user-configured webhook/ntfy/Mattermost URLs (which the backend POSTs to) are now resolved and rejected when they point at loopback, link-local (incl. the `169.254.169.254` cloud-metadata IP), reserved, multicast or unspecified addresses. **Private RFC1918 ranges are intentionally allowed** — self-hosted notification servers on an internal network are a legitimate target, and an admin can already reach them via instance config, so blocking them would add no protection while breaking real setups. (`follow_redirects` stays off; DNS-rebinding at connect time is out of scope for this LOW, admin-only path.)
- **Agent writes root-executed helper scripts to private, unpredictable paths** — the uninstall/deprovision/boot-persistence scripts were written to fixed `/tmp` names and then run as root; with no `fs.protected_symlinks` on FreeBSD, a local unprivileged user could pre-plant a symlink there and redirect the root write/exec. They are now created via `mkstemp` (O_CREAT|O_EXCL, random name, mode 0600). (Agent `__version__` → 1.6.5.)

### Fixed

- **Stale-agent watchdog no longer fires a false "offline" alert for an agent that recovers mid-pass** — the watchdog decided offline from a snapshot read once at the top of the pass and held the DB session open across the (slow) notification send, so an agent that reconnected during the pass could be clobbered off the stale snapshot. The offline flip is now a guarded conditional UPDATE (only if no fresher push arrived since the snapshot), the clock is read per-instance, and notifications are sent after the session is released.
- **Interface throughput rates no longer flatline on low-traffic links** — `metrics.value` was a single-precision FLOAT (24-bit mantissa), so raw cumulative byte counters above ~16.7 M were quantized; subtracting two consecutive samples to derive a per-second rate then rounded small deltas to 0 (or a staircase). The column is now DOUBLE (migration `015`). Already-stored values keep their existing precision; new samples are exact.

## [1.6.5] - 2026-06-27

### Added

- **Alerts page** — new top-level **Alerts** view (`/alerts`) that lists every service check (memory, CPU, disks, gateways, IPsec, firmware, ping monitors) across all instances — the exact data Checkmk receives via the export. Filters: "Problems only", search, and Checkmk visibility ("All" / "Exported" / "Excluded"). Each row links back to the instance and shows exclusion reason (category vs specific rule). The list is sorted worst-state first and refreshes every 30 s. Exclusions still affect only the Checkmk export; the dashboard and this page always show the complete set.

### Security

- **SSH private key no longer leaks into the audit log** — editing an instance's SSH key (`PATCH /instances/{id}`) previously serialized the ed25519 **private key** in cleartext into the permanent audit trail (and it was readable back via `GET /audit`), because the audit redaction only excluded `api_key`/`api_secret`. The audit `detail` is now built from an **allowlist** of safe fields; secrets (api_key/api_secret/ssh_key/ca_bundle) are never recorded by value — only the fact that one was rotated is logged, by name.
- **Securepoint SSH enrichment now verifies the box's host key (fail-closed)** — `swanctl`/diagnose connections previously ran with host-key verification effectively disabled (the pin was never captured or stored), so an on-path attacker could impersonate the firewall's SSH server and feed the dashboard fabricated IPsec state. Command-running connections now refuse to proceed unless the host key is pinned, and the key is captured trust-on-first-use when SSH enrichment is enabled/saved. **Action required:** existing SSH-enabled instances have no pinned key yet — until you re-save each instance (or it is re-saved) to capture the key, IPsec enrichment falls back to the spcgi API (no SPIs/byte counters). Pinning assumes the path is clean at capture time (TOFU).
- **Agent self-update refuses downgrades (anti-rollback)** — the agent verified an update's Ed25519 signature but not its version, so a compromised dashboard could replay an older — still validly signed — agent build to reintroduce a fixed vulnerability. The agent now rejects any pushed build whose embedded `__version__` is not strictly newer than the running one. The check reads the version from the signature-covered code (not the unsigned push parameter), so it can't be forged.
- **Agent enrollment now verifies the dashboard's TLS certificate** — the bootstrap step (exchanging the one-time enroll code for the long-lived agent token) ran through a shared HTTP helper that disabled certificate verification for all HTTPS, so an on-path attacker could intercept the code/forge the token. Verification is now on by default and skipped only for the box's own self-signed loopback API (the persistent WebSocket already verified). (Agent `__version__` → 1.6.4.)
- **Agent GUI tunnel can no longer be aimed at arbitrary hosts** — an "open" tunnel frame could carry a host/port that the (root) agent connected to, turning a compromised dashboard into a TCP pivot into the firewall's networks. The destination is now pinned to the configured local GUI target; server-supplied host/port are ignored (mirroring the HTTP relay).

### Fixed

- **Agent reconnect race made firewalls appear stuck-offline for commands** — on an overlapping reconnect (self-update restart, network blip, supervisor respawn) the dying old WebSocket's teardown could unregister the freshly-reconnected agent. The box kept pushing metrics (showed online) but every command/relay/tunnel/update/GUI/uninstall returned `503 agent not connected` until a clean reconnect. Agent unregistration is now identity-aware, so only a connection can remove itself.
- **ntfy notifications silently failed on every real alert** — alert titles are emoji-prefixed (🔴/✅), but ntfy received the title via an HTTP header (latin-1 only), so each send raised `UnicodeEncodeError` and was swallowed as `failed` — while the **Test** button (plain-ASCII title) reported `sent`, hiding the breakage. ntfy now uses JSON publishing (title carried in the UTF-8 body), and the test notification uses an emoji title so it exercises the same path a real alert takes.
- **GUI-proxy/relay tunnels can no longer exhaust backend memory** — each tunnel stream buffered agent frames on an unbounded queue, so a fast firewall + slow client (or a misbehaving agent) could grow it without limit. The buffer is now bounded; on overflow the stream is torn down (backpressure) instead of buffered.
- **Telegram alerts no longer dropped by Markdown metacharacters** — alerts were sent with `parse_mode: Markdown`, so a lone `*`/backtick or a truncated entity in an error string made Telegram reject the whole message (HTTP 400) — silently losing the offline alert, which embeds an arbitrary error string. Alerts are now sent as plain text.
- **A non-JSON 200 from an OPNsense box no longer fires a false "offline" alert** — a 200 response with an HTML body (captive portal, WAF, or an API key lacking the endpoint privilege) raised an unhandled decode error that aborted the whole poll, dropping all metrics for the cycle and alerting the box as offline. Such responses are now handled per-endpoint, so the poll degrades to a partial result instead of failing.
- **Agent `insecure_skip_sig` config flag now works** — the dev-only flag read a non-existent global, so it was always a no-op (the env var `AGENT_INSECURE_SKIP_SIG` still worked). It now reads the active config. Fail-secure either way — it could only ever fail to *disable* the self-update signature check, never weaken it.

## [1.6.4] - 2026-06-27

### Added

- **Checkmk export: optional non-piggyback (flat) mode** — set `ORBIT_PIGGYBACK=0` on the special agent to stop creating one Checkmk host per firewall. Instead every check is emitted on the single host that runs the agent, with each service item prefixed by the firewall name (`opnsense-fw01/memory`, summary `[opnsense-fw01] …`) so they don't collide. Default stays piggyback (one host per firewall) — no change unless you opt in. Documented in `CHECKMK.md` / `checkmk/README.md`.
- **Mattermost notifications, configurable in the UI** — instance up/down alerts can now be posted to a Mattermost channel via an incoming-webhook URL set under **Settings → General → Notifications** (admin-only). The webhook URL is a **secret**: stored Fernet-encrypted at rest, masked in the API (`••••••`) and shown as a password field. A **Send test** button posts a test message to every configured channel and reports per-channel status (sent / skipped / failed). The notifier now reads its config through the live override layer, so Mattermost (and the existing webhook/Telegram/ntfy channels) pick up changes without a restart.
- **General settings editable in the UI (Settings → General)** — operational defaults that previously only came from `.env` can now be overridden at runtime, admin-only: default poll interval, scheduler tick, poll concurrency, default agent push interval, agent-offline floor, metrics retention, IPsec-event retention, GUI-proxy idle close, and log level. Each shows its env default, a *custom/default* source chip, and a *needs restart* badge where applicable; reset reverts to the env value. Overrides live in a new sparse `app_settings` table (migration `014`) and are layered over the env defaults — the poller and maintenance jobs read them **live**, while `poll_tick_seconds` / `gui_idle_minutes` / `log_level` apply on the next restart. Infra/security settings (database URL, master key, env, proxy hops, admin password) stay environment-only and cannot be set here. (Single-worker deployment assumed for the override cache.)

## [1.6.3] - 2026-06-27

### Added

- **Settings page (admin-only) with Checkmk configuration** — a new `/settings` page (gear in the nav, visible to admins only). First section is Checkmk: **manage API keys in the UI** (create a re-viewable key whose token is kept Fernet-encrypted so it can be revealed/copied again later, with a ready-to-paste `ORBIT_URL` / `ORBIT_API_KEY` snippet; revoke drops the recoverable copy), and **choose what gets exported** — every check is exported by default, but you can switch off a whole category globally (memory/cpu/disk/gateway/`ipsec.service`/`ipsec.tunnel`/`ipsec.tunnel_ping`/firmware) or exclude a single service on one instance, with a live per-instance preview of the current checks and their states. Exclusions affect **only** the Checkmk export; the dashboard's own views still show everything. New `require_admin` dependency guards the settings/API-key endpoints. (Backend: `checkmk_export_exclusions` table + revealable API keys, migration `013`.)
- **`CHECKMK.md` — full Checkmk integration guide** — a single operator doc covering the pull architecture, the complete list of exposed services (memory/cpu/disk/gateway/`ipsec.service`/`ipsec.tunnel`/`ipsec.tunnel_ping`/firmware) with their state thresholds and perfdata, the IPsec ping-monitor conditions (agent-mode + configured monitor only), read-only API-key auth, the datasource-program wiring with a wrapper, piggyback host-name matching, and troubleshooting. Linked from `README.md` and `checkmk/README.md`.

### Fixed

- **Wrapped tunnel names rendered centered instead of left-aligned** — long IPsec tunnel names that wrap onto two lines (e.g. `Sigma - Caritas Neuss Anexia`) appeared centered in the **Tunnel** column of both the global VPN overview and the per-instance IPsec view, while single-line names sat left — an inconsistent ragged look. Cause: the name sits in a `<button>`, which the browser defaults to `text-align: center` (Tailwind preflight doesn't reset it); the centering was only visible once the text wrapped. The name buttons now force `text-left`, so wrapped lines align under the first line.

## [1.6.2] - 2026-06-27

### Changed

- **VPN overview readability tweaks** — the Phase-2 ping rollup ("ping ok" / "ping fail" …) no longer wraps onto two lines, the table keeps a `1080px` minimum width (so columns stop squeezing on narrower windows and scroll instead) while still stretching to fill wider browsers, and an expanded tunnel **join** now draws a continuous bright-emerald left rail plus a faint tint down its member rows so they read as belonging to that pairing. Unpaired single tunnels (no peer) render flat — without the rail/tint — so they no longer look attached to the join above them.

## [1.6.1] - 2026-06-27

### Security

- **Fail-closed startup when the master key is missing/invalid outside dev (F1)** — the session cookie and GUI-proxy HMAC derive from `DASH_MASTER_KEY`; an empty key silently fell back to a public constant, allowing forged `dash_session` cookies. The app now refuses to start when `DASH_ENV` is not `dev` unless `DASH_MASTER_KEY` is a valid Fernet key; dev still allows the insecure fallback but logs a loud warning.
- **`X-Forwarded-For` is no longer trusted blindly (F2)** — the client IP used for login/enroll rate-limiting and audit `source_ip` was read from the leftmost `X-Forwarded-For` value, which any client can spoof (bypassing the brute-force lockout, forging audit attribution). It now honours a new `DASH_TRUSTED_PROXY_HOPS` setting (default 0; compose sets 1 for the bundled nginx) and takes the Nth-from-last entry, falling back to the direct peer. Centralised into `app/net.py` (replaces the per-router `_client_ip` copies).
- **GUI tunnel WebSocket now does full session validation (F5)** — `/ws/tunnel/{id}` only checked for a `user_id` in the session; it now also verifies the user still exists and the `password_version` matches, so a cookie invalidated by a password change can't open a tunnel within its remaining lifetime.
- **`/api/health` no longer leaks the raw DB exception to anonymous callers (F4)** — on a DB failure the endpoint returned `detail: str(exc)` (driver/host/internal error text) to an unauthenticated caller. The detail is now logged server-side (`app.health` warning) and the response carries only `status`/`db`/`version`/`db_revision`.

### Changed

- **Previously-undocumented settings are now surfaced in `.env.example` and both compose files** — several `DASH_`/`TZ` knobs worked only off their built-in defaults and weren't exposed for ops to override: `DASH_POLL_TICK_SECONDS` (10), `DASH_PUSH_INTERVAL_SECONDS` (30), `DASH_AGENT_STALE_SECONDS` (120, agent-offline floor), `DASH_METRICS_RETENTION_DAYS` (30), `DASH_IPSEC_EVENT_RETENTION_DAYS` (90, VPN-history retention) and `TZ` (UTC). They are now forwarded by `compose.yml` / `compose-dev.yml` and documented in `.env.example`. No behaviour change — every default is unchanged.

## [1.6.0] - 2026-06-27

### Added

- **VPN tunnel history as a colour-coded timeline** — the per-tunnel History dialog now leads with a scatter chart that plots each recorded event by time, grouped into lanes (Ping / Phase / Tunnel down / Tunnel up) and coloured per event type (green up/ping-ok, red down/ping-fail, amber Phase 2), with a hover tooltip showing the child, old→new value and full timestamp. A 24h / 7d / 30d / All window toggle keeps the chart readable as history grows (defaults to the narrowest window that still has events); the dialog now pulls up to 500 events. The detailed newest-first text list stays below.

- **Securepoint SSH enrichment for IPsec pairing** — opt-in per Securepoint instance: the dashboard runs `swanctl --list-sas/--list-conns --raw` over SSH (read-only) to get the IKE cookies, ESP SPIs and per-tunnel byte counters the spcgi API doesn't expose, so a Securepoint tunnel pairs with its peer firewall in the VPN overview even across NAT (cookie-based pairing). Per-instance ed25519 private key, Fernet-encrypted at rest (the public half is installed on the box; optional host-key pinning, fail-closed on mismatch when set); SSH failures fall back to the plain spcgi view. New `just gen-ssh-key`; setup guide in `docs/securepoint-ssh.md`. Still a pull model — no agent on the box.

- **Securepoint UTM as a direct-poll device type (read-only)** — pick "Securepoint UTM" in the Add-instance form (username/password instead of API key/secret; self-signed certs allowed by default; no agent — the Agent tab is hidden for Securepoint). The dashboard polls the appliance's `/spcgi.cgi` JSON API (session auth) and surfaces its IPsec service + tunnel status in the VPN view (one row per Phase-2 selector grouped into a tunnel) plus host metrics — CPU %, memory, disk, uptime, per-interface IP addresses and firmware version (with available-update detection from `system info`) — mapped onto the same shape as OPNsense/pfSense. Read-only: tunnel connect/disconnect and IPsec restart report "not supported (read-only)". The credential read path never calls `ipsec get` (which would expose the PSK).

- **Per-instance poll/push interval** — set how often each device is polled (direct mode) or how often its agent pushes (push mode) in the Add/Edit-instance form, overriding the global defaults (empty = inherit, minimum 5s). The poller now ticks every `DASH_POLL_TICK_SECONDS` (default 10) and polls each instance on its own effective interval, so a box can run faster *or* slower than the `DASH_POLL_INTERVAL_SECONDS` default (30). A changed agent push cadence is mirrored to a connected agent live (applied on its next push) and re-sent on reconnect; the agent-offline threshold now scales with the per-instance push interval (~4 missed pushes) so a deliberately slow agent isn't falsely flagged offline. New global default `DASH_PUSH_INTERVAL_SECONDS` (30). (Agent `__version__` → 1.5.8.)

### Fixed

- **IPsec tunnel could show as down/`%any` when a passive half-open SA shared its connection name** — strongSwan's `swanctl --list-sas --raw` can emit two records under one connection name (the live ESTABLISHED SA plus a `%any`/CREATED half-open responder). The vici parser merged repeated section keys, so the half-open overwrote the established record's host and IKE cookie — a tunnel that was up read as CREATED/`%any` with a zeroed responder SPI (breaking status and cross-instance pairing). The parser now disambiguates colliding section keys so both survive and the established SA wins. Affects both the new Securepoint SSH path and the OPNsense/pfSense agent. (Agent `__version__` → 1.5.9.)

- **IPsec ping-monitor option hidden where it can't run** — the per-Phase-2 "Add/Edit ping" affordance (per-instance IPsec view and the global VPN overview) is now shown only for agent-mode instances. Ping checks execute on the firewall through the agent, so the option never worked on direct-poll instances (Securepoint, direct OPNsense); it no longer appears there, and the overview skips the per-instance ping-monitor fetch for them.

## [1.5.4] - 2026-06-26

### Added

- **Sortable columns on the Instances, VPN and Firmware lists** — click a column header to sort (toggles asc/desc, arrow shows the active column). Instances sorts by status / name / location / mode / tags / last poll (applies to both list and card views); Firmware by status / instance / location / installed / latest / updates / last check; VPN by instance / tunnel / remote / status / Phase 2 / uptime / IN / OUT. Shared `useSort` hook + `SortHeader` component.
- **Optional VPN aggregation** — the global VPN overview's paired-tunnel grouping is now toggleable via a **Grouped / Flat** button. Flat shows every tunnel end as its own sortable row (grouping/collapse off); Grouped keeps the paired view with the combined-health header and collapse. The choice is remembered (localStorage).

### Fixed

- **pfSense IPsec traffic selectors showed a `|/0` suffix (e.g. `10.3.3.0/24|/0`)** — pfSense's strongSwan reports traffic selectors with a trailing protocol/port part (`10.3.3.0/24|/0`) where OPNsense reports a bare subnet. The agent passed it through verbatim, so the VPN overview's Phase-2 rows showed `10.3.3.0/24|/0 → 10.1.1.0/24|/0` on pfSense ends, and the suggested ping source broke (`ipaddress.ip_network` can't parse the suffix). The agent now normalizes selectors to just the subnet (strips any `|proto/port` or `[proto/port]` tail) in both the SA and conn parsers. OPNsense unaffected. (Agent `__version__` → 1.5.7.)

## [1.5.3] - 2026-06-26

### Fixed

- **Agent crash-looped on Python < 3.11 (`ImportError: cannot import name 'UTC'`)** — `from datetime import UTC` requires Python 3.11, so on an older pfSense shipping only `python3.8` the agent failed at import on every (re)start and never connected, even once the launcher found the 3.8 binary. The agent now aliases `UTC = timezone.utc` (same object on 3.11+), so it actually runs on Python 3.8+. (Agent `__version__` → 1.5.6.) Crash-looping boxes can't self-update — the fixed `orbit_agent.py` must be copied to the box (or reinstalled) once.

## [1.5.2] - 2026-06-26

### Fixed

- **Agent launcher now finds any Python 3 version** — the rc.d service and `run-agent.sh` supervisor resolved the interpreter from a hardcoded list (`python3`, `python3.11`, `python3.10`, `python3.9`), so an older pfSense shipping only `python3.8` (or a newer one with `python3.12`/`3.13`) had no match and the agent never started. They now prefer an unversioned `python3` and otherwise pick the **newest** `python3.N` found in `/usr/local/bin` or `/usr/bin` (version-agnostic glob), so the agent runs regardless of which Python minor the box ships. The agent code itself is Python 3.8+ compatible (stdlib-only, `from __future__ import annotations`). Note: the launcher scripts are install-time files — self-update only swaps `orbit_agent.py`, so already-deployed boxes need the launcher re-fetched (dashboard serves them at `/api/agent/run` and `/api/agent/rc`) or a reinstall.

## [1.5.1] - 2026-06-26

### Added

- **Instances list: status links to detail + box links in the action row** — the Online/Degraded/Offline badge (table and card views) now links to the instance detail page, same as clicking the name. The action row gains two direct box links between **Test** and **Edit**: the **primary web-UI URL** and, for agent/NAT'd boxes, the **tunneled WebUI** via the GUI-proxy handoff (same "Open GUI" flow as the detail page). The redundant **Details** button is removed. No backend change.
- **IPsec tunnel state-change history with a popup on the VPN overview** — the dashboard now remembers each tunnel's past states, not just the current one. On every agent push the backend diffs the new IPsec snapshot against the previous one and appends the transitions to a compact event log (Alembic `010`, `ipsec_tunnel_events`): Phase-1 up/down (and other status changes), Phase-2 installed-count changes (e.g. `2/2 → 1/2`), and per-child ping `ok`/`fail`. A new **History** button on each tunnel row in the VPN overview opens a popup with the newest-first timeline (`GET …/ipsec/{tunnel_id}/history`). It's a transition log (one row per change, not periodic snapshots), keyed on the stable swanctl connection name, and the previous snapshot survives a backend restart (re-hydrated from `status_snapshot`) so reboots don't fabricate events. Retention is `DASH_IPSEC_EVENT_RETENTION_DAYS` (default 90) via a daily prune job. Push-mode only — direct-API instances return an empty history. No agent change required.

### Fixed

- **Phase-2 ping-check dialog prefilled an unpingable destination** — a new ping monitor prefilled the destination with the raw remote traffic selector (e.g. `192.168.48.0/24|/0`), a network, not a host, so "Test now" failed unless the user hand-edited it. It now derives a concrete pingable host from the remote selector (network + 1, a common remote gateway/firewall IP) — `192.168.48.0/24|/0` → `192.168.48.1`; a host or `/31`-`/32` selector is used unchanged. Still editable.
- **pfSense agent did not restart after a reboot** — pfSense (unlike OPNsense / stock FreeBSD) does not auto-start rcvar services from `/usr/local/etc/rc.d/` at boot, so the installed rc.d script + `orbit_agent_enable=YES` never fired and the agent stayed down until started by hand. The agent now registers pfSense's native `afterbootupshellcmd` boot hook (`/usr/local/etc/rc.d/orbit_agent onestart`) at every startup — idempotent and non-destructive (skips if present, appends rather than clobbering any existing command). Already-deployed pfSense agents self-heal on the next deploy: the self-updated code runs this on start. OPNsense unaffected (no-op). (Agent `__version__` → 1.5.5.)

## [1.5.0] - 2026-06-26

### Added

- **Paired-tunnel view in the VPN overview** — the global VPN overview now detects the two ends of the same site-to-site tunnel across managed instances (e.g. opn1↔opn2) and renders them grouped under one header with a combined health badge that flags asymmetry (`status mismatch` / `ping mismatch` / `both up` / `both down`). Pairing is keyed primarily on the **IKE cookie pair** (`initiator`+`responder` SPI — identical on both ends and NAT-proof), falling back to the reversed transport-IP pair for down / pre-establish tunnels. Healthy (`both up`) pairs collapse to a single header row showing the link uptime (expandable, plus an "Expand/Collapse all" toggle); mismatched/down pairs stay expanded. A tag-filter chip row (mirroring the Instances list) lets you scope the overview to selected instance tags. The agent now also reports the IKE SPIs and per-child ESP SPIs (`spi-in`/`spi-out`). (Agent `__version__` → 1.5.4.)
- **"Test now" button for Phase-2 ping checks** — the config dialog can run a one-off ping through the agent (`POST …/ipsec/ping-monitors/test`, agent command `ipsec.ping_test`) with the entered source/destination *before* saving, so a wrong source IP or unreachable destination is caught immediately (green reply / red no-reply / amber misconfig). Agent-mode only. (Agent `__version__` → 1.5.1.)
- **Optional per-Phase-2 ping check for IPsec tunnels** — each IPsec Phase 2 (child SA) can be given an optional source + destination address that the agent pings every push cycle, so a tunnel that is `INSTALLED` but not actually passing traffic is caught and shown red (state `ok` / `fail` / `error`). Monitors are configured per child SA in the WebUI (with a suggested source from the Phase-2 local selector), stored on the dashboard (Alembic `009`), pushed to the agent, and surfaced as a Checkmk check (`ipsec.tunnel_ping:<tunnel>/<selector>`). The instance VPN view and the global VPN overview now also list each tunnel's Phase 2 entries with their individual status.

### Changed

- **Faster Phase-2 ping checks** — the agent now paces ping packets 0.3s apart (`ping -i 0.3`, sub-second interval allowed as root) instead of the default 1s/packet, and tightens the per-probe deadline from `max(count+1, 3)` to `max(count, 2)`s. A healthy tunnel now answers in ~0.6s instead of ~2s (count 3), and a dead/timing-out tunnel waits ~3s instead of ~4s — pings already run concurrently (up to 8 workers), so this shortens each push cycle's worst case. (Agent `__version__` → 1.5.3.)
- **Agent disk metrics drop pseudo filesystems and collapse ZFS pools** — `collect_disk` now reads `df -T` and skips pseudo filesystems (`devfs`, `fdescfs`, `procfs`, `nullfs`, `linprocfs`, `linsysfs`), and reports a single entry per ZFS pool instead of one row per dataset (datasets in a pool share the same free space). The collapsed entry keeps a stable label (the pool's `/` mount) but reports the pool's **worst** dataset fill, so a separate dataset filling up (e.g. `/var/log`) is still surfaced rather than masked by a near-empty root. On a stock OPNsense/ZFS box this cuts the disk rows from ~16 to ~2 per push, shrinking the stored time-series substantially at fleet scale. (Agent `__version__` → 1.4.3.)

### Removed

- **Unused `metrics_5m` rollup table** — the 5-minute rollup was write-only: `read_metrics` always buckets from the raw `metrics` table on the fly (every chart range, including 30d), so nothing ever read `metrics_5m`, yet its 365-day retention made it the bulk of the DB footprint. The table (Alembic `008`), the `rollup_5m` scheduler job, and the `DASH_METRICS_5M_RETENTION_DAYS` setting are removed. Raw-metrics retention (`metrics_retention_days`, 30d) is unchanged and still serves all existing charts.

### Fixed

- **IPsec Phase-2 count inflated during a child-SA rekey (e.g. "4/2")** — a make-before-break child-SA rekey briefly lists two SAs for the same traffic-selector pair (old `INSTALLED` + new), and the agent counted each, so `phase2_up` exceeded `phase2_total` and bytes were double-counted (and the Phase-2 detail list showed duplicate rows). The agent now collapses child SAs per selector pair, keeping the `INSTALLED` / higher-traffic one — mirroring the existing IKE-level rekey-dedup. (Agent `__version__` → 1.5.2.)
- **Edited instance fields only showed after a page reload** — saving the Edit-instance dialog invalidated only the `["instances"]` list query, not the detail page's `["instance", id]` query, so changes like toggling **Auto-login** weren't reflected on the open instance page until a full reload. The dialog now invalidates the detail query too.

## [1.4.2] - 2026-06-26

### Fixed

- **IPsec tunnel flashing red while up (agent)** — during an IKE rekey (make-before-break) strongSwan briefly lists two SAs for one tunnel: the old `ESTABLISHED` SA still carrying the installed child + traffic, and a new `CONNECTING` SA mid-handshake. The agent indexed SAs last-wins, so a poll landing in that window surfaced the transient `CONNECTING` SA and the dashboard showed a red/connecting tunnel that was actually established and passing bytes (seen on busy/idle tunnels that re-handshake often). The agent now prefers the `ESTABLISHED` SA (then the one with an installed child / traffic) per connection, and no longer leaks the rekey dup as a phantom extra row.

## [1.4.1] - 2026-06-26

## [1.4.0] - 2026-06-26

### Added

- **Self-update rejection reason in the GUI** — when an agent refuses a pushed update (e.g. signature or sha256 verification failed), the reason is now persisted on the connection and surfaced everywhere it's triggered: the single-instance agent panel ("Last update rejected (→ version): …"), a red "update rejected" badge per row on the Instances list (full reason on hover), and the "Update all agents" banner (shows how many were rejected and why). It survives a page reload instead of only flashing as a transient toast.

### Security

- **Agent self-update signing is now enforced** — the agent bakes an Ed25519 public key (`_UPDATE_PUBKEY`) and rejects any pushed update without a valid signature over the code, so a compromised dashboard can't push forged agent code (the dashboard only relays the offline-produced `.sig`). `release.sh` signs the agent automatically at release time (key from `DASH_AGENT_SIGNING_KEY` / `.env`), verifies the signature against the baked key, and aborts if no key is available — so only the offline key holder can cut a release. `scripts/sign_agent.py` gains `--verify`. The `.sig` is committed (it isn't secret); the private key stays offline.
- **Dev-only signature bypass** — the agent skips self-update signature verification when `AGENT_INSECURE_SKIP_SIG=1` (env, for a locally-run agent) or `insecure_skip_sig: true` in its config (installed agent) is set, logging a loud warning. Off by default; lets a dev iterate on the agent without re-signing. Never use in production.
- **Dev recipes auto-sign the agent** — `just dev`, `dev-up`, `up`, and `backend-run` re-sign the agent first when a signing key is available (`DASH_AGENT_SIGNING_KEY` env or `.env`), so the served `.sig` stays fresh and self-update verifies. No key → skipped, dev still starts.
- **Agent config written 0600** — `_persist_token` now writes the agent config file via `_write_private` (O_CREAT 0600 + fchmod) instead of `write_text`, which created it world-readable under root's umask. The file holds the `agent_token` and `local_api_secret`, so a local unprivileged process could previously read the agent's bearer credential.

## [1.3.0] - 2026-06-26

### Changed

- **Agent installation guide: one-paste install** — the OPNsense/pfSense agent guide now combines the former download, config, and start steps (4–6) into a single copy-paste block, so the whole install runs from one command box.

### Fixed

- **GUI proxy: surface a missing `DASH_GUI_CADDY_ADMIN_URL`** — when the prod GUI proxy is enabled but the Caddy admin URL is unset, the vhost hot-load silently no-opped and every `gui-<slug>` host returned a blank `200`. The backend now logs `gui_caddy.admin_url_unset` at startup, and the docs (README, `.env.example`, `compose.yml`) state the variable is required and that the compose default does **not** carry over to a hand-written / Swarm stack.

## [1.2.0] - 2026-06-26

### Added

- **Persistent GUI URLs via instance slug** — each instance gets a stable, URL-safe `slug` (auto-derived from its name, e.g. "Firewall Büro Süd" → `firewall-buero-sued`; editable and unique). The prod GUI proxy origin becomes `https://gui-<slug>.<domain>` (`DASH_GUI_BASE_TEMPLATE=https://gui-{slug}.…`) instead of the numeric `gui-<id>`. The slug stays put across name edits, so the GUI URL is durable.

### Changed

- **Prod GUI-proxy Caddy is now hot-loaded** — because the public host is a slug (not arithmetic from the id), the host→port map lives in the DB. The mounted `Caddyfile.gui-prod` is just a bootstrap (admin API + empty wildcard); the backend regenerates the per-slug vhost map and pushes it through Caddy's admin API on every instance create/slug-change/delete and at startup. No more `gui-1..gui-25` cap or manual file regeneration. The external Traefik wildcard rule widens from `gui-[0-9]+` to `gui-[a-z0-9-]+` (examples given in both Traefik v2 and v3 syntax).

## [1.1.1] - 2026-06-26

### Added

- **Multiple base URLs per instance** — the Base URL field accepts a comma-separated list; every entry renders as a clickable web-UI link (header + card views). The first URL is the API endpoint used for direct-mode polling.

### Changed

- **Mode-aware instance edit form** — agent-mode instances now hide the direct-API-only fields (API key/secret, Skip-SSL) and expose the GUI **Auto-login** toggle instead (moved here from the agent panel), matching the add-instance dialog.

## [1.1.0] - 2026-06-25

### Added

- **GUI auto-login** — opt-in per instance ("Auto-login" toggle on the agent's Firewall GUI card). When enabled, "Open GUI" replays the firewall's WebUI login through the agent and lands the browser already signed in instead of on the login page. The agent reuses the existing `orbit` user (no new dashboard-stored secret): on pfSense the relay password doubles as the WebUI password; on OPNsense the agent mints + caches a dedicated WebUI password. Verified end-to-end on OPNsense 26.1 and pfSense 2.8.

### Fixed

- Agent credential cache files (`*.apikey`, `*.guipw`) are now created mode 0600 from the start (no brief world-readable window before chmod).
- The generic `/agent/command` endpoint refuses internal actions and masks credential-bearing keys before writing command results to the audit log.

## [1.0.0] - 2026-06-25

### Added

- **pfSense support** alongside OPNsense — a platform-dispatch layer in the agent (shared collectors for CPU/mem/disk/interfaces/IPsec; per-platform gateways + firmware).
- **Push agent** (`agent/orbit_agent.py`, stdlib-only) for firewalls behind NAT: outbound `wss://…/api/ws/agent`, periodic metric pushes, FreeBSD `rc.d` service + supervisor.
- **Agent lifecycle** — one-time enrollment (trade a code for a token), dashboard-triggered self-update (Ed25519 signing tooling via `just sign-agent`; verification off by default), and uninstall.
- **Relay** — the dashboard tunnels HTTP to a box's own REST API over the agent WebSocket, so it stays keyless; local API port auto-discovered from `config.xml`.
- **Checkmk/OMD export** — `/api/export/checkmk` + a special-agent plugin (`checkmk/`): one piggyback host per firewall with OK/WARN/CRIT service checks.
- **Service checks** — per-service OK/WARN/CRIT evaluation and a `/api/checks` endpoint.
- **Read-only API keys** for service accounts (hashed at rest, non-GET rejected) — used by the Checkmk integration.
- **Bulk actions + CSV export** across multiple instances (`firmware_check`, `ipsec_restart`).
- **Metrics retention + 5-minute rollup** scheduler jobs (replacing TimescaleDB) and derived interface throughput rates.
- **Notifications** via webhook, Telegram, and ntfy.
- Last-known status persistence so a backend restart re-hydrates the dashboard before the next push.

### Changed

- **Rebranded** to STYLiTE Orbit (agent → `orbit`, backend package `app.opnsense` → `app.xsense`).
- **Database switched from PostgreSQL/TimescaleDB to MariaDB 11** (`mysql+aiomysql`).

## [0.10.0] - 2026-04-27

## [0.9.0] - 2026-04-27

## [0.1.3] - 2026-04-27

## [0.1.2] - 2026-04-27

## [0.1.1] - 2026-04-27

## [0.1.0] - 2026-04-27

### Added

- Initial release pipeline. Combined production container (frontend + backend served by nginx on :80, uvicorn on :8000 internally). Split dev compose with bind-mounted source for hot-reload. Backend migrated to `uv` + `src/` layout. `release.sh` for `major|minor|patch` version bumps. GitHub Actions workflow publishes multi-arch images to Docker Hub and GHCR on tag push.
