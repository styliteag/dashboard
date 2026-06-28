# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
