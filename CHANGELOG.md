# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.2.20] - 2026-07-23

### Added

- The fleet VPN page groups the two ends of a tunnel between two managed
  boxes into one link again (old frontend parity): peers are matched by the
  shared IKE cookie pair with a reversed-endpoint fallback, each pair gets a
  header row with a combined health badge (both up / status mismatch / ping
  fail / stale / …), healthy pairs collapse to just their header, and a
  Grouped/Flat toggle plus "Expand all" / "Collapse all" are back in the
  toolbar.

### Changed

- The duplicate-CHILD_SA warning ("⚠ 2× SAs") moved from the expandable
  phase-2 child rows up to the tunnel row itself (fleet VPN page and the
  instance's VPN tab) — it was invisible until you expanded the right
  tunnel. The tooltip lists every affected selector.

## [4.2.19] - 2026-07-23

### Changed

- "Add ping monitor" now prefills the Destination with the first host address
  of the far side's Phase-2 selector (e.g. `192.168.0.0/20` → `192.168.0.1`)
  — a best-guess gateway you can overtype, instead of an empty field. Selectors
  without a sensible single guess (`0.0.0.0/0`) stay empty; editing an existing
  monitor keeps its saved destination.

## [4.2.18] - 2026-07-23

### Changed

- Interface error-rate check (`iface_errors:*`) is far less noisy: it now
  needs a meaningful packet sample (a near-idle link with a handful of packets
  no longer reads as a nonsensical >100% error rate — seen: igc0.305 300% =
  6 err / 2 pkts), and it skips virtual/software interfaces (bridge, loopback,
  pf log/sync, VPN + tunnel devices, jail/VM and container veths) whose error
  counters are not a physical-link signal. VLAN sub-interfaces on a real NIC
  (igc0.203) stay eligible.

## [4.2.17] - 2026-07-23

### Fixed

- Linux agent self-update never worked: the image built `orbit_agent.py`
  (firewall) into `/app/agent` but not `orbit_agent_linux.py`, so
  `served_version(:linux)` was nil — no linux instance ever showed "update
  available", the dashboard could serve no linux update, and the linux install
  guide's `script_linux` download 404'd. The Dockerfile now copies both agent
  lines (and their `.sig`s). Linux boxes were stuck on their enrolled version
  since the agent split. Rebuild + redeploy the image, then canary one box.

## [4.2.16] - 2026-07-23

### Added

- ZFS checks for linux nodes: Orbit now parses the Checkmk
  `zpool`/`zpool_status`/`zfsget` sections into per-pool health + capacity
  checks (`zfs:<pool>` — ONLINE is OK, DEGRADED/FAULTED/… is CRIT, capacity
  warns at 80%%/crits at 90%%) and per-dataset quota checks (`zfs:<dataset>`,
  emitted only for datasets that carry a quota and sit within 80%% of it, so a
  filling share is visible without cluttering the surface with slack datasets).
  All show under Checks and ride every surface (Checkmk export, Prometheus,
  Alerts).
- Linux instances get a **Checkmk** tab on the detail page showing the raw
  `check_mk_agent.linux` output the box pushed (retained in-memory, refreshed
  each cycle) plus the services Orbit exports to a Checkmk server for the
  instance.
- Extension point for downstream builds: `config :orbit, :vendor_tabs` adds
  device-type-scoped tabs to the instance detail page, rendered from the
  instance's cache entry (now also given the current `chart_range`). Open ships
  none.
- Extension point `config :orbit, :vendor_metrics`: a downstream build can
  register `{module, fun}` extractors that append extra `{name, value}` series
  to each push's persisted metrics. The `metrics` table is generic (metric-name
  string + double), so this adds rows, never schema — open, which registers
  none, never writes or reads those names. Enables charting downstream-only
  series with the existing `metric_chart` component.

## [4.2.15] - 2026-07-22

## [4.2.14] - 2026-07-22

## [4.2.13] - 2026-07-22

### Fixed

- New-instance form: picking or removing a tag no longer wipes the values
  already typed into the other fields (every re-render reset unbound inputs).
- Hub status page loads fast on large fleets: the pushes/min chart query now
  has a matching index (it scanned every metric row in the 6h window), the
  roster is scoped with one query instead of one per connected agent, and the
  initial HTTP render no longer computes the whole page twice — the skeleton
  paints immediately and the live data follows on the socket join.
- Live views reached over a secondary hostname (`DASH_WS_ALLOWED_ORIGIN_HOSTS`)
  no longer silently degrade to long-polling: the LiveView websocket only
  accepted the PHX_HOST origin and rejected the extra names with 403, and a
  browser tab that fell back once (also e.g. across a deploy restart) stayed
  on long-poll for its whole lifetime. The extra hostnames are now allowed on
  the LiveView socket too, and a full page load forgets a memorized fallback
  and probes the websocket again.

### Changed

- New-instance form: the direct-API fields (base URL, API key/secret, TLS
  verification, CA bundle) only appear when transport "direct (API poll)" is
  selected. In agent mode they are hidden and the instance is created with an
  empty base URL, which the push path expects anyway.

## [4.2.12] - 2026-07-22

### Changed

- The agent is now split into two single-file lines (docs §28), both at version 4.2.12:
  version 4.2.12: `orbit_agent.py` for OPNsense/pfSense firewalls (keeps its
  historical name and behavior) and `orbit_agent_linux.py` for generic Linux
  nodes. The dashboard serves each instance the line for its device type —
  self-update, the install snippet and "Update all agents" pick automatically
  — and each line refuses to start on the other's platform, so a wrong push
  rolls back via probation instead of half-running. The linux line carries
  only server-relevant collectors (the Checkmk agent still does the heavy
  telemetry); the firewall line keeps relay, GUI proxy, IPsec and firmware
  upgrades. Existing agents migrate onto their line by normal self-update.
- Both lines are generated from one source tree (`agent/src/`: a shared core
  plus per-line templates and drop-in parts) via `just build-agent`; the
  committed agent files are the build output, and a test fails if they drift
  from the source. The shared core — WS client, self-update, enrollment, push
  loop, shell/capture, probation — now lives in exactly one place, so a fix
  reaches both lines by construction.
- The UI now names each instance's agent line: the instances list shows
  `agent fw` / `agent linux` next to the version, and the instance detail
  Agent tab lists the line with its source file.

## [4.2.11] - 2026-07-22

### Fixed

- Access tab showed "Online now 0" while operators were logged in and active:
  LiveView navigation rides the WebSocket and never stamped `last_seen_at`, so
  anyone working purely inside the app went "offline" after 5 minutes.
  Connected LiveViews now stamp the session registry on mount and every 60s.
  The session cookie also gets the 12h max-age the registry sweep always
  assumed — previously it was a browser-session cookie, and a login older
  than 12h was force-expired in the registry (permanently "offline") while
  the operator kept using it.

## [4.2.10] - 2026-07-22

### Changed

- **The audit page opens on the Access tab, pre-filtered to what usually
  matters.** Access is now the first tab and the one the page lands on, and its
  filter defaults to Logins + Blocked over the last 24h, grouped. The three
  header cards (Logins, Blocked, Requests) now count over the *selected* time
  window instead of a fixed 24h/all-time span, so they agree with the event
  list below and re-scope when you change the period (all time still uses the
  monotonic all-time block total).
- **Interface error checks now alarm on the error _rate_ (% of total packets),
  not an absolute since-boot count.** A busy 10G link passes orders of
  magnitude more frames than a mgmt port, so a fixed "1000 errors = CRIT" was
  routine on one and a dying transceiver on the other. `iface_errors:*` now
  grades errors ÷ total packets: **CRIT above 0.1%, WARN above 0.05%**. A link
  with no packet counters, or no traffic carried yet, emits no check rather
  than a fake zero. (Needs an agent that reports packet counts — see below;
  poll-only boxes are unaffected as before.)
- **Agents now report per-interface packet counters** (`in_packets`/`out_packets`
  from `netstat -ibn`), the denominator the interface error-rate check needs.
  Agent 3.1.9; existing agents keep working, they just don't feed the rate
  check until they self-update.

## [4.2.9] - 2026-07-22

## [4.2.8] - 2026-07-22

### Added

- **Log events: a "raw" toggle reveals the un-masked sample line for a pattern.**
  Each row's masked pattern can be expanded to the actual raw log line it was
  built from, in a full-width panel under the row. Admin-only — raw log content
  may carry sensitive data the pattern masking removed (invariant 4).

### Changed

- **Alerts: filter by instance tag instead of Checkmk-exported/excluded.** The
  exported/excluded filter chips are replaced by tag chips (parity with the
  Instances and Log-events pages). The page now shows every alert by default
  and narrows by tag; each row still shows its Checkmk exported/excluded badge.
  The severity-toned check-family tally chips (red/amber `ipsec.tunnel ×3` …)
  are also removed — the CRIT/WARN tiles and per-row state already carry that.
- **The VPN tunnel expand toggle is a larger, easier click target.** The
  phase-2 child-SA disclosure arrow grew from a 24px to a 32px button with a
  bigger glyph.
- **Log events: filter by tag instead of by instance name, and less clutter
  above the table.** The row of instance-name chips is replaced by tag chips
  (a large fleet had one chip per box); the per-program severity-toned tally
  chips are gone (every program was orange because the whole page is
  warning-or-worse by definition, so the colour carried no signal); and the
  intro note is trimmed to the essentials.

## [4.2.7] - 2026-07-22

### Changed

- **The Base URL is now a clickable link everywhere it appears, and a
  comma-separated list opens each endpoint.** The instance detail page showed it
  as plain text; the list linked only the first endpoint. Both now render every
  comma-separated URL as its own link (parity with the old dashboard, where a
  base URL could hold several). Only `http(s)://` values become links. A globe
  quick-link icon now also sits beside the instance name on the fleet lists
  (instances, firmware, certificates, hub, alerts, connectivity), opening the
  box's URL in a new tab next to the existing WebGUI/terminal icons.
- **A child SA with no reported status now shows a muted "—", not an alarming
  red "?".** On the IPsec overview, Phase-2 children whose strongSwan status
  text is absent were painted in error-red with a "?", which read as a fault on
  tunnels that were plainly up (and showed regardless of ping monitoring). The
  unknown state is now a neutral em dash; red is reserved for a child that is
  genuinely down.
- **The "Analyse with AI" output is now rendered as formatted Markdown instead
  of raw text.** The model replies in Markdown — a findings table, `###`
  headings, bold severities, inline code — which a plain `<pre>` showed
  literally as `### Findings` and `| Title | Severity |…` pipes. Both AI panels
  (the IPsec tunnel diagnosis and the Log-tab analyser) now render a real
  table, headings, lists and code spans. The renderer is dependency-free and
  builds escaped HTML from parsed tokens, so the model's untrusted
  (prompt-injectable) output can never render as live markup.

### Fixed

- **"local IP drift" is no longer flagged on tunnels that are up.** The badge
  compares a tunnel's pinned local endpoint against the box's public address,
  but on a box that owns more than one public IP — typical of a Securepoint
  carrying a WAN block — the derived "public address" is only the first
  interface address, so every established tunnel bound to a sibling public
  address was wrongly flagged. An established tunnel proves it owns its local
  address (you cannot hold a live IKE SA otherwise), so the hint is now
  suppressed for up tunnels entirely; a down tunnel is matched against every
  public address the box owns, not a single one. Vendor-agnostic — it also
  cleared false positives on direct-polled OPNsense/pfSense.
- **IPsec "Diagnose" works again for a Securepoint tunnel whose name contains a
  space.** Securepoint escapes a space in a strongSwan connection name as `$20`
  (`OCV MEH` → `OCV$20MEH`) and keeps that encoded form as the id, but the
  diagnose safety check rejected the `$`, so Diagnose returned only `unsafe
  tunnel id: "OCV$20MEH"` and never gathered the bundle. `$` is now accepted —
  it can only ever precede hex here and is single-quoted before it reaches the
  shell — while every shell-injection character stays rejected.

## [4.2.6] - 2026-07-21

### Changed

- **Timestamps now display in your browser's local time zone, not UTC.** Every
  clock on the dashboard (audit/access tables, hub status, instance cards,
  users, API keys, log-events, check/tunnel history) now renders in the
  viewer's own zone with the zone shown (e.g. `2026-07-21 22:53:10 CEST`),
  formatted client-side — no server time-zone configuration needed, and each
  viewer sees their own zone. With JavaScript disabled the original UTC value
  stays visible. Metric-chart axes and the timestamp in export filenames remain
  UTC on purpose; a couple of hover tooltips (relative-time cells, config
  revision time) also stay UTC.

## [4.2.5] - 2026-07-21

## [4.2.4] - 2026-07-21

### Fixed

- **The Checkmk export no longer 500s for any box with a live ICMP probe.** The
  probe's `rtt_ms` perfdata was built as a string-keyed map while every other
  metric (and both exports) uses atom keys, so the export crashed with
  `KeyError key :name` as soon as ICMP started reporting a round-trip time. The
  probe now emits the canonical `ServiceCheck.metric/3` shape.
- **The reachability probe no longer crash-loops on the slim release image.**
  On `debian-slim` (no `/etc/protocols`) the ICMP socket was opened with the
  `:icmp` protocol name, which the kernel could not resolve — every probe sweep
  raised `String.Chars not implemented for Tuple` and measured nothing. The
  socket now uses the IPPROTO_ICMP number directly, so ICMP probing works with
  no image or host change. When a runtime genuinely cannot open an ICMP socket
  (no `ping_group_range` gid and no `CAP_NET_RAW`) the probe now reports ICMP as
  "not measured" rather than a false "down", so HTTP probing and check grading
  are unaffected.

## [4.2.3] - 2026-07-21

## [4.2.2] - 2026-07-21

## [4.2.1] - 2026-07-21

## [4.2.0] - 2026-07-21

## [4.1.3] - 2026-07-21

## [4.1.2] - 2026-07-20

### Changed

- **The second-factor page offers a choice instead of demanding a code.** With
  both factors registered it led with the code field, autofocused, and put the
  passkey behind a divider below — so a passkey user typed six digits out of
  habit without noticing the one-click alternative. The passkey now comes
  first and carries the primary styling, the code form sits under the "or",
  and nothing grabs focus unless the authenticator is the only factor.

### Added

- **The 2FA setup page shows a QR code.** It only ever printed the base32
  secret and the raw `otpauth://` link, so enrolling an authenticator meant
  typing 32 characters by hand. Rendered inline as a PNG (2.7 KB, versus 173 KB
  for the same code as SVG) on a white plate so it scans against the dark page.
  A failure to render never blocks enrollment — the secret below it stays.
- **You can remove the authenticator app once a passkey is registered.**
  Security page, next to the TOTP status. The last remaining factor can still
  never be removed — the mirror of the existing passkey guard — and removing
  the authenticator clears its secret rather than just disabling it, so no
  usable key material is left behind. Both the denial and the removal are
  audited.

## [4.1.1] - 2026-07-20

### Changed

- **"GUI login" is called "Autologin GUI", and new instances get it on.**
  The flag makes the agent replay the firewall's own login so the proxy lands
  you inside the web UI instead of on its login form — which is the point of
  opening it, so it is armed on creation now (the create form has no checkbox;
  unchecking it in Edit still wins). Existing instances are unchanged: the flag
  has the agent mint and cache a web-UI password on the box, and flipping that
  on for boxes already in the field is an operator decision, not a migration.

## [4.1.0] - 2026-07-20

### Added

- **The edit form has the same tag picker as the new-instance form.** Editing
  tags meant retyping a comma-separated line, with no sight of what the rest of
  the fleet already uses — the one place where a spelling drifts apart from the
  filter chips. Both forms now share one picker, so a fix or a change of
  behaviour lands on both at once.
- **Creating an agent-mode instance mints its enroll code right away** and
  opens on the agent tab with the install snippet ready. Before, every new box
  needed the same three clicks — open the detail page, find the agent card,
  press "Mint enroll code" — before anything could be installed on it.

### Fixed

- **The install snippet no longer leaves an old agent running.** Pasting it on
  a box that already had one ended in `daemon: process already running` on
  OPNsense and pfSense, which aborted the start: the new config was written but
  the OLD agent kept running against the old dashboard, so the box looked
  installed and never appeared. Re-enrolling a box, moving it to another
  dashboard or simply pasting the snippet twice all hit this. The snippet now
  restarts the service (and on Linux restarts the unit instead of leaving a
  running one untouched).

## [4.0.10] - 2026-07-20

### Added

- **Tags, ping URL, push interval and notes can be set while creating an
  instance.** They existed only on the edit form, so every new box had to be
  saved and then reopened to get its tags — and until someone did, the fleet
  page's tag filter had nothing to filter on. The four fields now sit on the
  new-instance form and are written on creation.
- **The tag field on the new-instance form is a picker again**, as it was
  before the rewrite: chips for what is picked, a dropdown of the tags already
  in use on the boxes you can see, and a "Create …" entry for a new one. Typing
  a tag that exists in another case adopts the existing spelling, so "lab" next
  to the fleet's "LAB" no longer quietly becomes a second tag the filter chips
  can't merge. Suggestions are group-scoped: you are only offered tags from
  instances you can already see.

## [4.0.9] - 2026-07-20




### Changed

- **The GUI origin's hostname now follows `DASH_GUI_BASE_TEMPLATE` instead of
  an assumed `gui-` prefix.** The template was the documented way to name those
  origins, but the request side ignored it and matched a hardcoded `gui-`, so
  anyone running a second stack on one domain (`gui2-<slug>.example.com`) got a
  host the reverse proxy routed correctly and orbit then dropped through to the
  router — a bare "Not Found" that points at everything except the cause. A
  configured template is now authoritative and pins the domain as well, so a
  `gui-`-prefixed host on some other domain is no longer treated as a GUI
  origin. Deployments without a template keep the old `gui-<slug>` behaviour.
- **The dev install snippet points at an address a firewall can actually
  reach.** It was built from `Endpoint.url()`, which in dev fell back to
  `http://localhost:4000` — wrong twice: 4000 is the container-internal port
  (dev publishes 8000) and localhost is not reachable from a box, so a pasted
  block produced an agent that could never connect. Set `DASH_PUBLIC_HOST` to
  the dev machine's LAN address and the block is directly pasteable. Production
  was never affected; `PHX_HOST` already fed the same setting there.
- **The agent install instructions are one copyable block, with a copy button.**
  The three steps sat in three separate code boxes, so getting them onto a box
  meant three selections and three round trips to a root shell — they are one
  script and are now rendered as one. Worse, the panel was a native `<details>`
  on a tab that re-renders on the live agent tier: every refresh dropped the
  browser's open state and snapped it shut about a second after it was opened,
  which made it effectively unusable. The open state is held server-side now.
- **An invalid `DASH_MASTER_KEY` is caught at startup, not on the first
  instance you create.** A key that is not url-safe base64 of 32 bytes used to
  pass boot unnoticed and then crash the LiveView the moment somebody saved an
  instance — the operator saw the form reset with no message, and the log
  blamed a Fernet function four frames deep instead of naming the variable. The
  format is checked at boot now, with the generator command in the error.
  Worth knowing: `openssl rand -base64 32` alone is **not** a valid key (plain
  base64 uses `+` and `/`, which Fernet forbids — 72% of runs produce a key the
  app rejects). Append `| tr '+/' '-_'`. README, `compose.yml` and
  `.env.example` now spell this out, including the warning that changing the
  key on a populated database does not re-encrypt anything, it makes the
  existing rows unreadable.
- **Starting before the database no longer crashes the app.** Swarm and
  Kubernetes have no `depends_on`, so orbit routinely comes up first — and it
  died on the spot, writing an `erl_crash.dump`, for a race that resolves
  itself seconds later. It now polls for the database and then migrates,
  logging that it is waiting. The wait is bounded (`DASH_DB_WAIT_SECONDS`,
  default 60) so a wrong `DATABASE_URL` still fails loudly instead of hiding
  behind a container that looks like it is starting. Crash dumps are switched
  off in the image as well: in a container the file lands in a layer nobody
  keeps and only delays the restart.

### Changed

- **Documented what a reverse proxy in front of the dashboard has to do**, with
  a `scripts/ws_idle_probe.py` that names the offending layer in two minutes and
  needs no login. Every long-lived feature here is a websocket that is
  legitimately idle at times, and the common defaults are hostile — HAProxy's
  `timeout tunnel` has no default at all, so a `mode tcp` load balancer cuts
  every websocket at its 30s `timeout client`. README "Reverse proxy
  requirements".

## [4.0.8] - 2026-07-20

### Fixed

- **The GUI cookie's `Secure` flag no longer depends on the endpoint's
  scheme rewrite.** It is derived from `X-Forwarded-Proto` directly. In
  production this changes nothing — `force_ssl` already rewrites the scheme
  before any endpoint plug runs — but it removes a silent dependency between
  a cookie's security flag and a setting three layers away.
- **The browser no longer drops its live connection mid-form behind a proxy
  with a 30-second idle timeout.** Phoenix's client heartbeat defaults to 30
  seconds — exactly the idle timeout many reverse proxies and load balancers
  ship with — so every heartbeat raced the proxy's timer and losing one round
  killed the socket, discarding whatever was typed into an open form. The
  heartbeat is 20 seconds now, the same interval the agent has always used.
  Measured in a customer deployment: idle connections were cut at 30.0s, a 25s
  heartbeat survived indefinitely, a 30s one died immediately.
- **A too-short `SECRET_KEY_BASE` now refuses to boot instead of serving a
  broken dashboard.** Plug's cookie store requires at least 64 bytes and
  raises per request when it is shorter — so the release booted, migrated,
  reported healthy (the health endpoint holds no session and answered `200`
  all day) and then failed every actual page with "cookie store expects
  conn.secret_key_base to be at least 64 bytes". The length is checked at
  startup now, with the fix in the message. Reported from a Swarm deploy.

## [4.0.7] - 2026-07-20

### Security

- **Opening a root terminal or a live packet capture is audited again.** Both
  are the most privileged actions the dashboard offers, and neither left any
  trace — only the snapshot-capture path was recorded. Successful opens and
  refusals are now written to the audit trail with the operator, the box and
  the source IP. The capture entry records the interface but deliberately not
  the BPF filter, which can contain third-party addresses.
- **An abandoned root shell no longer stays open forever.** Sessions close
  after 30 minutes without operator input, and after 8 hours regardless.
  Output from the box does not count as activity, so a running `tail -f`
  cannot hold a forgotten session open.
- **The audit-detail allowlist is enforced where the row is written**, not
  left to each caller. It previously governed only the mirrored log line
  while the database kept whatever the caller passed — one new mutation route
  handing over a raw params map would have written secrets into a table that
  admins and superadmins can read.

### Added

- **A CA bundle can be stored again, and now actually does something.** A
  firewall's GUI certificate is self-signed, so the only way to poll a box was
  to switch TLS verification off entirely: the `ca_bundle` column existed and
  the retired dialog offered the field, but orbit wrote it nowhere and read it
  nowhere. Paste the CA that signed the box's certificate and verification is
  checked against it instead of being turned off. Offered on the polling path
  only — in agent mode the dashboard makes no outbound call to verify. Boxes
  without a bundle connect exactly as before, and a malformed bundle falls
  back to that rather than taking the box offline.
- **Terminal sessions can be recorded again** (`DASH_SHELL_RECORD_DIR`, empty by
  default). Every root shell writes one asciicast file, replayable with
  `asciinema play`. The retired dashboard had this; orbit did not, so the
  variable had been a dead name since the cutover. Recorded is the box's
  output only, never keystrokes — those carry the passwords the terminal does
  not echo, and writing them would put a plaintext password log on the
  dashboard host. 8 MB per session, after which the file closes with a note
  and the session continues unrecorded; a failing or full disk never touches
  the session. Works for agent and Securepoint SSH terminals alike.
- **The VPN page can graph the whole fleet at once**, over a 24h/7d/30d
  window. The per-tunnel graph answers "what did this tunnel do"; the question
  it could never answer is "did they all drop at 03:12, or is it just this
  one?" — one lane per tunnel over a shared window makes a fleet-wide event
  read as a vertical stripe. Loaded only when opened, and it says so when it
  shows only the first 40 rows rather than quietly truncating.
- **Tunnel graphs gained a window selector and a Phase-2 count track.** The
  graph used to span "oldest recorded event → now", so two tunnels drew the
  same picture at wildly different scales and neither said over what period.
  Short outages are also no longer rounded away to an invisible sliver — a
  two-minute drop in a 30-day view was 0.005 % wide. The new numeric track
  shows how many child SAs of how many were up: the colour lane says
  "partial" whether one of two dropped or one of eight.
- **Tunnels can be re-checked from the fleet VPN page.** Asking the box for
  fresh status without waiting for the next push existed only on the instance
  page — the fleet page, where you watch a tunnel you just reconnected, made
  you sit through the refresh interval.
- **A series upgrade asks you to type the instance name.** It was confirmed by
  a browser dialog identical to the ordinary firmware update's, one reflexive
  Enter away — for a major version jump that reboots a customer's firewall and
  cannot be undone from the dashboard. The confirmation now names the target
  version and the box and requires the box's name typed back, checked on the
  server rather than in the browser.
- **Addresses show their location outside the audit Actions table too.** The
  Timeline and the online-sessions tile showed a bare IP, which is where an
  unfamiliar address actually matters. All three now share one cell, so they
  cannot drift apart again; private and unknown addresses still render alone.
- **The instances list flags boxes with a console password**, and its status
  badge is a link. Fleet standard is no password on the console menu, and the
  instance page has said so for a while — but from the list there was no way to
  see which boxes deviate without opening each one. The status badge was also
  the one thing on a row that looked clickable and was not; it now opens the
  box it describes.
- **Connectivity monitors have a History button.** Orbit has been recording
  every check state change since the cutover, but nothing read those rows per
  monitor, so "has this link been flapping all week, or did it just drop?" had
  no answer in the UI. Both the fleet Connectivity page and an instance's
  Connectivity tab now open a timeline with the recorded transitions beneath
  it. Reading it needs no write role. Short outages are widened so they stay
  visible in a long window, and the dialog says plainly that failures are
  debounced over three polls, so a brief blip may leave no trace.

### Changed

- **The firewall GUI proxy no longer needs a Caddy sidecar.** Orbit already
  served the whole thing itself — host-matching the per-instance origin on its
  own port, the handoff, the cookie gate and the tunnel proxying — and dev has
  run that way since the Elixir cutover. The `gui-proxy` service, its
  Caddyfiles, `DASH_GUI_CADDY_ADMIN_URL` and `ORBIT_GUI_DOMAIN` are gone. In
  production you now only add a wildcard route on the reverse proxy you already
  run, pointing at orbit itself: pass the original `Host` through and set
  `X-Forwarded-Proto: https`. Nothing to regenerate when instances change, no
  extra compose profile, no admin API to keep off the network.
  **Upgrading:** drop `--profile gui` and the two variables; repoint your
  wildcard router from `gui-proxy:80` to `orbit:4000`.
- **Two ready-made Traefik examples for the GUI proxy, both covering v2 and
  v3.** `docker/compose.traefik-gui.example.yml` is a compose overlay for the
  Docker provider (add it with a second `-f`, labels and network wiring
  included); `docker/traefik-gui.example.yml` is the file-provider equivalent.
  The label form previously existed only as a commented block on the removed
  sidecar. Both spell out that Traefik v2's `HostRegexp` named-group syntax
  matches **nothing** on v3 — which shows up as a 404 from Traefik rather than a
  startup error, and used to send people debugging the dashboard.

### Fixed

- **The Audit page survives a database it cannot read, and says so.** Its own
  queries had no guard at all, so a stressed connection pool killed the page
  on its 30-second refresh — exactly when an operator opens it. It now keeps
  the last rows it had and shows a warning that this is a read failure, not an
  empty trail: "no audit events" and "could not read the audit log" must never
  look the same.
- **An unreadable metrics table can no longer take a page down.** Charts fell
  back to empty only because the one caller happened to guard the read; the
  guard now lives with the query, so every consumer gets an empty series
  instead of a crash.
- **The GUI proxy config is rebuilt when instances change, and at boot.** It
  was only ever rebuilt when somebody opened a Web UI session for some box, so
  a renamed instance kept serving its old `gui-<slug>` address, a deleted one
  kept a live route to its forwarder, and a restarted proxy served no instance
  at all until the next GUI click. The rebuild now rides create, slug change
  and delete, and runs once at startup. It stays fire-and-forget: a slow or
  down proxy cannot block creating or deleting a firewall.
- **Editing an instance records what changed again.** Enforcing the audit
  allowlist at the point the row is written (earlier in this same unreleased
  block) cut the instance-edit entry down to the box's name: the list had been
  written for the mirrored log line and never carried the edit fields. Every
  edit since then recorded that something changed but not what. The safe edit
  fields are back on the list, and the rotated-secret names with them. Operator
  notes stay off it — free text can contain anything somebody pasted, which is
  what the allowlist is for.
- **A database under stress no longer kills long-lived processes or whole
  pages.** Nineteen more places that are written to degrade when the database
  is unavailable caught only exceptions, while a connection-pool checkout
  exits — so it went straight through them. The worst of these took down
  things that are supposed to survive anything: the agent socket's metrics
  path (an outage would have dropped every agent at once and reported the
  fleet offline), the job scheduler and with it every periodic task, the
  settings cache, the geo-access gate, and the hub's boot-time cache load.
  The rest turned a failed side panel into a dead page — instance charts,
  monitor lists, comments, audit lookups. Left alone on purpose: the
  "already exists" converters, where treating an outage as a name clash would
  be a worse lie than the crash.
- **A failed instance read no longer tears down every firewall GUI vhost.**
  The proxy config is rebuilt from the instance list, and an unreadable list
  fell back to "no instances" — which renders a valid config with zero vhosts
  and pushes it successfully. Now nothing is pushed and the last good config
  stays loaded. This got sharper when the rebuild started riding create,
  delete and boot, earlier in this same block.
- **A failed read no longer wipes a group's stored notification credentials.**
  Saving a channel reads the current config so that a masked secret submitted
  unchanged keeps its value; a read failure looked exactly like "the operator
  cleared it". The save is now refused with a message instead.
- **Terminal recordings are pruned** (Settings → Retention, 30 days by
  default) and the bundled compose file mounts a volume for them. They were
  the only thing orbit writes that is not a database row, so nothing ever
  cleaned them up — and without a volume they vanished on the next container
  rebuild, which is the opposite of why recording gets switched on. Only
  files orbit itself wrote are ever deleted.
- **The Connectivity tab crashed on any box with recorded check transitions**
  (introduced with the monitor timeline, earlier in this same unreleased
  block). The new dialog reused an assign name the instance page already used
  for the last 20 check-event rows, and a non-empty list is truthy — so the
  dialog opened by itself on page load and died on its first field access. The
  dialog now has its own name, and only opens on an actual dialog value.
- **A stressed database no longer turns handled failures into crashes.** Four
  places that are written to degrade gracefully when the database is
  unavailable — the geo-block deny path, the per-group notification channel
  lookup, and the two history timelines — caught only exceptions. A connection
  pool that is exhausted or restarting does not raise, it exits, so it went
  straight through those guards: a geo-denied login answered 500 instead of
  403, an alert could take its ingest path down with it, and an empty timeline
  could take a page down. They now degrade as documented.
- **A failed update check no longer counts as "update available".** When a box
  cannot reach its update repository the fleet Firmware page listed it among
  the boxes with a pending update, indistinguishable from a real one. Those
  rows now carry a "check failed" badge and count under Unknown, where "we do
  not know" belongs. The check itself still rates WARN, so Alerts and the
  exports are unchanged. The page also gained the operator comments the other
  fleet pages have, sharing the row with the instance's own Firmware tab.
- **Interface throughput was never shown.** The Network tab's RX/s and TX/s
  columns read "—" on every box and every transport, because nothing ever
  turned the cumulative byte counters into a rate. They are now derived per
  push; a counter that went backwards (reboot, interface reset) and the first
  push after a restart report nothing rather than a fictional burst.
- **A restart blanked every box until its next push.** The hub wrote each
  box's last state to `status_snapshot` but never read it back, so after a
  restart the fleet had no status, no checks, and the Checkmk and Prometheus
  exports reported nothing until a full poll cycle had passed. The cache is
  rehydrated at boot; a boot that cannot read the column starts cold, as
  before.
- **A tunnel pinned to an address the box no longer has is flagged.** When a
  tunnel names a public local endpoint that differs from the box's actual
  public address — it moved behind NAT, or its WAN address changed — phase 1
  fails with nothing in the tunnel's own status to say why. The VPN views now
  show a "local IP drift" hint naming both addresses. Informational only: no
  check, no alert, and private local endpoints are never judged.
- **The Agent tab crashed on Linux nodes.** Hiding the relay API test there
  compared the hub's agent record as if it were a boolean, which raises while
  rendering — the tab died on every open.
- **The instance tab bar follows you into the sub-pages.** Capture, Firewall
  and Terminal are their own pages, and they rendered without the tabs — so
  opening one dropped you out of the box entirely, with a single "back to
  detail" link as the only way anywhere. The bar now travels with them and
  marks the page you are on; the Terminal, which had no way back at all,
  gets it too.
- **The packet-capture page explains its two modes.** Live stream and
  snapshot were two unlabelled forms stacked on each other with identical
  field names; each is now its own card saying what it does with the result.

- **Interface error counters never produced a check.** The `iface_errors`
  family was registered everywhere — selection categories, the export tree,
  the aggregate map, even the flap-debounce list — but nothing emitted it, so
  the entry in the export tree could never match. A link quietly accumulating
  errors raised nothing. WARN at 100 errors since boot, CRIT at 1000;
  interfaces that report no counters (Securepoint, some poll paths) and
  interfaces that are down emit nothing rather than a fake zero.
- **A forgotten maintenance flag muted a firewall forever.** Maintenance caps
  every CRIT at WARN, and nothing ever cleared it — only a manual edit did.
  It now clears the moment the box reports in again (the behaviour the old
  dashboard documented), with a notification and an audit entry.
- **Certificates and Firmware hid polled boxes.** Both fleet pages filtered
  to agent-push instances, so a Securepoint's certificates and firmware
  version were missing from the compliance views while its own tabs showed
  them. Certificates also gained the operator comments the other fleet pages
  already had.
- **Linux nodes reported nothing at all.** A generic Linux server ships one
  Checkmk-agent dump instead of the per-section numbers a firewall agent
  collects itself — and the hub dropped that section without a word, while
  storing the agent's own zero-filled placeholders. The node enrolled,
  connected, reported its hostname, and then showed 0 % CPU, 0 % RAM and no
  disks forever: indistinguishable from an idle machine rather than from a
  broken import. The dump is now parsed into the normal sections, so a Linux
  box gets CPU, memory, swap, disks, interfaces, load, uptime, NTP (chrony)
  and failed-systemd-unit checks like every other box. CPU needs two pushes
  by nature (the kernel counters are cumulative) and reports nothing until it
  has both, rather than inventing a zero.
- **Direct-polled and Securepoint boxes were invisible to Alerts, Checkmk and
  Prometheus.** Their checks were evaluated and shown on the box's own Checks
  tab, but the fleet-wide export filtered to agent-push instances only — a
  leftover from before the poller was ported. On the dev fleet that hid two
  dead IPsec tunnels on a Securepoint from every alerting surface. All four
  surfaces now agree again, as the parity rule requires. No extra load: both
  transports feed the same section cache, so nothing polls a box per scrape.
- **A box enrolled with the wrong device type stays wrong forever.** The
  create form defaults to OPNsense, and nothing ever revisited the field, so
  a hand-enrolled pfSense kept the wrong firmware branch and the wrong GUI
  deep links. The agent reports what the box actually is on every connect;
  a mismatch is now corrected and audited. Only ever between the three types
  an agent can detect — a Securepoint is never touched.

### Added

- **"Analyse with AI" is back on the IPsec diagnosis**, for every kind of box.
  The old dialog offered it whenever an AI provider was configured; the
  rewrite kept the analyse button only on the Log tab, so the tunnel bundle —
  the one place where reading strongSwan output is genuinely hard — lost it.
  The bundle goes through the same anonymiser and character caps as the log
  analysis.
- **Securepoint boxes can be diagnosed at all.** The Diagnose button was
  wired to the agent relay only, so on a box that has no agent (and never
  will) it was permanently greyed out. The same bundle — connection config,
  crypto proposals, live SAs, the charon log and a peer ping — is now
  gathered over the SSH session the swanctl enrichment already uses. Without
  a pinned SSH host key it explains why instead of connecting unverified.

- **The bundled Checkmk agent script updates itself on Linux nodes again.**
  The agent has reported the script's checksum on every connect all along and
  nothing ever read it, so bumping the vendored copy never reached the fleet
  — a fixed collector stayed unfixed on every box. Orbit now compares the
  checksums when a Linux node connects and pushes a refresh when they differ,
  through the same trust chain as an agent self-update (checksum plus the
  Ed25519 signature, verified on the box before anything is written).

- **The firewall rule editor stopped being a memory test.** Source,
  Destination and both port fields now suggest the box's own aliases (with
  their descriptions) plus the values OPNsense's own GUI offers — typed from
  memory before, with typos only surfacing when the save was rejected. The
  fields stay free text, so anything OPNsense accepts still works; losing the
  suggestions (an unreachable box) never blocks editing.
- **Interfaces are tabs again, rules can be dragged.** Switching interface is
  the most frequent action on that page and was hidden behind a dropdown;
  reordering was arrow-buttons only. The ↑/↓ buttons stay for keyboard and
  touch. Rule actions render as colour badges, so pass and block are
  distinguishable at a glance in a long list.

- **Tunnel graph and history in the per-instance VPN tab.** Both dialogs only
  existed on the fleet VPN page — so an operator debugging one tunnel, who
  lands on that box's own tab, had to navigate back out and find the row
  again to see its timeline. Same dialog, now shared by both surfaces.
- **A "N blocked" counter in the footer** once the access gate has refused
  something, next to the GeoIP tag. Hidden while it is zero.

- **The capture viewer reads like `hexdump -C` again**: offset, sixteen bytes
  of hex in two groups, and the printable-ASCII gutter — so a hostname, an
  SNI or an HTTP verb in the payload is actually spottable. Packets also
  carry a plain-language reading of their TCP flags ("SYN" = connection
  attempt, "RST" = refused), with a legend above the list.
- **A push-p95 tile on the Hub page**, plus a counter for pushes over 250 ms.
  It separates "a box is slow to collect" from "the hub is saturated" — the
  number you want when the dashboard starts feeling laggy.
- **The config-backup diff endpoint compares arbitrary versions** via
  `?against=<id>`; the UI could already pick two versions, the API could not.

- **"Renewal overdue" is back on the Certificates page.** A Let's Encrypt (or
  ZeroSSL, Buypass, Google Trust) certificate that is still standing 21 days
  before expiry means the ACME automation has already missed its window —
  the strongest "renewal is failing here" signal, and it fires about three
  weeks before the generic expiry warning. Shown as its own KPI filter and a
  per-row badge. Self-signed firewall certificates are never flagged, since
  nothing renews them automatically.
- **GeoIP tags next to audit IPs.** The footer resolved the viewer's own
  address while the audit rows — where an unfamiliar IP actually matters —
  showed a bare number.
- **API-key scrapes appear in the access log.** Checkmk and Prometheus
  scrapers were invisible, so there was no way to tell whether a key was
  still in use before purging it.
- **New instances arrive with the terminal armed again** (per-instance
  opt-in, as before the rewrite). The root shell still requires the global
  shell feature gate, an admin session and the write role, and every open is
  now audited — a box that must never expose a shell needs the flag cleared
  after creation.
- **Tags can finally be edited.** The field existed on every instance and the
  fleet page filtered by it, but no form ever wrote one — the filter chips
  could never be populated. Comma-separated on the instance edit form.
- **Series upgrade in bulk.** The bulk runner already supported it (skipping
  firmware-locked boxes, refusing agent-less ones); it just had no entry in
  the actions menu, so a fleet had to be upgraded box by box.
- **An `agent.collect` check.** The detail page has always drawn the agent's
  collect-cycle duration against a 10 s line, but a cycle creeping toward the
  push interval — a hanging collector, so the box's data goes stale while the
  agent still looks connected — raised nothing on Alerts or in the exports.
  WARN only, never CRIT; a box without an agent reports nothing rather than a
  fake OK.
- **Public IP on the Network tab, for every kind of box.** The old dashboard
  answered "where does this box sit on the internet?" only for agent-push
  firewalls, because only the agent runs the outbound probe. It now answers
  for the whole fleet: agent boxes keep the probe, and a direct-polled
  OPNsense/pfSense or a Securepoint gets its public address read off its own
  interfaces. Shown as external IPv4/IPv6 with copy buttons, a **Behind NAT /
  Direct** badge, the address the hub saw the agent connect from, and a line
  saying which of the two sources the numbers came from — a probe and an
  inference are different claims. Nothing is shown at all until something is
  known, and there is no NAT verdict without a public IPv4 to judge on.

- **Account menu in the top right.** Username, Security & 2FA, Change
  password, the design/mode switcher and Sign out now live behind one
  trigger showing the signed-in account and its role, instead of four
  loose controls competing with the fleet navigation.
- **Charts follow the pointer.** Moving across a metric chart draws a
  crosshair and prints the timestamp and value for the nearest sample.
  Previously the values existed only as native tooltips on invisible dots
  — effectively undiscoverable on a 720-point series.

### Changed

- **Relative timestamps are English now.** The instance list said "vor 14s" /
  "gerade eben" inside an otherwise English UI — a deliberate carry-over from
  the React frontend, retired by operator decision. It now reads "14s ago" /
  "just now".
- **Instance detail tabs live in the path.** `/instances/7/checks` instead of
  `/instances/7?tab=checks` — tabs are addressable like the Terminal/Capture/
  Firewall sub-pages always were, and links to a specific tab survive being
  pasted into chat. Old `?tab=` bookmarks keep working.
- **Check export chips are readable.** The per-check consumer toggles were
  10px cryptic tags ("@" for email); now slightly larger, "mail" spelled out,
  with a plain-language tooltip ("Export to checkmk: ON — global rule, click
  to override for this box") and a proper pressed state for screen readers.
  The VPN tunnel state dot also gained a tooltip and screen-reader text —
  colour is no longer the only up/down signal.

### Fixed

- **Browser tabs are distinguishable again.** Every page shipped with the
  Phoenix scaffold title ("Orbit · Phoenix Framework"), so five open dashboard
  tabs were five identical labels and history was useless. Each LiveView now
  titles its tab ("Alerts · Orbit", "opn1 · Orbit" on an instance page).
- **Metric charts no longer draw near-black gridlines on the light designs.**
  The grid used a hardcoded dark-slate hex from the old dark-only UI; it now
  follows the active theme at 12% opacity in both modes.
- **The "Config revision" card is back on the instance overview.** A stray
  tab gate made it render on no tab at all — the overview showed an empty hole
  next to System health, and the last-change info was unreachable.
- **Audit targets show the instance name.** Rows read "instance:5"; they now
  read "bensheim (#5)" for instances in the viewer's groups (out-of-scope
  targets keep the raw id on purpose).

### Changed

- **Hub page layout**: the six stat tiles share one row on wide screens (was a
  ragged 4+2), the fleet push chart spans the full width, and the error
  counters no longer stretch three huge tiles across the page.
- **Instance overview layout**: Services and Disks sit side by side instead of
  a half-empty row and a full-width two-line card. A stopped service reads as
  neutral grey, not alarm red — the check engine decides what stopped means.
- **The firmware upgrade log survives the upgrade.** It was tied to the
  live-tracking flag and disappeared the moment tracking ended — taking the
  boot-environment name and the final lines with it, exactly when they are
  needed. It now stays until dismissed.
- **Problems-first defaults are back**: Alerts opens on the Checkmk-exported
  set, the fleet VPN page on the down tunnels, and the Logs page on
  error-level events, instead of unfiltered lists you have to narrow
  yourself. The KPI tiles keep counting everything, and one click on the
  "Checkmk-exported" chip shows the full set again.
- **The Selection rules page is reachable again** — it was routed and
  implemented but linked from nowhere. It now sits next to the export tree it
  overrides, on the Checkmk and Prometheus settings tabs, and the Prometheus
  tab carries a copy-paste scrape config.
- **Settings Save buttons stay inert until you change something.** Twenty
  always-green Save buttons read as twenty pending changes; each one now
  lights up only when its field differs from the stored value.
- **Direct-polled OPNsense boxes show interface IPs, not MAC addresses.**
  OPNsense reports an interface once per configured address — a link row
  carrying the MAC plus the interface-wide byte counters, then one row per
  address. The poller kept the first row, so the Network tab printed a MAC
  where every other transport prints an IP. Counters still come from the
  link row, so the traffic graphs are unaffected.
- **The dashboard fits a phone screen.** Every page scrolled sideways at
  phone width — the header, the instance action bar, long config values and
  wide tables each pushed past the viewport. Tables now scroll inside their
  own box with the rest of the page holding still; verified at 390, 768 and
  1024 px across fourteen pages.
- **Empty lists explain themselves** instead of showing one grey sentence:
  Connectivity, Certificates, Firmware, Logs and Hub say why they are empty
  and what would fill them. Long tables keep their header visible while
  scrolling, and the maintenance marker is an icon rather than an emoji.
- **Smaller polish**: the instance header actions carry icons, the VPN row
  buttons became icons with tooltips (Reconnect stays a labelled button),
  the config revision timestamp is formatted instead of raw ISO, form fields
  show a visible keyboard focus ring, and Edit/Create/Access-control are
  left-aligned like every other page.
- **Consistency sweep**: buttons and chips use theme color pairs instead of
  hardcoded white text (fixes contrast on light themes), UNKNOWN/neutral state
  chips match the pastel chip family, the Connectivity fleet table drops the
  redundant "Connectivity" prefix per row, the Security page is left-aligned
  like every other page, and the theme popover closes on outside click.

## [4.0.6] - 2026-07-19

### Fixed

- **The GeoIP database is no longer re-downloaded on every restart.** The weekly
  MaxMind refresh also runs ~30 s after each boot, and it pulled the tarball
  unconditionally — so a dev stack (or a redeploying/crash-looping prod one) that
  restarts often hit MaxMind dozens of times a day and eventually got throttled
  (HTTP 429), which bans the whole account, not one box. The job now skips the
  download when the installed `.mmdb` is younger than six days; a genuine weekly
  refresh still goes through. Without a fresh database on disk it downloads as
  before, so first setup is unchanged.

## [4.0.5] - 2026-07-19

### Added

- **A Test button on the SSH settings.** It does not just open a socket: it
  logs in, reports which account it landed as, and then runs the same swanctl
  dumps the poller runs. "SSH connects" and "swanctl answers" are different
  failures — a box can accept the key while strongSwan is missing or unreadable
  for that account — and the message says which, plus how many tunnels it found.

- **SSH access is configurable again on a Securepoint.** The edit form had no
  SSH fields at all, so the enrichment, the ping monitors and the terminal could
  only ever work on boxes whose rows predated the rewrite — a new box could not
  be set up through the UI. The form now has the enrichment switch, port, user
  and private key, plus a **Capture host key** button: pinning is
  trust-on-first-use and the transport refuses to connect without a pin, so
  saving a new key would otherwise leave SSH silently dead. The captured key is
  audited, and it can only come from probing the box — never from typing.

- **Connectivity monitors are editable from the fleet page as well.** The
  Connectivity overview could only be read; changing a monitor meant finding its
  instance first. Each row now has Edit, opening the same dialog.

- **Connectivity monitors are edited in a dialog too.** They could only be
  created, toggled and deleted; correcting a destination meant deleting the
  monitor and losing its history and its check key with it. Same dialog shape as
  the Phase-2 ping monitors, with Test.

- **The Phase-2 ping monitor dialog is now on the instance's own VPN tab too.**
  It previously only existed on the fleet VPN page; the instance page carried a
  cramped inline form per tunnel row that could only ADD a monitor — no editing,
  no disabling, no deleting, and no way to try a ping before saving. Both pages
  now open the same dialog, with source, destination, pings per cycle, an
  enabled switch, and Test.

- **Test works on boxes without an agent.** It ran the agent's one-off ping and
  answered "no agent" everywhere else — including the Securepoint boxes whose
  monitors had just been made to work. It now uses whichever way the box can be
  reached.

- **The monitor UI is reachable on Securepoint boxes.** The probes started
  working over SSH, but the Connectivity tab and the Phase-2 monitor controls
  were still hidden — they were gated on "has an agent" rather than on "can run
  a ping", so the feature existed with no way to configure it. Both now appear
  wherever monitors can actually run.

- **Ping monitors work on Securepoint boxes.** IPsec Phase-2 and connectivity
  monitors both ping *from* the box — through the tunnel, from a chosen source
  address — which is something the dashboard cannot do from outside. With no
  agent to run them, an agent-less appliance simply had no ping results at all;
  they now run over the same SSH access the tunnel enrichment uses. A probe that
  cannot even start (an unassignable source, an unresolvable host) is reported
  as a configuration error, not as an outage.

- **Comments are editable wherever they are shown.** The little note marker on a
  tunnel, certificate, monitor or the firmware panel was read-only — hover for
  the text, then go find the central Notes form to change it. It is now the same
  inline editor used everywhere else. It also drew a raw emoji; it uses the
  regular icon set now.

- **The Terminal works on Securepoint boxes.** They have no agent to attach to,
  so the shell now runs over the same SSH access the IPsec enrichment uses. The
  requirements are deliberately the same as before plus one: the terminal must
  be enabled globally and for that instance, and the box needs a stored key and
  a **pinned host key** — a root shell is the last thing that should be opened
  to an unverified peer. Boxes with an agent are unaffected and still attach to
  it. Closing the tab ends the login on the box.

- **The dashboard checks reachability itself again — `ping` and `http`.** For a
  box without an agent this is the only honest liveness signal: it cannot tell
  us it is down, it just stops answering. The instance's ping target decides
  what runs — a bare host or IP is pinged, a full `http(s)://` URL is pinged
  *and* fetched, and the two are reported separately because a box answering
  ICMP while its web interface is down is a different problem. Any HTTP status
  counts as reachable; a firewall GUI answering 401 is alive.

  A failing probe is graded by what else is known: WARN when something still
  confirms the box is up (a fresh agent, or an ICMP reply while only HTTP
  fails), CRIT when nothing does. These two checks are deliberately exempt from
  the staleness cap — they are freshly measured, and they are what tells a
  genuinely dead box apart from one whose agent merely went quiet.

## [4.0.4] - 2026-07-19

### Fixed

- **The fleet VPN page listed no tunnels for direct-polled boxes.** Their IPsec
  data sits in the same place an agent's does, and the instance's own VPN tab
  showed it — the fleet view simply filtered those boxes out before collecting
  tunnels.

- **Direct-polled boxes had an empty Checks tab and no Firmware tab at all**,
  although the data behind both was already being collected. Two `agent_mode?`
  filters hid working code: the Checks tab returned nothing for any polled
  instance, and the Firmware tab was not even offered. On a Securepoint box that
  meant memory, CPU, load, disk, firmware and one row per IPsec tunnel were all
  computed and then discarded before rendering. Both surfaces now show for
  polled devices too. Firmware *actions* stay hidden where they cannot work —
  Securepoint firmware is read-only from the dashboard, so the tab says so
  instead of offering a button that would fail.

- **Securepoint boxes reported no firmware version.** The vendor API carries the
  installed version and the available upgrade; the port never read them, so the
  Firmware tab had nothing to show and the "update available" warning could
  never fire.

### Changed

- **Published images are amd64-only from now on.** Release builds moved to
  native runners, and the emulated arm64 build — which cost roughly ten of the
  twelve minutes a release took — is switched off rather than emulated. Servers
  are amd64; Mac workstations build their own image from `compose.yml`'s
  `build:` block, which is the default there anyway. If you pull
  `styliteag/dashboard` on an arm64 machine, build locally instead. Re-enabling
  arm64 is a one-line change in the release workflow, on a paid runner.

### Fixed

- **Securepoint boxes reported a load average of 0 that was never measured.**
  The box does report load averages and its core count; the port never read
  them, so the metric writer stored zeros — a graph pinned at 0 reads as an idle
  box rather than as "not measured". Real values now, and no section at all when
  the box does not report them. Swap is likewise derived instead of hardcoded to
  the no-data sentinel: a box without a swap device stays unmonitored as before,
  but one that has swap is now actually watched.

- **The Securepoint SSH enrichment could not connect to a box whose pinned host
  key was RSA.** Such a box typically offers several host keys, and the
  negotiated one was not necessarily the pinned one, so verification failed and
  the connection was refused. The key exchange now *prefers* the pinned key's
  algorithm — without narrowing the list, which would have excluded the
  dashboard's own ed25519 login key and broken authentication instead.

### Added

- **Rich IPsec data for Securepoint boxes, over SSH.** The spcgi JSON API
  reports tunnels but none of the IKE cookies, ESP SPIs or byte counters — the
  identifiers that let two ends of the same tunnel be recognised as a pair
  across NAT, and the numbers behind the traffic graphs. The dashboard now runs
  `swanctl --raw` on the box and parses it, as the python backend did. Opt-in
  per instance (SSH enabled, a key stored, a pinned host key), and the
  enrichment fails open: any SSH problem leaves the plain spcgi tunnel list in
  place rather than failing the poll. The connection itself stays fail-closed —
  an unpinned or mismatched host key refuses to connect, it never falls back to
  trusting the peer.

## [4.0.3] - 2026-07-19

### Changed

- **The published image is called `dashboard` again, not `dashboard-orbit`.**
  The Elixir release image briefly shipped under its own name while the old
  FastAPI+React image still existed; now that it is the only image, it reclaims
  the original name. `ghcr.io/styliteag/dashboard:latest` and
  `docker.io/styliteag/dashboard:latest` — which until now still pointed at the
  retired 3.1.8 python stack — move to the current release on the next tag.
  4.0.2 was the only version ever published as `dashboard-orbit`; pull
  `dashboard:<version>` from 4.0.3 onwards.

## [4.0.2] - 2026-07-19

### Fixed

- **The 4.0.1 release build published no image.** The release workflow still
  built the deleted root `Dockerfile` of the retired FastAPI+React stack and
  aborted before it ever reached the orbit image. It now builds only orbit.
- **Agent installation from the release image 404'd on every file but
  `orbit_agent.py`.** The install guide's `curl`/`fetch` lines pull five files
  from `/api/agent/*`, but the orbit image only shipped the agent script and its
  signature — `run-agent.sh`, the FreeBSD `rc.d` script, the systemd unit and the
  vendored `check_mk_agent.linux` were never copied in, so enrolling a new box
  against a released image was impossible. All five now ship.

- **Securepoint boxes showed no CPU, memory, disk, uptime or interface data.**
  The port fetched `appmgmt get_information` and passed that payload through as
  the raw "system" section, but none of the live numbers live there. The python
  client had read `system info` — per-state CPU %, Mem Total/Avail, storage,
  uptime — and derived the same section shapes the OPNsense client emits, so a
  pulled Securepoint box filled the same metrics surface as an agent box. That
  derivation is back: CPU busy (100 − idle), memory in MB with a used %, the
  /data volume, hostname/version, and interfaces with their addresses and
  up/down state. Interface byte counters stay 0 — that API exposes them only
  via RRD, so the graphs stay honest rather than inventing traffic.

## [4.0.1] - 2026-07-19

### Fixed

- **Every Securepoint box answered 500 on its detail page.** The raw `ipsec`
  hub section arrives in two shapes — agent and OPNsense pushes send a map
  (`running` plus a `tunnels` list), while a Securepoint direct-poll stores a
  bare list, because every section the Securepoint client fetches is a list.
  The page only knew the map shape, so reading `["tunnels"]` off a list raised
  `the Access module supports only keyword lists` and the whole view crashed
  before rendering anything. Both shapes are handled now.


- **A fresh installation could not be logged into at all.** The cutover ported
  only the retirement half of the bootstrap-seed lifecycle: orbit read
  `DASH_ADMIN_DISABLED`/`DASH_SUPERADMIN_DISABLED`, honoured `is_bootstrap` at
  login and auto-retired a seed once a real account existed — but nothing read
  `DASH_ADMIN_PASSWORD`/`DASH_SUPERADMIN_PASSWORD` and nothing ever *created* a
  seed account. The python backend had done that on every start, so the gap
  stayed invisible until it was removed. On an empty database orbit came up with
  zero users and no way in. `Orbit.Auth.Bootstrap` restores the creation half as
  a line-by-line port: both seeds are derived at boot (create on first start,
  auto-disable once a real counterpart exists, break-glass re-enable plus
  password reset when none remains, `*_DISABLED=1` forces off). The four
  variables are now passed to orbit in both compose files — the dev stack passed
  none of them.

- **A fresh installation also had no group, which is a second dead end.** Alembic
  028 seeded group 1 `default` and put every user in it as a DATA migration; the
  orbit baseline carries the schema only. Without a group the first admin can
  neither see nor create anything: instances have a NOT NULL `group_id`, the
  create form answers "group required" when the creator has no membership, and
  scoping gives a user with zero groups `WHERE false` — no role escapes that, by
  design. Boot now seeds `default` when the groups table is empty and puts the
  seed admin in it, matching 028. The seed superadmin deliberately stays without
  any membership: it manages rights, not instances.


- **The baseline schema migration could have deleted the whole database.**
  `orbit/priv/repo/baseline_schema.sql` is supposed to be a no-op on an existing
  database — it exists only so orbit records that it now owns the schema. It
  shipped with 27 `DROP TABLE IF EXISTS` statements instead: `mariadb-dump`
  emits those by default and the `just orbit-dump-baseline` comment filter did
  not strip them. On the first orbit boot against a populated database the
  migration tried to drop every table. It failed harmlessly only because
  `SET FOREIGN_KEY_CHECKS = 0` does not survive between statements, so the first
  DROP hit a foreign key (errno 1451) and aborted — leaving orbit in a crash
  loop rather than an empty database. The dump recipe now passes
  `--skip-add-drop-table`, the migration refuses to execute any
  DROP/TRUNCATE/DELETE/RENAME statement, and a test asserts the shipped SQL is
  free of them.

### Removed


- The retired **FastAPI backend and React frontend are gone from the repo**.
  They stopped being built or run at the orbit cutover but stayed on disk, so
  `backend/` still looked like a live component — and `just backend-run` still
  started a second dashboard against the same database, which could write rows
  orbit did not expect. Deleted along with the combined production `Dockerfile`,
  its nginx config and entrypoint, the `contract/` black-box suite (its job was
  gating the port, which is finished) and the FastAPI-generated OpenAPI
  snapshot. Recovering any of it is a `git show <pre-cutover-commit>:<path>`.

- Notices and SBOM no longer list Python or JavaScript packages — the release
  image ships neither. `THIRD-PARTY-NOTICES.md` drops from ~7800 to ~400 lines
  and now covers the Elixir/Hex closure plus the vendored Checkmk agent.

### Changed

- **`backend/` was also the venv for tooling that has nothing to do with the
  API server** — agent signing, the agent and Checkmk test suites, notices/SBOM
  generation and the two key generators all ran out of it. Deleting it would
  have taken away the ability to sign agent self-updates. That tooling now
  lives in `tools/` (its own uv project, five dependencies instead of
  eighteen); `just sign-agent`, `just agent-test`, `just checkmk-test`,
  `just notices`, `just gen-key` and `just gen-ssh-key` are unchanged from the
  caller's side. Run `just tools-install` once.

- The dev stack is orbit only: `compose-dev.yml` no longer starts `backend` and
  `frontend` containers. **The dev dashboard moves from `http://localhost:5173`
  to `http://localhost:8000`.** The `caddy` service went with them, so the
  firewall GUI proxy is not available in the dev stack any more — prod still
  ships it behind the `gui` profile. `docker/Caddyfile.dev` is kept and now
  points at `orbit:4000` / `orbit:14400+id`, so re-adding the service is a
  compose edit if the feature needs testing locally.

### Added

- Orbit polls the direct-API fleet again. The cutover retired the python
  backend, and with it the only process that polled OPNsense/pfSense API boxes
  and Securepoint UTMs — those instances went unmonitored (their data froze at
  the last python poll). Orbit's scheduler now ticks every
  `poll_tick_seconds`, polls each box once its own `poll_interval_seconds`
  (per-instance override honoured) has elapsed since its last attempt, and
  fans the work out at `poll_concurrency` so one hung appliance cannot stall
  the tick. Each poll writes the metric rows, updates the online/offline
  columns and fires the same recovered/offline notifications and history rows
  as a push agent.

- Direct-polled OPNsense boxes now also report **interfaces, uptime and the
  running version**, not just CPU/memory/disks — so their interface traffic
  graphs, uptime sawtooth and version display work like an agent box's.

### Fixed

- A direct-API box that is unreachable is now reported as **offline**.
  Previously (python behaviour, carried into the port) the vendor client
  swallowed connection errors, the poll counted as a success, and the box
  stayed green while its CPU graph flatlined at 0 % — a dead firewall looked
  idle rather than down. A poll that yields no data at all is now an error.

## [4.0.0] - 2026-07-19

### Changed

- Production compose is now the **Orbit (Elixir/LiveView) cutover topology**: the
  old combined FastAPI+React `app` image is gone; a thin `nginx` service is the
  only front door and proxies the UI, `/api`, the agent websocket and the
  LiveView socket to the `orbit` release on `:4000`. Old and new never run side
  by side. New required env: `ORBIT_SECRET_KEY_BASE` and `DASH_PUBLIC_HOST`; the
  orbit runner image now bundles `curl` for its `/api/health-ex` healthcheck.
  A cutover reuses the already-migrated DB and its accounts. README updated.

- Orbit now **owns the database schema** (Ecto migrations), ending the Alembic
  dependency. `Orbit.Repo.Migrator` runs pending migrations at boot, before the
  app serves a request: an **empty** database is created from a baseline
  migration (`orbit/priv/repo/baseline_schema.sql`, the captured Alembic-head
  schema, emitted in FK-dependency order and idempotent), and a **cutover**
  database has its existing tables adopted as a no-op that just records the
  version — data untouched. Schema changes are now ordinary migrations
  (`just orbit-migration <name>` / `just orbit-migrate`); `Orbit.Release`
  exposes `migrate`/`rollback` for the release. No more `alembic upgrade head`
  step on greenfield installs.

### Security

- Orbit: the fleet Log events page was reachable by every signed-in account,
  while the python original gates `/logs/events` — like every logfile route —
  on admin. The rows carry the program name and the log line itself, and raw
  log content is admin-only by policy, so a `user` or `view_only` member of a
  group could read the log lines of that group's firewalls. `/logs` is now in
  the admin-only route group and its nav link needs admin **and** group
  membership. Orbit-only regression from the LiveView rewrite; the python
  dashboard was never affected.

- Orbit: the Hub status page was reachable by **every** signed-in account,
  while the python original gates `/hub/stats` on admin. Only the agent roster
  is scoped per instance — the message/error counters, the fleet pushes-per-
  minute chart and the served-agent version are global in-memory numbers, so a
  view-only user, or the group-less seed superadmin (who by design sees no
  instances at all), could read fleet-wide activity off an otherwise empty
  page. `/hub` now lives in the admin-only route group and its nav link is
  admin-gated, matching the react dashboard. Orbit-only regression from the
  LiveView rewrite; the python dashboard was never affected.

- Orbit: the login and agent-enrollment brute-force limiters keyed on the raw
  socket peer instead of the proxy-aware client IP. Behind nginx that peer is
  the reverse-proxy container — identical for every external client — so the
  per-IP lock collapsed into one shared bucket: five bad passwords (or five
  bad enrollment codes) from anyone locked login for **all** users, and agent
  enrollment for the **whole** fleet, for 15 minutes. Both controllers now
  resolve the client IP through `Orbit.Net.client_ip/1` (honouring
  `DASH_TRUSTED_PROXY_HOPS`), matching what audit and the geo gate already use.

### Fixed

- Orbit: writing an audit entry that carried an allowlisted detail field
  (comment.set, instance.delete, geoip.config.update, …) crashed the
  calling process on the log line (string detail keys vs. the atom-keyed
  log meta); the DB row was written first so it surfaced only as noise —
  now fixed, with a regression test.

- Orbit GUI proxy: the very first request after opening a firewall WebUI no
  longer fails with "firewall gui unavailable" — the proxy now retries the
  initial connection while the on-demand tunnel (agent stream + TLS/HTTP-2
  handshake) comes up.
- Orbit GUI proxy: the live widgets inside a proxied firewall UI (traffic
  graph, firewall log, CPU) now work — server-sent-event streams are passed
  through chunked instead of buffering to a timeout.

### Changed

- Orbit Log events: the page now says what it is not — not a log viewer.
  It states the hourly push cadence, that each push replaces a box's events,
  that anything below severity 4 is dropped at ingest and can never show up,
  and that a row is a normalised pattern with a count rather than a single
  occurrence. It also shows the newest ingest timestamp, so an idle box's old
  data is recognisable as old. A program tally row (`kernel ×22`,
  `sshd ×1`, toned by worst severity) sits above the table; if more than
  eight programs are involved the row says how many it left out.

- Orbit Alerts: the page now states what it does and does not cover — only
  agent-mode boxes (direct-API polled firewalls produce no alerts here), that
  UNKNOWN means "could not check" rather than OK, and that a silent agent or a
  box in maintenance caps its other CRITs to WARN, so a calm page can still
  mean a loud box. A tally row above the table shows the affected check
  families with their worst state (`ipsec.tunnel ×3` in red, `cert ×1` in
  amber).

- Orbit Hub: every number on the page now says what it counts. Each tile
  carries a one-line caption (your scope vs. fleet-wide, since when), the two
  counter blocks explain what a non-zero value means and that they are
  hub-wide totals — so "Total pushes" (your agents) legitimately disagreeing
  with "Metric pushes" (whole fleet) is no longer a puzzle — and the roster
  gets a tally row above it (`opnsense ×2`, `3.1.8 ×5`, outdated versions in
  amber). Same presentation the Access-control page uses.

- Orbit: the top navigation now hides the instance pages (Instances, Alerts,
  Connectivity, VPN, Certs, Firmware, Logs) for accounts that have no group
  membership — every one of those pages renders an empty list for them, so the
  links were seven dead ends. This is the normal state of a superadmin
  (rights management only, no instance access) and of any user before groups
  are assigned; a superadmin who *does* hold groups keeps the full menu. The
  post-login landing page follows the same logic: admins still land on Hub,
  users with groups on Instances, a group-less superadmin on Users.

### Added

- Orbit GeoIP: the dashboard now shows the **city** (not just the country) an
  IP resolves from, using the GeoLite2-City edition the weekly updater already
  pulls. A small footer on every page shows where you are connecting from; the
  Access-control page shows the admin's own "City, CC" (and evaluates the
  self-lockout dry-run against the real proxy-forwarded IP, not the nginx
  container); and a firewall's External IP panel shows the location of its WAN
  address. Display-only — the access gate still decides on country, so nothing
  about who is blocked changes. Persisted city in the denial history/stats
  waits until orbit owns the shared schema (those tables stay country-only for
  now).

- Orbit: the Settings page is rebuilt to match the old UI — real tabs
  (General, Mattermost, Telegram, Email, AI, Checkmk, Prometheus) with rich
  rows per setting (friendly label, help text, key + default line, "default"
  and "needs restart" badges, typed inputs, per-row Save + reset). Channel
  tabs carry the mute toggle + test, AI the provider test buttons, Checkmk
  and Prometheus the API-key/selection links. Two settings that were
  env-only (GUI proxy idle timeout, IPsec event retention) are now
  DB-overridable and appear in the list.

- Orbit: inline editable comments in the list views — a pencil per row on
  Instances (the box's notes), VPN tunnels and Connectivity monitors opens
  a small popover to add/edit/clear a comment, matching the old UI's
  EntityCommentBadge.
- Orbit: the VPN page's WebGUI icon now deep-links to the firewall's own
  IPsec status page (/ui/ipsec/sessions on OPNsense, /status_ipsec.php on
  pfSense) instead of the GUI root, matching the old UI.
- Orbit: the Instances list rows (list and grid) get the WebUI and Terminal
  quick links they were missing — same per-row icons as the fleet pages.

- Orbit (LiveView rewrite): metric history charts on the instance detail page
  — CPU, RAM, load, pf states, agent collect time and the uptime sawtooth,
  switchable across 1h/6h/24h/7d/30d like the old UI. The Elixir hub now also
  persists metric rows on every agent push, so the series keeps growing when
  Orbit (not the Python stack) is the active hub.
- Orbit: the firewall rules page grows the full editor — create, edit,
  clone, move up/down (reorder), search — on top of toggle/delete/apply.
- Orbit: packet capture gains snapshot mode — bounded tcpdump via the
  agent, pcap download, and an in-browser packet viewer (proto/src/dst/
  flags, hex preview, client-side filter) next to the live stream.
- Orbit: every page now renders through the semantic theme tokens, so all
  three designs and both modes restyle the whole UI (status colors stay
  semantic: warning=amber-family, error=red-family per theme).
- Orbit: three switchable designs (Orbit, Bench, Soft), each with light and
  dark mode — same system as the link-shortener: year-long cookies, served
  as data-theme, switcher bottom-right on every page including login.
  Orbit-dark is the classic slate+emerald look and stays the default.
- Orbit: UI polish pass — pointer cursors on all buttons (Tailwind v4
  preflight left them default), emerald keyboard-focus rings, 150ms color
  transitions on interactive elements, subtle table-row hover, a clear
  active state in the top navigation, and real SVG icons for the WebUI/
  Terminal quick links instead of unicode glyphs.
- Orbit: the Hub page reaches full parity with the old one — pushes/min and
  errors-total KPIs, the error-counter grid (auth failures, bad JSON,
  unknown frames — red when non-zero), the message-counter grid (pushes,
  command results, tunnel frames, pongs, connects, disconnects), CRIT
  alerts grouped as chips linking to the owning page, and the in-memory
  uptime note; the Elixir hub now counts all of these itself.
- Orbit: the console-password policy note is back on the instance detail
  overview — an amber banner when "Password protect the console menu" is
  enabled on the box (fleet standard is no console password).
- Orbit: the VPN page has a dedicated Graph button per tunnel (three-lane
  state view, larger lanes) next to History (lanes + transition table),
  matching the old UI's two separate popups.
- Orbit: the Hub page shows the fleet push-activity chart (pushes per
  minute over the last 6 hours).
- Orbit: per-tunnel Diagnose on the instance detail — the agent's readable
  diagnostic bundle (swanctl/status/log sections) inline under the IPsec
  table, first section expanded.
- Orbit: the tunnel History dialog renders the three-lane state graph
  (Phase 1 / Phase 2 / Ping — green up, amber partial, red down, grey no
  data), and persistent duplicate CHILD_SAs are detected again: the Elixir
  hub debounces the agent's dup signal over three pushes, shows the ⚠ N×
  SAs note on the phase-2 rows and records phase2_dup_on/off history
  events, exactly like the Python hub did.
- Orbit: tunnel history is back — a History dialog per tunnel on the VPN
  page with an up/down timeline graph and the recorded transitions
  (phase-1 up/down, phase-2 count changes, ping ok/fail); the Elixir hub
  now records these transitions on every push, so history keeps growing
  after cutover.
- Orbit: phase-2 ping monitors get a proper edit dialog on the VPN page —
  source/destination/count/enabled plus a Test button that live-pings the
  current form values through the agent before saving; the expand arrow
  moved to the first column and is properly clickable now.
- Orbit: the root URL goes straight to the Hub page — the interim landing
  page from the first milestone is gone.
- Orbit: the fleet VPN page gains the phase-2 expander (traffic selectors,
  child status, ping state) and inline phase-2 ping-monitor add/remove per
  child SA — same controls as the instance detail, one query for the whole
  fleet.
- Orbit: the instance detail page is tabbed again like the old UI —
  Overview, Config, Checks, Network, Capture, Firewall, VPN, Connectivity,
  Log, Firmware, Agent — with the same device-capability filter (no agent
  tabs on Securepoint, rule editor only on OPNsense) and the active tab in
  the URL; plus an inline two-version config-backup diff viewer with
  colored +/- lines.
- Orbit: the Settings page is organized into sections (Polling & agents,
  Retention, Notifications, AI providers), the notification mutes become
  one-click mute/unmute toggles, and each AI provider gets a Test button
  that proves key, base URL and model through the real analyze path.
- Orbit: Phase-2 ping monitors can be added/removed inline in the IPsec
  phase-2 expander (source pre-filled from the agent's suggestion; one
  monitor per child SA).
- Orbit: the Groups page gains the instance-assignment table (move any
  instance between groups, applies immediately) and the firmware card shows
  pending-package list, update counters, needs-reboot and the last check
  output.
- Orbit: inline note badges (📝 with the note as tooltip) on IPsec tunnels,
  certificates, connectivity monitors and the firmware card.
- Orbit: connectivity monitors on the instance detail page — live ping
  results (state/RTT/loss) joined per monitor, create/enable/disable/delete,
  and the agent now receives both monitor sets (standalone + IPsec phase-2)
  right after every reconnect, so probes keep running when Orbit owns the
  hub.
- Orbit: full agent lifecycle on the instance detail page — enable/disable
  agent mode (token mint/revoke), refresh-now, reconnect, test-local-API
  through the relay, show token, uninstall with fallback to direct
  transport, plus condensed copy-paste install instructions (FreeBSD and
  Linux) and the public bootstrap download endpoints
  (/api/agent/script|run|rc|systemd|checkmk).
- Orbit: instance detail gains the System-health strip (load per core, swap,
  pf state table, NTP), the last-config-revision card, per-collector runtime
  bars on the Agent card, and per-check notify/export toggles (instance
  override vs global, same selection rules as the exports).
- Orbit: GeoIP database "Refresh now" button on the Access page (with last
  refresh outcome), a version tag in the navigation header, and audit
  Actions-tab filters (free text, time window, load-more) with usernames
  instead of raw user ids.
- Orbit: the fleet overview pages regain the old UI's interaction — Alerts
  (severity tiles, search with deep link from the instance badges, Checkmk
  exported/excluded filter), VPN (up/down tiles, search, sortable columns,
  phase-2/uptime/traffic, reconnect per row), Firmware (verdict tiles,
  search, type chips, latest/security/needs-reboot/lock columns) and
  Certificates (expiry tiles, search, issuer/expiry columns with runway
  bars, GUI/CA badges); Connectivity (state tiles, search), Log events
  (severity tiles, search, per-instance chips) and Hub status (KPI cards,
  instance names + links instead of bare ids, connected-since column); all
  with WebUI/Terminal quick links per row.
- Orbit: IPsec tunnels on the instance detail page are interactive again —
  connect/disconnect/reconnect per tunnel, service restart with confirmation,
  instant recheck, phase-2 expand with traffic selectors and ping state, plus
  remote/uptime/traffic columns and a stale-push banner when the agent is
  silent.
- Orbit: per-group notification channels — alerts for a group's instances go
  to the group's own Mattermost/Telegram/Email target instead of the global
  one, and the Groups page gains the channel editor (masked secrets,
  "keep stored" on save, remove falls back to global).
- Orbit: the weekly GeoLite2-City database refresh now also runs in the
  Elixir stack (idle without MaxMind credentials, atomic install) — after
  cutover the GeoIP database keeps updating without the Python scheduler.
- Orbit: the instances list regains the old UI's interaction — clickable KPI
  tiles (Total/Online/Degraded/Offline) that filter by status, search over
  name/location/tags, device-type and tag chips, a maintenance-only filter,
  sortable columns, list/grid toggle, per-row CRIT/WARN alert badges, edit and
  delete row actions, and the amber "Update all agents" banner.

## [3.1.8] - 2026-07-16

### Changed

- New Securepoint / SSH-enrichment instances default to SSH port **22** in the
  UI and API (was 9922). Existing instances keep their stored port; set the
  field explicitly when a box listens on a non-standard port.

## [3.1.7] - 2026-07-16

### Added

- GeoIP country tags now appear next to every dashboard IP, not only on
  blocked requests: audit log, access timeline (logins, instance access,
  requests), grouped view, online sessions, the Users page and the footer.
  Hovering the tag shows everything the local GeoIP database knows — city,
  region, full country name, continent and EU membership (e.g.
  "Berlin, Berlin · Germany · Europe · EU").
- The weekly GeoIP auto-download switched from GeoLite2-Country to
  GeoLite2-City (~35 MB instead of ~6 MB, same free MaxMind license) to feed
  the hover labels above. It replaces the database in place at the existing
  path, so country blocking keeps working unchanged and existing
  installations pick City up on their next download — trigger it early via
  Access Control → "Refresh now" if you want city labels immediately.

### Fixed

- The Users page table no longer collapses into overlapping columns on
  narrower windows: cells got proper padding, dates and action buttons no
  longer wrap mid-word, and the table matches the bordered scrollable style
  of the other admin tables.

## [3.1.6] - 2026-07-16

### Added

- pfSense series upgrades (e.g. 2.7.2 → 2.8.1) can now be started from the
  dashboard (agent 3.1.5). pfSense publishes each release in its own pinned
  update train, so the box always answered "up to date"; the agent now
  switches the update branch on-box first (the same code path as the vendor
  GUI's System > Update) and then runs the regular updater — with a ZFS boot
  environment created first, live progress tracking and the existing red
  "Upgrade to X" / bulk series-upgrade buttons. The target release comes from
  the box's own repo metadata, never from the dashboard.

### Fixed

- On pfSense with a newer release train available, a manual "Check now"
  overwrote the cached firmware verdict without the series-upgrade offer —
  the upgrade hint vanished from the dashboard until the next ~12h automatic
  check (agent 3.1.5).
- pfSense firmware updates started while another pfSense-upgrade instance
  briefly held its lockfile (the periodic check, or the metadata refresh a
  branch switch spawns) aborted silently after 5s and never installed
  anything — the agent now waits up to 3 minutes for the other instance to
  finish before starting the updater. The wait happens agent-side because
  the updater's own -T timeout flag does not exist on older tooling
  (pfSense 2.7.2 dies with "Illegal option -T") (agent 3.1.7).
- Firmware updates/upgrades on a box with a nearly full disk died silently
  mid-download while the dashboard showed a successful start. The agent now
  refuses to start a vendor update with less than 512 MB free on / and
  reports the actual free space instead (agent 3.1.5).
- The pre-update ZFS boot environment was created non-recursively, so on
  pfSense it missed the /cf child dataset that holds config.xml — booting
  the rollback environment ended in "config.xml is corrupted" exactly when
  the rollback was needed. Boot environments are now created with
  `bectl create -r` (agent 3.1.6).

- The agent installer (install.sh) refused boxes whose only Python is
  python3.8 (e.g. pfSense Plus 22.05) — its hardcoded interpreter list
  ended at 3.9. It now resolves the interpreter like run-agent.sh does:
  unversioned python3 first, else the newest python3.N found.
- The firmware update-check parser now also tolerates a "pfSense Plus"
  product spelling in the vendor tooling's output — a mismatch would have
  read an available Plus upgrade as "up to date" (agent 3.1.8,
  defensive; CE wording confirmed live).

- Agent-side refusals of a firmware update/upgrade ("insufficient disk
  space", "no series upgrade offered") rendered as a green "started"
  message with the error appended — they now render red and no tracking
  starts. A reply timeout no longer shows a confusing "— command timed
  out" suffix: the trigger may well have worked (seen live under full
  updater load), so the UI starts tracking and waits for the box.

### Changed

- The device-type filter on the Instances page now offers one bubble per
  product (OPNsense, pfSense, Securepoint UTM, Linux) instead of the coarse
  Firewalls/Linux split; the Firmware compliance page gained the same filter
  bubbles. Both appear only while the fleet mixes device types.

## [3.1.5] - 2026-07-16

### Added

- OPNsense series upgrades (e.g. 26.1 → 26.7) can now be started from the
  dashboard: the firmware card shows a dedicated red "Upgrade to X" button
  (agent 3.1.1) with its own type-the-name confirmation. The box resolves
  the target release itself — the dashboard never sends a version — a ZFS
  boot environment is created first, and progress is tracked live through
  the reboot. Direct-poll instances keep using the vendor GUI.
- The Firmware compliance page can run series upgrades in bulk: selecting
  boxes with an offered series upgrade reveals a red "Series upgrade N
  selected" button (type UPGRADE to confirm). Locked instances are skipped
  and direct-poll instances are refused per box, mirroring the
  single-instance rules.

- Starting a firmware update on an OPNsense/pfSense box installed on ZFS now
  automatically creates a boot environment first (`orbit-pre-<version>`,
  visible under System > Snapshots) — the vendors themselves snapshot
  nothing. Rollback: activate the environment and reboot. The agent keeps
  the two newest orbit-created environments and never touches user-created
  ones; on UFS installs the update simply proceeds without a snapshot.

- The agent (3.0.5) now detects OPNsense series upgrades (e.g. 26.1 → 26.7)
  the same way the box GUI does (`opnsense-update -vR`). The firmware card
  reports the new series as available with a note that the upgrade must be
  run from the OPNsense GUI or console — the dashboard update button only
  applies minor updates. A pending minor update keeps precedence (reach the
  latest minor first), the series note rides along in the status text.

### Fixed

- The agent (3.1.2) no longer goes silent ("agent silent for >120s" WARN)
  during the post-reboot package phase of a series upgrade: while the
  vendor updater is running, the periodic firmware check is skipped (it
  would fight the updater for the package lock and stall the agent's push
  loop for minutes) and the card shows "vendor update in progress" instead.
- The firmware upgrade log no longer vanishes the moment tracking finishes:
  the panel now stays on screen (with a Dismiss button) and the "Update
  started" banner carries the agent's start message, e.g. which boot
  environment was created.
- After an OPNsense series upgrade the firmware check no longer wedges the
  box's pkg system: the post-major catalogue rebuild takes minutes, the
  agent's old 60-second timeout killed pkg mid-rebuild and the dead
  process's leftover repo lock made every later check — the box GUI's
  included — wait forever, while unserialised agent checks kept piling up.
  The agent (3.0.7) now serializes all update checks, allows the rebuild
  five minutes, removes a dead holder's leftover repo-lock artifacts, and
  retries a failed check after 15 minutes instead of showing "Check failed"
  for up to 12 hours.
- Firmware updates on OPNsense/pfSense no longer show "Tracking progress…"
  forever: the agent (3.0.4) now reports real running/done progress with the
  vendor updater's log tail (OPNsense `/tmp/pkg_upgrade.progress` incl.
  `***DONE***`/`***REBOOT***` markers, pfSense `/conf/upgrade_log.txt` +
  process state). With older agents the UI stops tracking after 15 minutes
  instead of never.
- After a pkg-only point release that does not reboot the box (e.g. OPNsense
  26.1.11_5 → _10), the firmware card kept advertising the pre-update
  "1 available" for up to 12 hours (the agent's cached update verdict was
  never re-armed without an agent restart). The verdict is now dropped when
  the tracked update finishes, and the agent also self-heals when it notices
  the advertised version is already installed (covers bulk "Update all" and
  manual CLI updates nobody tracks).

## [3.1.4] - 2026-07-14

### Fixed

- The GUI proxy no longer trips the GeoIP gate: its forward-auth and handoff
  subrequests arrive container-to-container, so the gate always saw the proxy
  container's private docker IP (no resolvable country) and denied every GUI
  open with `no_country` when a country allowlist was active. Both paths are
  now exempt like the agent endpoints — they carry their own auth (one-time
  token, per-instance HMAC cookie), and the user's session behind them is
  geo-checked as before.

### Added

- The Access tab timeline gained a fourth event type "Access" — a user
  reaching into a box: web GUI opens, shell sessions, packet captures and
  firewall-rule edits, each with the box name. It also gained free-text
  search (user, IP, action, path, instance name — failed logins are found by
  the attempted username too), a time-range filter, and a "Grouped" view that
  collapses recurring events into one row with count and last-seen (numeric
  path segments masked, like the Logs page). Raw request samples are now off
  by default in the timeline filter — one click brings them back.

## [3.1.3] - 2026-07-14

### Added

- The Audit page has a new "Access" tab for admins answering "who is using
  this dashboard": who is online right now (login IP, last activity), every
  login, logout and failed attempt, session expiry (the previously invisible
  12h auto-logout is now a real `auth.session_expired` audit event), requests
  blocked by the GeoIP country gate or the CrowdSec blocklist, and per-user /
  per-API-key request counters — as 24h aggregates on top and a filterable
  merged timeline below. Request rows are sampled under load (the counters
  always count everything); retention is configurable under Settings →
  Retention (samples and ended sessions 30 days, hourly counters 365 days by
  default).

### Security

- The audit trail (`GET /api/audit` and the Audit page) is now restricted to
  admins and the superadmin. Previously any logged-in account — including
  `view_only` — could read the full trail with usernames, source IPs and
  actions of every user.

## [3.1.2] - 2026-07-12

### Added

- The footer now shows every logged-in user the global count of requests
  blocked by the GeoIP/CrowdSec gate ("🛡 N blocked") — awareness for the
  whole team; details (IPs, countries, paths) remain superadmin-only on the
  Access page.

## [3.1.1] - 2026-07-12

### Fixed

- A backend restart no longer floods notification channels with false
  offline/recovered pairs for every push instance (a 5-minute container
  outage produced 140 Mattermost messages for a 50+ box fleet): agent silence
  is now measured from backend start after a restart, so agents get their
  full staleness threshold to reconnect before being flagged — genuinely
  dead agents still alert once that threshold passes.

### Added

- Denied-request analytics for the GeoIP/CrowdSec gate, persisted across
  restarts: totals per day/reason/country live in an aggregate table that
  counts every denial and cannot be flooded, recent denials are stored as
  individual rows (sampled under floods, 30-day retention). The Access page
  shows totals, top countries and the latest denials; the Prometheus export
  gains `orbit_geoip_denied_total{reason}`,
  `orbit_geoip_denied_country_total{country}` and
  `orbit_geoip_fail_open_total` counters that stay monotonic across backend
  restarts.

## [3.1.0] - 2026-07-12

### Added

- CrowdSec bad-actor blocklist for the dashboard (optional; active once
  `DASH_CROWDSEC_API_KEY` is set, `DASH_CROWDSEC_DISABLE=true` switches it
  off like the GeoIP kill switch): ban decisions from a CrowdSec sidecar (bundled as
  compose profile `crowdsec`) are pulled in stream mode every 30 seconds and
  denied on every interactive request — even when the country restriction is
  off. The GeoIP whitelist always wins (operator rescue), agents and API keys
  stay exempt, and a LAPI outage keeps the last known bans active instead of
  silently un-banning everyone. Sync state and ban count are visible on the
  Access page.

- GeoIP access restriction (superadmin → Access): dashboard logins and every
  API/WebSocket session request can be limited to a country allowlist backed
  by a local GeoLite2 database (IPv4+IPv6; no login IPs leave the server),
  plus an always-allowed whitelist of CIDRs and DynDNS hostnames (re-resolved
  every 5 minutes — DNS outages keep the last known addresses). Agents and
  orbit_ API keys are never geo-blocked; empty configuration allows everyone.
  Saving rules that would block your own IP warns first; blocked requests get
  an explicit "access restricted from your location" message and blocked
  login attempts land in the audit log. `DASH_GEOIP_DISABLE=true` is the
  emergency kill switch; with MaxMind credentials set the database refreshes
  weekly (plus a "Download now" button). The footer shows every user their
  own IP/country, and the Users page shows IP, country and time of each
  account's last login.

## [3.0.6] - 2026-07-12

### Changed

- Disk usage alerts now scale with volume size: the classic 80%/90% levels
  still apply to small boot disks and size-unknown sources, but larger
  volumes alarm later (≥50 GB: 85/93, ≥200 GB: 90/95, ≥1 TB: 93/97) — a 2 TB
  datastore no longer pages while hundreds of GB are still free. Check
  summaries now include the remaining free space (e.g. "82% used (high,
  45.1 GB free)") wherever the source reports a size (agent ≥3.0.3, Linux
  nodes, OPNsense direct-poll, Securepoint).

## [3.0.5] - 2026-07-12

### Added

- Instance overview: new "Uptime (days)" sawtooth graph next to the other
  metric charts — uptime drops to zero at every reboot, making reboot history
  visible at a glance. Works for agent-push, OPNsense direct-poll and
  Securepoint instances (the human uptime string is parsed to seconds at
  ingest; unparseable strings are skipped rather than plotted as a fake
  reboot).

### Changed

- The tags field in the add/edit instance dialogs is now a proper tag picker:
  selected tags render as removable chips, typing suggests tags already used
  across the fleet, and unknown text can be added as a new tag (Enter/comma,
  or the "Create" entry in the dropdown).

- "Add instance" dialog starts with friendlier defaults: the first available
  group is pre-selected, device type defaults to Linux in agent mode, and
  "Skip SSL verification" starts checked (self-signed certs are the fleet
  norm).
- New instances are created with "Terminal (root shell)" and "WebUI login"
  (GUI login replay) enabled by default (previously every box needed a manual
  edit). The server-wide shell feature gate (`DASH_SHELL_ENABLED`) still
  applies — the terminal stays off unless that is enabled too; GUI login
  falls back to the plain login page until a credential is provisioned.

## [3.0.4] - 2026-07-12

### Fixed

- Interface error-rate checks (`iface_errors:*`) no longer page on a single
  burst: like the ping monitors, a WARN/CRIT must now survive three
  consecutive pushes before it surfaces (recovery stays immediate), and the
  streaks are re-seeded on backend restart so no false "recovered"
  notifications fire (prod: `ix0` fired CRIT→OK within 31 seconds on one
  counter blip).

## [3.0.3] - 2026-07-12

### Fixed

- The fleet-wide aggregate endpoints (Alerts page, Checkmk export, Prometheus
  export) took 1.3–1.5s per request in prod and stalled every push, shell and
  page while computing. The check evaluation across all instances now runs in
  a worker thread, and direct-poll appliances are served stale-while-
  revalidate from the shared cache (refreshed by a deduped background poll)
  instead of being polled inside scrape/page requests — this also covers the
  Alerts page, whose 30s auto-refresh had bypassed the cache entirely.

## [3.0.2] - 2026-07-12

### Fixed

- Hourly log pushes no longer drag the push handler into the yellow (prod:
  p95 ~200ms with slow-push clusters at the top of every hour after the
  fleet-wide 3.0.0 rollout synchronized all agents). The database write now
  runs in a background queue with a single serial writer instead of inside
  the push handler, and agent 3.0.2 jitters its first hourly log collection
  by 0–10 minutes after a restart so a fleet updated at once stays spread
  out — "Refresh now" still collects immediately.

## [3.0.1] - 2026-07-11

### Fixed

- The Agent tab's installation guide was wrong for Linux nodes (it showed
  the FreeBSD steps: `fetch`, rc.d, `sysrc`/`service`, 30s interval). Linux
  instances now get their own guide — curl downloads (including the bundled
  Checkmk agent and the systemd unit, both now served by the dashboard),
  `printf` config with 120s interval and chmod 600, `systemctl enable
  --now`, `journalctl -f` for logs — and the firewall-only GUI/local-API
  box is hidden there.

## [3.0.0] - 2026-07-11

### Fixed

- "Start update" on a Linux node no longer tracks progress forever (agent
  2.9.17): the agent reports the background apt/dnf upgrade as running/done
  from live process state plus the dpkg log tail, the banner completes, and
  the pending-update counts refresh on the next push instead of after the
  12h check window. Firewall agents keep the previous behavior.
- Kernel updates no longer bounce back after "Start update" (agent 2.9.19):
  the upgrade runs `apt-get dist-upgrade` instead of `upgrade` — a kernel
  metapackage pulls a new versioned image package, which plain upgrade keeps
  back forever. Also fixed: on a box with less than ~12h uptime the freshly
  finished upgrade kept showing the old pending counts (the verdict cache
  didn't expire with a young monotonic clock — it is now dropped outright,
  same fix applied to the agent's "Refresh now" path).
- Linux nodes no longer show a WebGUI globe icon in the instance lists and
  hub status (there is no web UI to open); the backend refuses
  `/gui/open` for such device types outright. The Terminal button works
  for Linux nodes once the per-instance shell opt-in is set — root shell
  and packet capture verified end-to-end against a live Ubuntu node.

### Added

- Two more CPU-heavy jobs moved off the event loop into worker threads:
  log-event extraction on every hourly log push (regex over up to ~1 MB per
  file) and the anonymizer pass before an AI log analysis — neither can
  stall pushes, shells or the UI anymore.
- Scaling observability: the Hub status page shows the push handler's p95
  wall-clock time as a tile (amber above 100ms) plus a "Slow pushes" error
  counter; every push slower than 100ms and every API request slower than 1s
  logs a warning with the culprit. Checkmk payload parsing for Linux nodes
  moved off the event loop (thread pool) so a fat payload can never stall
  pushes, shells or the UI.
- New device type **Linux** (generic Linux server, e.g. customer app servers or
  MSP infrastructure hosts): push-only via the orbit agent — created without a
  base URL/API key, enrolled exactly like a firewall, with a calmer 120s default
  push interval. Firewall-only surfaces (VPN, web-UI proxy, firewall rules) are
  hidden for this type; the Test button probes the agent WebSocket round-trip
  (there is no direct API to poll). Full data collection (metrics, checks,
  updates, logs) lands in the following releases via the bundled Checkmk agent.
- Agent 2.9.11 detects generic Linux hosts (`platform: linux`) and, when the
  bundled Checkmk agent script is present, ships its raw output with every
  push (`checkmk_raw` section, gzip, 2 MB cap) for backend-side parsing. The
  vendored `check_mk_agent.linux` (Checkmk 2.5.0p8, GPLv2, unmodified) is now
  part of the repo, signed with the same Ed25519 key as the agent and listed
  in THIRD-PARTY-NOTICES.
- The backend parses the pushed Checkmk output (cpu/kernel, mem, df, uptime
  sections for now) into the regular snapshot shapes, so Linux nodes show
  real CPU %, load, RAM/swap, disk usage and uptime in the instance views,
  metrics history and checks — no separate Linux code path downstream.
- New `agent/install-linux.sh` + systemd unit: installs the agent, the
  run-agent.sh supervisor (same self-update/rollback contract as on
  FreeBSD) and the bundled Checkmk agent on a Linux server. The FreeBSD
  `install.sh` is untouched.
- The Updates tab works for Linux nodes (agent 2.9.12): pending apt/dnf
  package updates with per-package list, a "reboot required" flag and
  "Start update" / bulk "Update all" support (upgrade runs in the
  background; a server is never rebooted automatically). The firmware
  check WARNs only when *security* updates are pending — routine updates
  show as an OK count instead of keeping the fleet permanently yellow.
- The bundled Checkmk agent script now keeps itself current on Linux nodes
  (agent 2.9.15): the agent reports its deployed script's sha256 on connect
  and the dashboard pushes the vendored copy when it differs — Ed25519-signed
  with the same offline key as the agent itself, verified on the box before
  any byte is written (atomic replace, never touches a distro-installed
  check_mk_agent). Bumping the vendored script in the repo now rolls it to
  the fleet on the next reconnect.
- The Instances page gets a device-class filter row (All types / Firewalls /
  Linux) above the tag chips — shown once the fleet contains a Linux node.
- Linux nodes now populate the Network tab (interfaces with state, IPv4 and
  traffic/error counters from the Checkmk `lnx_if` section — also feeds the
  capture interface picker and interface-error-rate checks), get a real NTP
  check from `chrony` (stratum/offset/peer), and show their running services;
  a systemd unit in **failed** state raises a WARN check until it recovers
  or is reset. All parsed backend-side — no agent rollout needed.
- Log snapshots for Linux nodes (agent 2.9.14): hourly journald slices
  (errors, warnings, sshd/sudo auth) plus dmesg land in the Log tab's
  stored snapshots and the AI log analysis; hosts without systemd fall
  back to the classic /var/log files. The (pf-specific) firewall-log
  block is hidden for Linux nodes.

## [2.9.11] - 2026-07-10

### Added

- Editable operator **comments** on VPN tunnels (per phase 1), connectivity
  monitors, firmware (one note per box) and certificates — a pencil appears on row
  hover and opens a small multiline editor (Ctrl+Enter or click away saves, Esc
  cancels, saving empty deletes); an existing comment shows as a speech-bubble
  icon with the text (and author) as tooltip. Available on the
  per-instance tabs and the global overviews (VPN, Connectivity, Firmware
  compliance, Certificates). The instance comment (Notes) is now also editable
  inline from the Instances overview, list and grid. Edits require the write role
  and are audited.

## [2.9.10] - 2026-07-10

### Added

- The **Network** tab of each instance now shows a **Public IP** block at the top:
  the box's external IPv4 and IPv6 (reported by the agent via an ipify echo), the
  source IP the dashboard saw when the agent connected, and a **Behind NAT / Direct**
  indicator. NAT is detected when the box's public IPv4 is not one of its own
  interface addresses — so boxes sitting behind an upstream/carrier NAT are visible
  at a glance. Agent (`2.9.10`) adds the external-IP probe (throttled to ~15 min,
  cached and sticky through transient failures; the only collector that reaches an
  outside service, over verified HTTPS).
- IPsec tunnels now carry a dashboard-only **lip-mismatch** note (amber, beside the
  existing `dup` note) when a tunnel pins a *public* local endpoint IP that no longer
  matches the box's real external IP — i.e. the configured local address drifted
  (box moved behind NAT, or its WAN IP changed). Shown on both the per-instance IPsec
  view and the global VPN overview. Purely informational: no alert, no notification.

## [2.9.9] - 2026-07-08

### Added

- Instances overview (list and grid) now shows a WARN/CRIT bubble next to each
  instance's status, mirroring the existing "Console PW" badge style — red with the
  CRIT count when any service check is critical, amber with the WARN count
  otherwise. Clicking it opens the Alerts page pre-filtered to that instance, so a
  problem is visible without opening every box's detail page.

## [2.9.8] - 2026-07-07

### Fixed

- Agent (`2.9.8`): pfSense firmware update check no longer reports the **beta**
  train as an available update. pfSense Plus publishes the next release as its own
  numeric pkg train (e.g. `26_07`) that sorts above the installed stable one, so the
  cross-train "newer release" detection flagged an upgrade to the beta even on a box
  pinned to a stable branch (reported on Plus boxes on 26.03 showing "update to
  26.07"). Beta/development trains are now excluded (via the `.descr` branch label and
  the `…-beta.` / `pfSense_master` repo host); a genuine newer **stable** train
  (e.g. 26.03.1) is still surfaced, matching the box's own System Information widget.

## [2.9.7] - 2026-07-06

### Fixed

- Instance list/grid **Status** column showed "Online" for agent-mode instances even
  when the agent was disconnected — it read the (stale) last-poll timestamps, which
  agent-mode instances don't refresh. Status now reflects the live agent connection for
  agent-mode instances (the same source as the Agent/Mode column, so the two can no
  longer disagree); the Online/Offline filter buckets them the same way. API-mode
  instances keep the poll-timestamp status.

### Added

- Agent card gains two on-demand buttons (admin, connected agents): **Refresh now**
  forces the agent to re-collect its interval-throttled metrics immediately — logfiles
  (hourly), firmware (~12h) and the config backup — and push a fresh snapshot, so views
  like Log Events heal at once instead of waiting for the next hourly tick; **Reconnect**
  drops and re-establishes the agent's dashboard WebSocket (back within a few seconds).

## [2.9.6] - 2026-07-06

### Fixed

- Timestamps rendering in the future (e.g. Log Events "last seen: in 1h") on
  deployments where the database container's `TZ` was set to a non-UTC zone. Columns
  defaulted with `NOW()` / `CURRENT_TIMESTAMP` were written in the DB session's local
  zone but then labelled UTC, offsetting every such timestamp by the `TZ` offset. The
  DB session is now pinned to UTC on connect, so `NOW()` always equals `UTC_TIMESTAMP()`
  regardless of `TZ`. Existing rows written under a non-UTC session keep their old
  offset until next rewritten.

## [2.9.5] - 2026-07-06

### Changed

- Log Events page: the table now spans the full window width instead of being capped
  at 1280px, so all columns fit and the message-pattern column absorbs the extra space
  on wide screens.

## [2.9.4] - 2026-07-06

### Fixed

- Agent on pfSense **2.6**: relay-credential and boot-persistence provisioning died
  with `Call to undefined function config_get_path()` (that accessor + `config_set_path`
  were only added in pfSense CE 2.7), leaving the `orbit` user, WebUI auto-login and
  reboot autostart unprovisioned on the older boxes. The generated PHP now shims both
  accessors over the global `$config` array when they're absent (one code path for 2.6
  through 2.8) and guards every `write_config()` on a populated config so a failed
  config load is a safe no-op instead of stubbing out `config.xml`.

## [2.9.3] - 2026-07-05

### Fixed

- Hub "CRIT alerts by tab": gateway alerts were bucketed under **Connectivity**,
  which is only the ping monitors — so a fleet with 0 ping problems but down
  gateways showed a misleading "Connectivity N" chip linking to a page with nothing
  wrong. Gateway alerts now get their own **Gateways** chip that deep-links to the
  filtered alert list (`/alerts?q=gateway:`); Connectivity counts only `connectivity:*`
  ping monitors.
- Service checks: `ipsec.service` no longer reports CRIT ("IPsec service NOT
  running") on boxes that don't use IPsec at all. strongSwan legitimately isn't
  running there, so the check was a permanent false alert (it inflated the Hub's
  VPN alert count and the Checkmk/Prometheus exports). The service is now only
  evaluated when the box has IPsec tunnels configured; a genuine daemon crash on an
  IPsec box still surfaces (its tunnels stay listed and go CRIT).

### Added

- Packet capture viewer: TCP packets now show their control flags by name
  (SYN, ACK, FIN, RST, PSH, URG) with a plain-language reading of the combo —
  SYN-ACK = accepted, RST = refused (reject rule / closed port), lone SYN with no
  reply = silently dropped/firewalled — plus a legend, so you can tell whether a
  connection was accepted, rejected, or blocked.
- Packet capture viewer: the packet detail pane now shows a classic hex + ASCII
  dump side by side (offset · hex bytes · printable-ASCII gutter, like `tcpdump -X`),
  so text in a packet's bytes is readable next to the hex.

## [2.9.2] - 2026-07-05

### Added

- Hub "Connected agents" table: each row now carries the same WebUI (tunneled) and
  Console (root terminal) icon links as the other list views, next to the instance
  name — so operators can jump straight into a box's GUI or shell from the Hub.

### Changed

- Prometheus and Checkmk exports now serve direct-poll (OPNsense/pfSense direct,
  Securepoint) appliance status from a short shared TTL cache instead of polling the
  box on every request. Push instances are unaffected (already read from the hub
  cache). This stops frequent Prometheus scrapes — and a fleet running both
  integrations — from hammering the same appliances; the interactive Alerts page and
  single-instance checks stay live.

### Fixed

- Top talkers table: German column headers ("Pakete"/"Alter") and a hardcoded German
  number locale in the otherwise-English UI are now English ("Packets"/"Age").

## [2.9.1] - 2026-07-05

### Fixed

- Instance detail: the Packet Capture and Config Backups sections kept their local
  state across an instance switch, so after capturing on one box another box's
  Capture tab showed the first box's result (with download/view links pointing at
  the wrong capture), and a carried-over backup-version selection fired a diff under
  the wrong instance. Both sections now remount per instance.

### Security

- **Live packet-capture WebSocket was unauthenticated and unscoped.**
  `GET /api/ws/capture/{instance_id}` accepted the connection and started an agent
  `tcpdump` stream without any auth, origin, or group-scope check — any origin could
  make any agent-connected firewall capture and stream its full raw traffic. It now
  requires a write role + valid session and enforces instance visibility (mirroring
  the shell/tunnel WebSockets and the pcap-download path), and opens are audited.

## [2.9.0] - 2026-07-05

### Added
- Firewall rule editor (OPNsense): **Source, Destination and Interface are now
  multi-value**, matching OPNsense's own `Multiple=Y` fields. Pick several
  networks/aliases/interfaces as removable chips (or type a CIDR); for Source/Dest
  "any" stays exclusive, and a rule with no interface is treated as floating. A new
  rule seeds its interface from the active tab. Values round-trip as the
  comma-separated string OPNsense expects — including its per-field-type get_rule
  formats (plain string for Source/Dest, selected-option map for Interface).

### Fixed
- **Hub CRIT alerts now link to the tab that owns them.** The "Red / CRIT alerts"
  block grouped by raw check key (many count-1 chips) and pointed every chip at the
  generic alert list. Alerts are now grouped by destination tab — VPN, Connectivity,
  Firmware, Certificates, System — and each chip links straight to that page.
- **Firewall rules editor (OPNsense): Source/Destination autocomplete was empty.**
  The network/port/category option lookups and the "Apply changes" call targeted
  the abstract `filter_base` API controller, which OPNsense does not route
  ("Endpoint not found"), so the responses were silently swallowed to empty. All
  now use the concrete `filter` controller — Source/Destination suggest the
  interface networks (LAN net, WAN net, opt…) and defined aliases, port fields
  suggest named ports, and **Apply changes actually applies** (it never did before).
- **Firewall alias completion returned nothing.** The alias lookup used the
  non-existent `alias/search_alias` endpoint (correct is `alias/search_item`), and
  an empty-but-successful push-agent reply short-circuited the OPNsense API path.
  Aliases now resolve with their expansion (address) for the Source/Dest hint;
  OPNsense-internal `__<if>_network` aliases are filtered out as duplicates of the
  network options.
- **Packet capture viewer failed to build** (`aliasList` used before declaration)
  and suggested fabricated alias names; the alias list is now driven solely by the
  instance's real aliases.
- Firewall rules editor: the interface tab bar no longer shows "All rules" twice
  (OPNsense's own `__any` entry duplicated the pinned tab), and the verbose
  "IPsec encapsulation" tab (enc0) is shortened to "IPsec".

### Changed
- Added non-alert warning under /instances (small "Console PW" badge) and on the instance Overview tab (amber note) when "Password protect the console menu" is enabled on a firewall. The team prefers console access without password protection (the disableconsolemenu flag absent in config.xml). No check/alert or notification is emitted for this condition. Agent 2.7.17+ surfaces the flag via status; direct-poll boxes default to no warning.

## [2.8.7] - 2026-07-05

### Changed
- Firewall rules editor (OPNsense): added prominent interface tabs for primary navigation (Floating/WAN/LAN/... + All), matching preferred pfSense-style organization while staying in the app's dark/slate theme. Native HTML5 drag-and-drop row reordering with grip handle (drops move the rule before the target; arrows remain as fallback). Action column now uses colored badges (pass=green, block/reject=red). Interface shown as subtle pills. "Drag to reorder" hint in header. Removed duplicate interface dropdown in favor of tabs. (Stats and category-based sections intentionally omitted.)
- Firewall rule edit dialog: restructured closer to the pfSense edit style (Source/Destination/Extra Options sections with help text, Invert match, Port Range labels + hints, Disabled toggle, "Display Advanced" button, Address Family). Dark/slate theme preserved.

## [2.8.6] - 2026-07-05

## [2.8.5] - 2026-07-05

## [2.8.4] - 2026-07-05

## [2.8.3] - 2026-07-05

## [2.8.2] - 2026-07-05

## [2.8.1] - 2026-07-05

## [2.8.0] - 2026-07-05

### Added

- **Remote packet capture** — trigger a bounded `tcpdump` (interface + BPF filter + max seconds/bytes) on the firewall via the agent (no SSH). PCAP is downloaded from the dashboard. Includes a browser packet list + hex viewer that opens in a new tab (basic Ethernet/IP/TCP/UDP dissection).
- **OPNsense firewall rules editor.** OPNsense instance pages now have a
  Firewall tab backed by the core `firewall/filter` API, over either direct API
  credentials or the agent relay. It lists rules, marks legacy/internal rows as
  read-only, and supports add, edit, clone, delete, enable/disable, log toggle,
  move-before reordering and explicit apply, with audit entries for every write.
- **Prometheus settings tab** — dedicated section under Settings → Prometheus for
  creating read-only API keys used with `GET /api/export/prometheus`. Keys use the
  same `orbit_…` mechanism (and group binding) as Checkmk keys but live in their
  own tab with a Prometheus-specific scrape config example.
- **Prometheus export** (`GET /api/export/prometheus`) — sibling of the Checkmk
  export in Prometheus text format, ready to scrape for Grafana. Emits
  `orbit_instance_info`, `orbit_check_state` (0=OK/1=WARN/2=CRIT/3=UNKNOWN, same
  convention as Checkmk) and `orbit_check_metric{,_warn,_crit}` perfdata series
  for every evaluated check. Same auth + group scoping as the Checkmk export
  (read-only API key as `Authorization: Bearer`); no selection filtering or
  aggregation — filter in PromQL.
- **Certificate lifecycle view** — a fleet-wide certificate inventory at `/certs`
  (nav: "Certs"). Aggregates every agent-collected cert/CA across the caller's
  visible instances into one page: KPI tiles (total, OK, expiring < 30d,
  critical/expired, ACME renewal-overdue), an expiry-runway timeline bucketed by
  how soon each cert lapses, and a searchable/sortable table (instance, cert,
  issuer, expiry, remaining) with GUI/CA badges and deep links. ACME (Let's
  Encrypt et al.) certs are derived from the issuer and flagged **renewal overdue**
  when they sit inside their auto-renew window (< 21 days) — a strong "renewal is
  failing" signal. Backed by a new `GET /api/certs/overview`; reuses the existing
  per-cert expiry alerting (`cert_checks`, CRIT < 7d / WARN < 30d). Certs are
  agent-push only, so direct-poll and Securepoint boxes contribute nothing.
- **Hub observability page (backend self-monitoring).** New admin-only page
  (nav "Hub", `/hub`) backed by `GET /api/hub/stats`: connected agents (with
  per-connection push count and last-push time), a pushes-per-minute chart for
  the last hour, and hub counters (connects/disconnects, auth failures, bad
  JSON frames, handler/WS errors, unknown message types). All numbers are
  in-memory since backend start — a restart resets them, and the page says so.
  The agent list is group-scoped like every other instance surface.
- **Config backup & versioning (agent 2.7.15).** The agent now pushes
  `config.xml` whenever it actually changes (mtime + sha256 gated, gzip
  transport); the dashboard stores encrypted, versioned copies (Fernet at
  rest, newest 30 per instance, sha256-deduped). New per-instance "Config
  Backups" section with a diff viewer ("what changed between two versions?")
  and one-click download of any version for disaster recovery
  (`GET /api/instances/{id}/config-backups[/{bid}/download|/diff]`).
  OPNsense/pfSense agent mode only for now — Securepoint has no on-box agent.
- **Top talkers / state-table insight (agent 2.7.15).** The agent aggregates
  `pfctl -vss` on-box every 5 minutes (streaming parse, capped memory) into top
  source/destination talkers by state-lifetime bytes, states per
  interface/protocol and the ten biggest flows — lightweight traffic insight
  without NetFlow. New group-scoped endpoint
  `GET /api/instances/{id}/pf-top` and a "Top Talkers" section on the
  instance page's Network tab (OPNsense/pfSense agent mode only).

### Changed

- Instance detail now has a dedicated **Config** tab containing the versioned
  config backups list, diff viewer ("what changed between Tue and Wed?"), and
  one-click downloads. The high-value backup & recovery feature is no longer
  hidden behind a collapsed section under Overview.
- "Service Checks" (current states + notify/export toggles) and "Check history"
  are now in their own **Checks** tab on the instance page (split out of Overview
  for the same reason as Config).

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
