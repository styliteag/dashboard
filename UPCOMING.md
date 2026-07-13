# UPCOMING — Feature Ideas & Roadmap Candidates

Brainstorm document: things STYLiTE Orbit could grow into. Not a commitment list —
items graduate from here into `TODO.md` / `docs/agent-architecture.md` when they get
concrete. Ordered roughly from "small polish" to "big bets".

Known-gap backlog (correctness holes, agent lifecycle) lives in
`docs/agent-architecture.md` §11/§14 and `TODO.md` — not duplicated here.

---

## 🔧 Quick wins & polish
- **Global search** — one search box: instances, devices, VPN tunnels, log events,
  users. Keyboard-first (Cmd-K palette).
- **CSV/JSON export buttons** — on every table (instances, devices, log events,
  firmware compliance) for reporting workflows.
- **UI language toggle (DE/EN)** — fleet operators here are German-speaking; i18n
  layer with German as first-class locale.
- **Column/widget preferences** — persist per-user table columns, sort orders, and
  dashboard card layout.
- **Session kill (revocation)** — deliberately deferred from the access-log ADR
  (docs/access-log.md, DR-AL5): the session registry is bookkeeping-only, so a
  kill button would be cosmetic. Cheapest effective path when needed: bump the
  user's `password_version` (kills all of a user's sessions via the existing
  `current_user` check, zero new enforcement infrastructure).

## 📈 Monitoring & alerting

- **Alert rules engine** — user-defined thresholds (CPU > x for y min, tunnel down,
  cert expiring in < n days, gateway RTT/loss), per group or per instance, with
  silence windows and maintenance mode.
- **More notification channels** — e-mail digests, generic webhook, ntfy, Slack /
  Teams / Telegram. Escalation chains (notify B if A doesn't ack in 15 min).
- **Live log streaming** — today logs arrive as hourly snapshots; add an on-demand
  "follow" mode where the agent tails a selected log over the existing WS and the
  UI streams it live (with the same admin-only + anonymization rules).
- **SLA / availability reports** — monthly uptime per instance and per tunnel,
  rendered as PDF/e-mail for customers ("99.7 % in June").

## 🛰 Agent & fleet operations

- **Config drift / compliance checks** — declarative expectations ("SSH password
  auth off", "DNS servers = X", "firmware ≥ Y") evaluated fleet-wide, with a
  compliance score per group. FirmwareCompliancePage is the seed of this.
- **Scheduled & staged firmware rollouts** — maintenance windows per group,
  canary-first ordering (update 1 box, wait, then the rest), automatic abort on
  failed health check after reboot.
- **Agent as native package** — OPNsense plugin (`os-orbit-agent`) / pfSense package
  so installation happens in the firewall GUI instead of scp + shell.
- **Update-key rotation flow** — solve the chicken-and-egg of rotating the baked-in
  Ed25519 pubkey across the fleet (dual-key transition window).
- **Wake-up / on-demand refresh** — "refresh now" button that asks the agent to push
  immediately instead of waiting for the next interval.

## 🔐 Security & compliance

- **CVE matching** — map collected firmware/package versions against vulnerability
  feeds (VINCE/NVD, vendor advisories); "3 boxes run an OpenSSL with CVE-2026-XXXX".
- **SSO** — OIDC (Entra ID, Keycloak, Authentik) and/or LDAP; group claims mapped to
  Orbit groups so MSP onboarding is automatic.
- **Fine-grained roles** — read-only role, "operator" (may run updates, no terminal),
  per-feature permissions on top of group scoping.
- **Audit log export & retention policy** — signed/append-only export (syslog, S3)
  for customers with compliance requirements.
- **Anomaly flags on log events** — highlight *new* event patterns per instance
  ("this box never logged this before") instead of only severity.

## 🤖 AI / assistant

- **Daily fleet briefing** — one generated paragraph per morning: what changed,
  what's degraded, what needs a human. Delivered via the notification channels.
- **Log-pattern triage suggestions** — when a new critical pattern appears, the LLM
  proposes a classification (noise / action needed) that an admin can confirm —
  feeding back into the curated noise list in `app/logs/events.py`.

## 🏢 Big bets

- **Full multi-tenancy** — organizations above groups: per-tenant branding,
  isolated API keys, tenant-scoped admins. The MSP scale-up path
  (backlog §14 Tier 2 names this).
- **Topology map** — auto-drawn fleet graph: boxes as nodes, IPsec/OpenVPN/WireGuard
  tunnels as edges, colored by health. All the data already exists; this is the
  "wow" view for the login screen.
- **More VPN types** — WireGuard and OpenVPN status parity with IPsec (peers,
  handshake age, transfer), on all three platforms.
- **More vendors** — the platform abstraction (agent collectors + Securepoint-style
  pollers) is designed for this: Sophos XG(S), MikroTik (REST API), FortiGate,
  UniFi gateways. Each vendor = poller module + normalized status mapping.
- **Config push (write path)** — the OPNsense **firewall rules editor** shipped the
  first slice (add/edit/clone/delete/reorder/apply rules, group-scoped + audited).
  Remaining: alias editing, syncing an object across the fleet, and — for anything
  higher-blast-radius — an approval workflow, dry-run/diff and rollback story.
- **HA / horizontal scaling** — agent hub is in-memory today; move hub state to
  Redis pub/sub so multiple backend replicas can share the WS fleet, plus status
  persistence across restarts (fixes the "backend restart = blind" gap).
- **Mobile PWA** — read-only fleet status + alert push notifications on the phone;
  the on-call view.
- **Public API + webhooks** — documented, versioned REST API surface and outbound
  webhooks (instance offline, update finished) so customers integrate Orbit into
  their own tooling.

## 🧪 Moonshots

- **Autonomous remediation** — for a whitelisted set of failures (stale DHCP lease
  daemon, hung IPsec child SA) the dashboard proposes — and with per-group opt-in,
  executes — a known-good fix via the agent, fully audited.

---

Shipped since this list was last pruned (see `CHANGELOG.md`): Prometheus export,
certificate lifecycle view, hub observability, config backup & versioning, top
talkers / pf state-table, remote packet capture, the OPNsense firewall rules editor,
Checkmk/Prometheus API-key split, and per-instance tags & notes.

*Last updated: 2026-07-05*
