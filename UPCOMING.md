# UPCOMING — Feature Ideas & Roadmap Candidates

Brainstorm document: things STYLiTE Orbit could grow into. Not a commitment list —
items graduate from here into `TODO.md` / `docs/agent-architecture.md` when they get
concrete. Ordered roughly from "small polish" to "big bets".

Known-gap backlog (correctness holes, agent lifecycle) lives in
`docs/agent-architecture.md` §11/§14 and `TODO.md` — not duplicated here.

---

## 🔧 Quick wins & polish
- **Instance tags & notes** — free-form labels (customer, site, SLA class) +
  markdown notes per instance; filterable everywhere.
- **Global search** — one search box: instances, devices, VPN tunnels, log events,
  users. Keyboard-first (Cmd-K palette).
- **CSV/JSON export buttons** — on every table (instances, devices, log events,
  firmware compliance) for reporting workflows.
- **UI language toggle (DE/EN)** — fleet operators here are German-speaking; i18n
  layer with German as first-class locale.
- **Column/widget preferences** — persist per-user table columns, sort orders, and
  dashboard card layout.

## 📈 Monitoring & alerting

- **Alert rules engine** — user-defined thresholds (CPU > x for y min, tunnel down,
  cert expiring in < n days, gateway RTT/loss), per group or per instance, with
  silence windows and maintenance mode.
- **More notification channels** — e-mail digests, generic webhook, ntfy, Slack /
  Teams / Telegram. Escalation chains (notify B if A doesn't ack in 15 min).
- **OpenMetrics / Prometheus endpoint** — sibling of the Checkmk export
  (`/api/export/prometheus`); makes Grafana dashboards trivial and widens the
  monitoring-integration story beyond OMD.
- **Certificate lifecycle view** — fleet-wide cert inventory (already collected)
  with expiry timeline, ACME renewal status, and alerting.
- **Live log streaming** — today logs arrive as hourly snapshots; add an on-demand
  "follow" mode where the agent tails a selected log over the existing WS and the
  UI streams it live (with the same admin-only + anonymization rules).
- **Top talkers / state table insight** — lightweight traffic insight from `pfctl`
  state summaries: top source/dest, states per interface, without full NetFlow.
- **SLA / availability reports** — monthly uptime per instance and per tunnel,
  rendered as PDF/e-mail for customers ("99.7 % in June").
- **Backend self-monitoring** — hub observability (connected agents, push rate,
  error counters) as first-class metrics page, not just logs.

## 🛰 Agent & fleet operations

- **Config backup & versioning** — agent pushes `config.xml` (and Securepoint
  equivalent) on change; dashboard stores encrypted, versioned copies with a
  **diff viewer** ("what changed on this box between Tue and Wed?") and
  one-click download for disaster recovery. Probably the highest-value single
  feature for a firewall fleet tool.
- **Config drift / compliance checks** — declarative expectations ("SSH password
  auth off", "DNS servers = X", "firmware ≥ Y") evaluated fleet-wide, with a
  compliance score per group. FirmwareCompliancePage is the seed of this.
- **Scheduled & staged firmware rollouts** — maintenance windows per group,
  canary-first ordering (update 1 box, wait, then the rest), automatic abort on
  failed health check after reboot.
- **Zero-touch enrollment** — one-time enrollment code as QR / single copy-paste
  installer line; pre-provisioned group assignment so a new box lands in the right
  customer group automatically.
- **Agent as native package** — OPNsense plugin (`os-orbit-agent`) / pfSense package
  so installation happens in the firewall GUI instead of scp + shell.
- **Update-key rotation flow** — solve the chicken-and-egg of rotating the baked-in
  Ed25519 pubkey across the fleet (dual-key transition window).
- **Terminal session recording** — the browser terminal (SSH/PTY) gets asciinema-style
  recordings attached to the audit log; optional four-eyes approval for root sessions.
- **Remote packet capture** — request a bounded `tcpdump` (interface, filter, max
  seconds/bytes) via the agent, download the pcap from the dashboard.
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

- **Root-cause assistant** — "why is tunnel opn1↔pf1 down?" — LLM gets the
  (anonymized) tunnel status history, related log events, and gateway metrics, and
  answers with a hypothesis + suggested checks. Builds on the existing anonymized
  LLM analysis path; TODO.md already suggests feeding `swanctl.conf` connection
  blocks.
- **Fleet Q&A** — natural-language queries over inventory: "which boxes still run
  2.6 and have a cert expiring this quarter?"
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
- **Config push (write path)** — carefully scoped write operations: edit an alias,
  add a firewall rule from a template, sync an object across the fleet. Huge value,
  huge blast radius — needs approval workflow, dry-run/diff, and rollback story first.
- **HA / horizontal scaling** — agent hub is in-memory today; move hub state to
  Redis pub/sub so multiple backend replicas can share the WS fleet, plus status
  persistence across restarts (fixes the "backend restart = blind" gap).
- **Mobile PWA** — read-only fleet status + alert push notifications on the phone;
  the on-call view.
- **Public API + webhooks** — documented, versioned REST API surface and outbound
  webhooks (instance offline, update finished) so customers integrate Orbit into
  their own tooling.

## 🧪 Moonshots

- **Orbit Marketplace for checks** — pluggable check/collector definitions
  (signed, like the agent) that the community can share: "Suricata alert summary",
  "Zenarmor status", "CARP health".
- **Cross-fleet benchmarking** — anonymized, opt-in comparisons: "your tunnel
  re-key failure rate is 4× the fleet median".
- **Autonomous remediation** — for a whitelisted set of failures (stale DHCP lease
  daemon, hung IPsec child SA) the dashboard proposes — and with per-group opt-in,
  executes — a known-good fix via the agent, fully audited.

---

*Last updated: 2026-07-05*
