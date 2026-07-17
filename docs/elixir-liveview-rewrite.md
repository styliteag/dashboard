# Plan: Rewrite auf Elixir/Phoenix LiveView (Anlauf 2)

Status: **In Umsetzung** · Branch: `liveview-rewrite` · Stand: 2026-07-18 —
M0–M4 ✅ · M5 ✅ (Kernseiten; Capture-Viewer/GUI-Proxy-Fläche offen) ·
M6 ✅ (Exit erfüllt: LLM-Anonymizer, Firmware-Orchestrierung, Config-Backup,
GeoIP/CrowdSec DR-G8/G9, Access-Log/Session-Registry DR-AL1..AL9, Bulk-Ops,
CSV-Export; Restlücken explizit in `docs/agent-architecture.md` §14-Nachtrag
2026-07-18) · M7 begonnen

## 0. Vorgeschichte / warum Anlauf 2

Anlauf 1 (Branch `elixir-rewrite`, gleicher Tag, zurückgerollt): Elixir als
**headless JSON-API** hinter dem bestehenden React-Frontend. Das war der
Fehler — der 164-Routen-HTTP-Vertrag inkl. manueller Type-Mirrors hätte
bitgenau nachgebaut werden müssen, nur um am Ende dieselbe UI zu behalten.
Entscheidung (User, 2026-07-17): **Phoenix LiveView statt React**. Endzustand
ist **eine** Elixir-Anwendung — UI, Maschinen-API und Agent-Hub in einem
Release. Kein React im Browser, kein FastAPI, kein Vite.

Die Analyse aus Anlauf 1 bleibt gültig und lesenswert
(`git show elixir-rewrite:docs/elixir-rewrite-plan.md` und
`…:docs/elixir-migration-plan.md`); dieses Dokument ersetzt beide für
Anlauf 2. Die dort gebaute Contract-Suite (Commits 65428a5…49a9d57) wird
teilweise wiederverwendet (§4).

## 1. Zielbild

- Neues Top-Level-Verzeichnis **`orbit/`** — Phoenix ~1.8 **mit** LiveView,
  Tailwind, Bandit; Ecto/MyXQL gegen die bestehende MariaDB.
- Browser spricht nur noch LiveView (WebSocket + HTML). Die interne
  JSON-API für die UI **stirbt ersatzlos** — LiveViews rufen Context-Module
  direkt auf.
- Endzustand ein Image: Elixir-Release serviert UI, Maschinen-Endpunkte und
  Agent-WS. nginx bleibt nur als TLS-Terminator/Upstream-Schalter.
- `backend/` und `frontend/` werden nach dem Cutover entfernt (eigener PR).
- Der **Agent bleibt unverändert** (Python 3.8, stdlib, ein File) — sein
  WS-Protokoll ist der unverhandelbare Vertrag.

## 2. Was gegenüber Anlauf 1 entfällt — und was hart bleibt

Entfällt (weil kein React mehr):
- HTTP-Vertrag der 164 UI-Routen, OpenAPI-Snapshot, Type-Mirrors,
  Vite-Proxy-/nginx-Strangler pro Route.
- Session-Cookie-Interop zwischen zwei UI-Backends (ein Re-Login beim
  Cutover ist für ein internes MSP-Tool akzeptabel — User-Entscheid s. §7).

Hart bleibt (Maschinen-Verträge, bitgenau):
1. **Agent-WS-Protokoll** — `/api/ws/agent` (+ `tunnel/shell/capture`),
   hello/welcome-Frames, Kommando-Envelope, Metrik-Push, Relay, PTY,
   Capture-Streams, Self-Update (Ed25519, Anti-Rollback-Versionsparser
   bitgleich, Probation, Exit-42-Kontrakt). ~70 Boxen. Höchstes Risiko.
2. **Checkmk-Special-Agent-JSON** und **Prometheus-Text-Export** —
   von der alten Contract-Suite gepinnt; Vier-Oberflächen-Gleichheit
   (Checkmk == Prometheus == Alerts == per-Instanz) bleibt Invariante.
3. **`orbit_`-API-Keys** — read-only by construction, Scoping-Semantik:
   ApiKey ohne Bindings = GLOBAL, User ohne Gruppen = NICHTS, kein
   Superadmin-Bypass, out-of-scope = 404 nie 403. Change-frozen.
4. **Fernet** (`DASH_MASTER_KEY`, `*_enc`-Spalten) — Eigenmodul auf
   `:crypto` (AES-128-CBC + HMAC-SHA256, base64url), Cross-Language-
   Testvektoren gegen Python-cryptography PFLICHT.
5. **Argon2id-Passwort-Hashes** (argon2-cffi, PHC-Format) — `argon2_elixir`
   validiert Bestands-Hashes; mit echten Dev-DB-Hashes beweisen.
6. **MariaDB-Semantik** — DATETIME naiv-UTC (Session-TZ pinnen, Pendant zu
   `_pin_session_utc`), `INSERT IGNORE`, `FROM_UNIXTIME(… DIV n * n)`-
   Bucketing, gebatchte Deletes (Gap-Lock-Incident), MEDIUMBLOB/MEDIUMTEXT,
   Double statt Float. **Alembic bleibt alleiniger Schema-Owner bis zum
   Cutover** — `orbit/priv/repo/migrations/` bleibt leer (CI-/Review-Check).
7. Alle Sicherheits-Invarianten aus CLAUDE.md (WS-Auth-Reihenfolge mit
   Close-Codes 4401/4403/4404/4008, Audit-Allowlist, `_redact_audit`,
   Anonymisierung vor LLM, no-data ⇒ kein Check, 20-s-TTL für
   Maschinen-Exporte, guarded Section-Writes im Hub-Cache).

## 3. Strategie: paralleler Neubau, Cutover pro Umgebung

Kein Route-für-Route-Strangler (das war die Konsequenz aus "React bleibt").
Stattdessen:

- `orbit/` wird **parallel** zum Bestand gegen dieselbe Dev-MariaDB gebaut;
  beide Stacks laufen in `compose-dev.yml` nebeneinander (Orbit auf :4000).
- Verifikation primär im Lab (`/lab-verify`): echte Agents (opn1/opn2/pf1/
  pf2/ubn1, pf3 = echter 3.8-Agent) verbinden sich gegen den Elixir-Hub.
- **Cutover = Umgebungs-Schaltung**, nicht Routen-Schaltung: nginx-Upstream
  von uvicorn auf das Elixir-Release drehen; Agents reconnecten von selbst
  (gleiche URL). Rollback = zurückdrehen; der Python-Stack bleibt bis nach
  der Probation warm. Erst NACH stabilem Betrieb: Ecto-Baseline einfrieren,
  `backend/`+`frontend/` entfernen.
- Doppel-Aktivität vermeiden: Poller/Scheduler/Hub sind in Dev per Flag nur
  in EINEM Stack aktiv (sonst doppeltes Appliance-Polling und doppelte
  Notifications). Lab-Instanzen werden explizit einem Stack zugewiesen.

## 4. Wiederverwendung aus Anlauf 1 (Cherry-Picks)

- **Maschinen-Contract-Pins** (Checkmk-JSON, Prometheus-Text, ApiKey-/
  Group-Scoping-Semantik, Write-Gates): Commits `7b6e25d`, `5ad8bf6`,
  `6050099`, `49a9d57` — Runner ist black-box HTTP (`CONTRACT_BASE_URL`),
  läuft also unverändert gegen Orbit. UI-Routen-Fixtures daraus verfallen.
- **Nicht** übernommen: `server_ex/`-Scaffold (API-only, falscher Zuschnitt),
  OpenAPI-Snapshot als Vertrag.

## 5. Stack

| Baustein | Wahl | Anmerkung |
|---|---|---|
| Elixir/OTP | 1.20.x / 28.x | wie link-shortener; alles im Container (ADR-0007 dort) |
| Framework | Phoenix ~1.8 + LiveView | `mix phx.new orbit --database mysql --no-mailer` |
| HTTP/WS | Bandit + WebSock | Agent-WS als **Raw-WebSocket-Handler**, KEIN Phoenix-Channel-Framing |
| DB | Ecto SQL + myxql | bestehende MariaDB; keine Ecto-Migrationen bis Cutover |
| UI | LiveView + Tailwind (dark-only, slate/emerald wie heute) | JS nur als LiveView-Hooks: xterm.js (Shell), uPlot o.ä. (Charts) — vendored, kein CDN |
| HTTP-Client | Req | Poller (OPNsense/pfSense/Securepoint), Webhooks |
| Scheduler | Oban | `max_instances=1` über Uniqueness; Pruning gebatcht |
| Fernet | Eigenmodul auf `:crypto` | Hex-Pakete verwaist; Testvektoren-CI gegen Python |
| Ed25519 | OTP `:crypto` (eddsa) | Update-Signaturprüfung/-Auslieferung |
| Passwörter | `argon2_elixir` | Bestand ist Argon2id (argon2-cffi) |
| GeoIP | `:locus` | GeoLite2-Country.mmdb vom bestehenden Volume |
| Logging | `:logger` JSON | structlog-kompatible Feldnamen |

## 6. Meilensteine

Reihenfolge bewusst: **Hub vor UI** — LiveView braucht den Live-Zustand
(verbundene Agents, Hub-Cache) nativ im selben BEAM-Node.

### M0 — Scaffold + Dev-Loop
`orbit/` generiert (LiveView, mysql), Dockerfile.dev (elixir:1.20 + cmake +
inotify-tools), Service in `compose-dev.yml` (Port 4000, Toolchain-Caches
unter `orbit/data/`, gitignored), justfile-Rezepte (`orbit-setup`,
`orbit-test`, `orbit-fmt`, `orbit-lint`, `orbit-sh`, `orbit-iex`),
`runtime.exs` liest die bestehende `DASH_DATABASE_URL` (Treiberpräfix
strippen), `GET /api/health-ex`.
**Exit:** `just dev-up` startet beide Stacks; `just orbit-test` grün;
Kollege kann ohne lokales Elixir arbeiten.

### M1 — Fundament (Auth, Scope, Krypto, Zeit)
Ecto-Schemas read-only für Bestands-Tabellen; UTC-Pinning; Fernet-Modul +
Cross-Language-Testvektoren; Argon2-Login gegen echte Hashes; Phoenix-
Session + LiveView-Auth-Hooks (Rollenleiter als Plug/on_mount-Kette);
`orbit_`-API-Key-Plug (read-only); **Scope-Modul** (change-frozen, Tests
spiegeln `test_group_scoping.py`); Settings-Registry (ETS + DB-Overrides);
JSON-Logging; `client_ip` mit Trusted-Proxy-Hops.
**Exit:** Login mit Bestands-User im Browser; Scope-Property-Tests grün;
Fernet-Vektoren beidseitig grün.

### M2 — Maschinen-Contract-Suite reaktivieren
Cherry-Picks aus §4, Runner gegen Orbit zeigen (`CONTRACT_BASE_URL`);
UI-Routen-Fixtures streichen. Agent-Protokoll-Spec Frame für Frame als
neuer §-Abschnitt in `docs/agent-architecture.md` (deutsch), extrahiert aus
`orbit_agent.py` + `agent_hub/`.
**Exit:** Maschinen-Pins laufen (rot gegen Orbit ist ok — sie sind das
Fortschrittsmaß für M4/M5), Protokoll-Spec reviewed.

### M3 — Agent-Hub (kritischster Teil)
Raw-WS-Handler `/api/ws/agent`: GenServer pro Agent + Registry + PubSub;
Hub-Cache mit guarded Section-Writes (truthy vs. presence je Sektion,
dokumentiert), Hydrate beim Boot, Flap-Streak-Re-Seeding; Kommando-Envelope,
`_INTERNAL_AGENT_ACTIONS`-Pendant; Self-Update-Auslieferung (Ed25519,
Anti-Rollback bitgleich, Probation); Enrollment; Relay/Tunnel, PTY-Shell-
und Capture-Bridging (`/api/ws/{tunnel,shell,capture}/{id}` mit exakter
Auth-Reihenfolge + Close-Codes).
**Exit:** Lab-E2E — alle Lab-Boxen inkl. pf3 (3.8!) verbinden, Metrik-Push,
Kommandos, Shell, Capture, Relay, kompletter Self-Update-Zyklus
(Push → Exit 42 → Probation → Report) über den Elixir-Hub; Regressionstest
"unauthentifizierter Connect konsultiert den Hub nie".

### M4 — Poller, Checks, Exporte, Jobs
Req-Clients (OPNsense/pfSense API, Securepoint spcgi + SSH-Enrichment);
Checks-Engine-Port (pure functions; no-data ⇒ nil, UNKNOWN < WARN, CPU nie
CRIT); `overlay_checks`; Debounce + Hydrate; Checkmk-/Prometheus-Exporte
über ETS-TTL-Cache (20 s); Oban-Jobs (Pruning gebatcht oldest-first,
Retention aus Settings); Notifications (dispatch NACH Commit).
**Exit:** Maschinen-Contract-Pins aus M2 grün gegen Orbit;
Vier-Oberflächen-Abgleich grün; Checkmk-Site im Lab liest identische
Service-Listen von beiden Stacks (diffbar).

### M5 — LiveView-UI komplett
Alle heutigen Seiten als LiveViews (Instances, InstanceDetail mit Tabs +
`key={nid}`-Äquivalent = pro-Instanz-Prozess-State, Alerts, VPN/Connectivity-
Übersichten, Firmware, Logs/LogEvents, Audit + Access-Log, Users/Groups/
Security, Settings, Hub-Status, Terminal via xterm.js-Hook, Capture-Viewer,
Zertifikate, Kommentare, Views/Selection). Dark-only, slate/emerald,
englische Labels (`fmtRelative`-Deutsch-Ausnahme portieren). Live-Updates
via PubSub vom Hub statt Polling-Intervalle.
**Exit:** Feature-Walkthrough gegen Dev-Stack; kein Verweis mehr auf :5173.

### M6 — Restflächen
LLM-Anonymisierung (Char-Caps), Firmware-Orchestrierung, Config-Backup +
Versionierung, GeoIP/CrowdSec-Plugs (DR-G8/G9-Semantik), Access-Log/
Session-Registry, Bulk-Ops, Exporte/Downloads (`<a href>`-Flächen).
**Exit:** Funktionsparität; offene Lücken explizit in §14 der
Agent-Architektur-Doku gelistet statt still.

### M7 — Prod-Image + Cutover-Probe
Multi-Stage-Release-Dockerfile (hexpm-Builder → debian-slim, `mix release`,
`USER nobody`, VERSION aus Repo-Root wie link-shortener); kombiniertes
Compose; nginx-Upstream-Schaltung dokumentiert + einmal ABSICHTLICH geprobt
(hin und zurück) gegen den Dev-Stack; `just release`-Pfad angepasst;
THIRD-PARTY-NOTICES/SBOM inkl. Hex-Pakete (Lizenzpflicht).
**Exit:** frisches `docker compose up -d` auf leerer Kiste bootet
vollständig auf Elixir; Rollback-Probe dokumentiert.

### M8 — Cutover Prod + Rückbau
Maintenance-Fenster: Upstream drehen, Agents reconnecten, Probation
beobachten; Python-Stack warm halten bis Freigabe. Danach: Alembic-Stand
als Ecto-Baseline einfrieren (Boot-Migrator mit `GET_LOCK`-Äquivalent),
`backend/` + `frontend/` entfernen (eigener PR), CI/Release final, Docs.
**Exit:** eine Woche Prod-Betrieb ohne Python-Prozess; Abschluss-§ mit
Live-Nachweisen in `docs/agent-architecture.md`.

## 7. Prozessregeln

1. **Alembic-Monopol bis M8** — `orbit/priv/repo/migrations/` bleibt leer;
   Schema-Änderungen weiterhin als `NNN_*.py` im Python-Backend.
2. Arbeit passiert auf **Branch `liveview-rewrite`** in diesem Checkout
   (User-Entscheid: Branch statt Worktree). Merges nach main nur als ganze
   Meilensteine nach Review. Kein `git add -A`, explizite Pfade.
3. Feature-Entwicklung am Bestand geht auf `main` weiter; `liveview-rewrite`
   wird regelmäßig auf main rebased — nein: **gemerged** (kein Rebase im
   geteilten Repo), Konflikte meilensteinweise aufgelöst.
4. Sicherheits-Invarianten gelten in `orbit/` unverändert; das Scope-Modul
   ist dort genauso change-frozen wie `scope.py` hier.
5. Gates in `orbit/`: `mix format --check-formatted` + `mix compile
   --warnings-as-errors` + `mix test` (justfile-Rezepte). Keine weiteren
   Werkzeuge ohne Team-Entscheid.
6. Ein gerissenes Exit-Kriterium pausiert den Meilenstein — es wird nicht
   drübergebaut.

## 8. Offene Entscheidungen

- [ ] Re-Login beim Cutover akzeptiert? (Annahme: ja, internes Tool)
- [ ] Bus-Faktor: wer außer dem Initiator lernt Elixir?
- [ ] arm64-Prod-Image nötig? (native Runner kosten; QEMU zu langsam)
- [ ] Chart-Lib für LiveView-Hooks (uPlot vendored vs. SVG-Eigenbau)
- [ ] Feature-Freeze-Toleranz auf main während M3–M5
