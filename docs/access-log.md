# Access-Log & Session-Registry (ADR)

Status: beschlossen (Grill-Session 2026-07-13/14, wb) — umgesetzt im selben Zug
(Migration 041, `app/access/`, Audit-Tabs; Dev-E2E 2026-07-14).
Sprache dieses Dokuments: Deutsch (wie `agent-architecture.md`); Code/Kommentare/UI: Englisch.

## Kontext

Anforderung: Ein für jeden Admin (nicht nur Superadmin) sichtbares Zugriffs-Log —
alle eingeloggten User, jeder Login und (Auto-)Logout, jeder Fehl-Login, jede IP,
Zugriffe auf das Dashboard selbst, inklusive Kennzeichnung „blocked by
country/CrowdSec". Aggregiert UND im Detail.

Befund im Bestand (verifiziert 2026-07-13):

- `audit`-Tabelle + `GET /api/audit` existieren; `auth.login` (ok/fail mit Grund,
  Brute-Force-Lock), `auth.logout`, `source_ip` sind vorhanden. **Aber:** Endpoint
  und Audit-Seite waren `current_user`-gated — jeder eingeloggte User (auch
  view_only) sah den kompletten Trail.
- GeoIP/CrowdSec-Denials (DR-G8/G9): `geoip_denial_stats` (Tag/Grund/Land-Aggregat,
  365 Tage) + `geoip_denial_events` (gesampelt, max 50 pro 15s-Flush, 30 Tage).
  Reasons: `country_blocked`, `no_country`, `crowdsec_banned`, `fail_open`.
  Anzeige bisher nur auf der superadmin-only Access-Seite.
- HTTP-Zugriffe: nur structlog (`app.http`) in Docker-Logs, keine DB-Persistenz.
- Sessions: signierte Cookies (`SessionMiddleware`, max_age 12 h), kein
  Server-Zustand. „Wer ist online" war unbeantwortbar; Cookie-Ablauf erzeugte
  kein Event.

## Entscheidungen

### DR-AL1 — Sichtbarkeit: `require_admin_or_superadmin`, Audit im selben Zug dichtziehen

Die neue Access-Log-Fläche ist `require_admin_or_superadmin`. Gleichzeitig wird
die bestehende Audit-API (`GET /api/audit`) von `current_user` darauf gehoben
(Security-Fix: view_only konnte Usernamen, IPs und Aktionen aller lesen; einziger
Frontend-Konsument ist die AuditPage, Nav-Link wird entsprechend gegated).
CHANGELOG unter `### Security`.

Warum nicht plain `require_admin`: der Superadmin hat Rolle `view_only`
(Rechteverwaltung, kein Instanz-Zugriff) und wäre ausgesperrt — im Live-Test
2026-07-14 nachgewiesen (403 „admin only" für den Seed-Superadmin). Aufsicht
über Logins/Blocks ist aber gerade Superadmin-Domäne.

DSGVO-Hinweis (deutscher MSP, Mitarbeiter-Monitoring): bewusst entschieden, dass
alle Admins IPs/Aktivität aller User sehen. Gegengewicht: begrenzte, konfigurierbare
Retention (DR-AL6) und keine IP-Samples von Anonymen (DR-AL8).

### DR-AL2 — Request-Erfassung: Aggregat + Sample (DR-G9-Muster)

Kein Voll-Log jedes Requests (Polling-UI erzeugt ~3–8k Requests/User/Tag;
Gap-Lock-Incident-Historie). Zweistufig wie `geoip/denials.py`:

- `access_stats` — Zähler pro (Stunden-Bucket, Principal): `count`, `last_ip`.
  MariaDB-Upsert (`ON DUPLICATE KEY UPDATE`). Zählt JEDEN Request, Kardinalität
  ≈ aktive Principals × 24/Tag.
- `access_events` — einzelne Request-Samples (ts, principal, ip, method, path,
  status), pro Flush-Intervall hart gedeckelt; bei Flut landet nur ein Sample,
  das Aggregat zählt trotzdem alles. Eigener `ts`-Index, batched Prune.
- Request-Pfad schreibt nur in bounded In-Memory-Puffer; 15s-Scheduler-Job
  flusht (eigene Session, `max_instances=1`).

Principal-Dimension: `user:<id>`, `apikey:<id>`, `anon` (DR-AL8). API-Keys
(Checkmk/Prometheus-Scrapes) zählen mit, getrennt vom Menschen-Traffic.
WebSocket-Open zählt als 1 Zugriff.

Fütterung: die bestehende `AccessLogMiddleware` (`http_log.py`) liefert user_id
aus dem Session-Scope; der API-Key-Pfad (`auth/apikey`-Lookup) meldet Key-Hits —
kein zusätzlicher DB-Read im Request-Pfad.

### DR-AL3 — Session-Registry: Buchführung, KEIN Enforcement

Neue Tabelle `auth_sessions`: Login erzeugt Zeile (sid, user_id, login-IP,
created_at, last_seen_at, ended_at, end_reason). Die sid wandert zusätzlich in
die Cookie-Session. Requests stempeln last_seen gedrosselt (max. 1 Update/60s,
über den 15s-Flush-Puffer, kein Write pro Request).

Bewusst NUR Buchführung: `current_user` prüft die Registry nicht — der
Cookie (+ `password_version`-Vergleich) bleibt alleinige Wahrheit. Kein
zusätzlicher DB-Read pro Request. Konsequenz akzeptiert: Session-Revocation ist
damit nicht wirksam möglich → Kill-Feature verschoben (DR-AL5).

„Online" = Session ohne ended_at mit last_seen ≤ 5 min (2× größer als die
Stempel-Drossel, damit aktive Sessions nie als offline flackern).

### DR-AL4 — Auto-Logout: nur 12h absolut, aber erstmals als Event

Kein Idle-Timeout (bewusst: Verhalten für User ändert sich nicht; Polling hielte
Sessions ohnehin aktiv). Ein Scheduler-Job (5-min-Takt) markiert Registry-Zeilen
mit `created_at` älter als die Cookie-max_age (12 h) als beendet
(`end_reason="expired"`) und schreibt `auth.session_expired` ins Audit — der
bisher unsichtbare Auto-Logout wird damit zum Ereignis. Expliziter Logout
markiert die Zeile mit `end_reason="logout"` (Audit `auth.logout` existiert).

### DR-AL5 — Session-Kill: verschoben (UPCOMING)

„Kill einzelne Session" ohne Enforcement wäre ein wirkungsloser Button —
ehrlicher ist gar keiner. Auf `UPCOMING.md` notiert; wenn es kommt, ist der
billigste wirksame Weg der bestehende `password_version`-Vergleich
(alle Sessions eines Users sofort tot, null neue Enforcement-Infrastruktur).

### DR-AL6 — Retention: wie GeoIP, konfigurierbar

SettingDefs im settings registry (DB-überschreibbar, `effective_settings()`):
Request-Samples und beendete Sessions 30 Tage, Stunden-Aggregate 365 Tage
(Defaults). Prune im Batched-Muster (`DELETE … ORDER BY ts LIMIT n`), eigener
ts-Index — Repo-Pflicht.

### DR-AL7 — Denials in der gemeinsamen Timeline

Der Access-Tab zeigt EINE chronologische Ereignisliste mit Typ-Filter:
Login (ok/fail) / Logout / Session-expired / GeoIP-CrowdSec-Denial /
Request-Samples. Denials kommen read-only aus den bestehenden
`geoip_denial_events` (gesampelt by design — das Aggregat zählt alles), klar
gelabelt mit Reason (`country_blocked`, `crowdsec_banned`, …). Die
superadmin-only Access-Seite (GeoIP-KONFIGURATION) bleibt unverändert.

### DR-AL8 — Anonyme Zugriffe: Aggregat ja, IP-Samples nein

Unauthentifizierte, nicht geo-geblockte Requests (abgelaufene Cookies, Scanner
aus DACH) zählen als Principal `anon` im Stunden-Aggregat — sichtbar, DASS es
sie gibt. Keine IP-Samples von Anonymen (Datensparsamkeit; Forensik-Detail
liefert weiterhin das Docker-Log `app.http`).

### DR-AL9 — UI: Audit-Seite bekommt Tabs

Kein neuer Nav-Eintrag. Die Audit-Seite wird zu Tabs: **Actions** (bisheriger
Mutations-Trail) | **Access** (neu). Access-Tab: oben Aggregate (Online-User,
Logins/Fails 24h, Blocks nach Grund/Land, Requests pro Principal), darunter die
Timeline (DR-AL7) mit Filtern. Refetch-Tier: 30 s Standard.

## Implementierungsskizze

- Migration `041`: `auth_sessions` (sid CHAR(32) PK, user_id FK, ip, created_at,
  last_seen_at, ended_at NULL, end_reason NULL; Indizes: user_id, last_seen_at),
  `access_stats` (bucket, principal_type, principal_key → UNIQUE; count,
  last_ip), `access_events` (id, ts INDEX, principal, ip, method, path, status).
  `UtcDateTime`-Spalten, re-runnable DDL.
- Neues Feature-Paket `app/access/` (store.py mit Puffer/flush/prune nach
  `denials.py`-Vorbild, routes.py `require_admin`, schemas.py).
- Endpoints: `GET /api/access/summary` (Aggregate + Online-Sessions),
  `GET /api/access/timeline` (server-seitig gemerged aus audit `auth.*`,
  `access_events`, `geoip_denial_events`; ts-Cursor, Typ-Filter).
- Scheduler: 15s-Flush (Zähler, last_seen), 5-min Session-Expiry,
  täglicher Prune — alle idempotent, `max_instances=1`, eigene Session.
- `test_role_guards.py` bleibt grün; neue Tests: Guard-Test (view_only → 401/403
  auf audit+access), Flush/Drossel-Unit-Tests DB-frei, Expiry-Event-Test.

## Verworfene Alternativen

- **Voll-Log jedes Requests** — Volumen/Gap-Lock-Risiko (Incident-Historie).
- **Frontend-gemeldete Seiten-Navigation** — umgehbar, blind für API-Keys/curl,
  neuer Client-Pfad.
- **Registry-Enforcement + Idle-Timeout + Session-Kill** — ein DB-Read pro
  Request bzw. neue Prozess-Invarianten für ein Feature ohne akuten Bedarf;
  Kill via `password_version` bleibt als billiger Weg dokumentiert (DR-AL5).
- **Neue eigene Nav-Seite** — Tab auf der Audit-Seite reicht, weniger Nav-Lärm.
- **Zweistufige Sichtbarkeit (Detail nur superadmin)** — bewusst verworfen,
  Admins sind hier das Betriebs-Team (DR-AL1, DSGVO-Hinweis dort).
