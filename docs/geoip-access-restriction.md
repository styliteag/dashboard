# GeoIP-Zugriffsbeschränkung (ADR)

Status: beschlossen (Grill-Session 2026-07-12, wb) — Implementierung im selben Zug.
Sprache dieses Dokuments: Deutsch (wie `agent-architecture.md`); Code/Kommentare/UI: Englisch.

## Kontext

Das Dashboard ist ein Hochrisiko-Dienst: Wer eine Session übernimmt, steuert ~70
Kunden-Firewalls inklusive Root-Shell. Passwort + MFA existieren; als zusätzliche
Schicht wird der Zugriff geographisch eingeschränkt (Betrieb ist ein deutscher MSP —
legitime Logins kommen praktisch nur aus DACH).

## Entscheidungen

### DR-G1 — Datenquelle: lokale GeoLite2-Country mmdb

MaxMind GeoLite2-Country als lokale `.mmdb`-Datei; Lookup in-process (<1 ms), keine
Login-IPs an Dritte (Datenschutz). Kein Online-Lookup-Dienst. Die DB enthält IPv4
**und** IPv6.

Aktualisierung: wöchentlicher Scheduler-Job (`refresh_geoip_db`,
`poller/scheduler.py`-Muster, `max_instances=1`) lädt mit `DASH_MAXMIND_LICENSE_KEY`
das offizielle Tarball, entpackt und ersetzt die mmdb **atomar** (tmp + rename),
lädt den Reader neu. Ohne Key: Job bleibt idle, manueller Weg (Volume) funktioniert
weiter. Das Alter der DB ist im Superadmin-UI sichtbar.

### DR-G2 — Enforcement: Login UND jede Session-Request

Geo-Prüfung als **pure-ASGI-Middleware** (kein `BaseHTTPMiddleware`, Repo-Regel) auf
allen Requests, plus dadurch implizit auf dem Login. Ein gestohlener Session-Cookie
aus einem nicht erlaubten Land ist damit sofort wertlos, nicht erst beim nächsten
Login.

Ausnahmen (in dieser Reihenfolge geprüft):

1. **Kill-Switch** `DASH_GEOIP_DISABLE=true` (env-only, bewusst NICHT im Settings-UI:
   Rettungsanker, wenn die Config selbst aussperrt; Container-Neustart nötig).
2. **Agent-WebSocket** `/api/ws/agent` — Firewalls verbinden von Kundenstandorten
   weltweit; Agents authentifizieren per Token, nie geo-blocken.
3. **API-Key-Requests** (`Authorization: Bearer orbit_…`) — Maschinen-Reads
   (Checkmk/Prometheus), read-only by construction, oft aus Rechenzentren.
4. **Whitelist-Treffer** (DR-G4).
5. Sonst: Land der Client-IP (`app.net.client_ip`, respektiert
   `trusted_proxy_hops`) gegen die Länder-Allowlist.

Geblockte Requests: **403** mit expliziter Meldung "access restricted from your
location" (ohne Landnennung). Login-Pfad-Denials werden auditiert
(`auth.login`, result=denied, reason=geo_blocked, Land im Detail); alle anderen
Denials nur strukturiert geloggt (rate-limitiert), kein DB-Write pro Request.

### DR-G3 — Leere Config = allow all; Default aus

`geoip_enforce` default **false**. Und: keine Länder gewählt UND Whitelist leer →
allow all, selbst wenn enforce=true. Es gibt damit keinen Erst-Boot-Lockout-Pfad.
Scharf wird das System erst durch bewusstes Konfigurieren.

Achtung (dokumentierter Fallstrick): Sobald Länder gesetzt sind, haben private IPs
(RFC1918, ULA fc00::/7, ::1) **kein Land** und fallen unter fail-closed — LAN-/VPN-
Zugriff braucht dann einen Whitelist-Eintrag. Die Warnprüfung beim Speichern
(DR-G5) fängt das ab, weil der speichernde Admin typischerweise selbst so zugreift.

### DR-G4 — Whitelist: CIDR **und** DynDNS-Hostnames, v4+v6

Superadmin-verwaltete Liste; jeder Eintrag ist entweder

- ein **CIDR** (`10.0.0.0/8`, `2001:db8::/32`, einzelne IP als /32 bzw. /128), oder
- ein **DynDNS-Hostname** (`host.dyndns.de`): ein Hintergrund-Job löst alle
  Hostnames alle 5 Minuten auf (A **und** AAAA); die Middleware prüft gegen die
  zuletzt aufgelösten IPs. DNS-Fehler behalten die letzten bekannten IPs
  (flatterndes DNS darf nicht aussperren); aufgelöste IPs + Zeitpunkt sind im UI
  sichtbar. Sicherheits-Tradeoff (bewusst): Wer die DNS-Zone des Eintrags
  kontrolliert, kontrolliert den Bypass.

IPv6 durchgängig: Länder-Lookup (mmdb), CIDR-Matching (`ipaddress`-Modul) und
DynDNS-Auflösung behandeln v4 und v6 gleichwertig.

### DR-G5 — Fail-Semantik und Lockout-Schutz

- IP ohne Land-Eintrag (bei konfigurierten Ländern): **deny** (fail-closed).
- mmdb fehlt/unlesbar: **allow** + lautes strukturiertes Log + Banner im
  Superadmin-UI (fail-open nur für den Infrastrukturfehler — ein kaputtes
  DB-Update darf nicht die ganze Firma aussperren; der Kill-Switch bleibt
  zweiter Rettungsanker).
- Speichern einer Config, unter der die **eigene** IP des Speichernden geblockt
  würde: Warnung + Bestätigung im UI (dry-run-Check im Backend), Speichern
  bleibt erlaubt (bewusster VPN-Wechsel möglich).

### DR-G6 — Global, superadmin-verwaltet, eigene Tabelle

Eine globale Länder-Allowlist für alle User, keine per-User-Overrides (Sonderfälle
über die Whitelist). Konfiguration liegt in einer **eigenen Tabelle**
(`geoip_config`, Einzeiler), NICHT in der Settings-Registry: deren generische
Routen sind admin-gated (`require_admin`), diese Fläche ist ausschließlich
`require_superadmin`. Jede Änderung wird auditiert (`geoip.config.update`,
allowlisted Detail-Felder).

### DR-G7 — Sichtbarkeit

- Jeder User sieht seine aktuelle IP (+ Land, wenn ermittelbar) in der
  **Footer-Statusleiste** (`/auth/me` liefert `client_ip` + `client_country`).
- Admins sehen auf der Users-Seite IP + Land des **letzten erfolgreichen Logins**
  (`users.last_login_ip/_country/_at`, gesetzt beim Session-Mint im MFA-Schritt —
  nicht beim Passwort-Schritt, der noch keine Session erzeugt).

### DR-G8 — CrowdSec-Blocklist (umgesetzt als zweite Stufe)

Bad-Actor-Anreicherung über ein optionales CrowdSec-Sidecar (LAPI,
compose-Profile `crowdsec`): ein Scheduler-Job (30 s) zieht Ban-Decisions im
**Stream-Modus** (`/v1/decisions/stream`, erster Pull `startup=true` =
Vollbestand, danach Deltas) in einen Prozess-Cache — nie Live-HTTP im
Request-Pfad. Einzel-IPs im O(1)-Set, echte Ranges (v4/v6) linear.

- **Eigener Schalter, gleiche Form wie GeoIP**: aktiv, sobald
  `DASH_CROWDSEC_API_KEY` gesetzt ist (+ `DASH_CROWDSEC_LAPI_URL`);
  `DASH_CROWDSEC_DISABLE=true` schaltet ab, ohne den Key zu entfernen —
  spiegelbildlich zu `DASH_GEOIP_DISABLE`, der weiterhin beides abschaltet.
  Unabhängig von der Länder-Restriktion: die Blocklist beißt auch, wenn
  keine Länder konfiguriert sind.
- **Prioritäten**: Whitelist schlägt Blocklist (Operator-Rettung zuerst),
  Blocklist schlägt Länder-Allow. Reihenfolge ist Teil des
  `decide()`-Vertrags und getestet.
- **Ausfall-Semantik**: LAPI down → letzte bekannte Bans bleiben aktiv
  ("stale beats empty" — ein Sync-Schluckauf darf nicht alle Angreifer auf
  einmal entbannen); Fehlzustand im Status-Endpoint/UI sichtbar.
- Agents/`orbit_`-Keys bleiben ausgenommen (wie DR-G2). Bouncer-Key:
  `docker exec dashboard-crowdsec-1 cscli bouncers add orbit-dashboard`.

## Nicht-Ziele

- Kein Geo-Blocking für Agent-Verbindungen oder API-Keys (siehe DR-G2).
- Keine Stadt-/ASN-Auflösung, nur Land (GeoLite2-**Country**).
- Kein per-User-Länder-Modell.

## Betroffene env-Variablen

`DASH_GEOIP_DISABLE` (Kill-Switch), `DASH_MAXMIND_LICENSE_KEY`,
`DASH_GEOIP_DB_PATH` — alle drei in `.env.example` + `compose.yml` +
`compose-dev.yml` (Incident 9767355: nur-dev-compose-Variablen sind in prod
nicht aktivierbar).
