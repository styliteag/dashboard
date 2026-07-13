# Glossar

Domänenbegriffe des Orbit-Dashboards. Quelle der Wahrheit ist der Code; §-Verweise
zeigen auf `docs/agent-architecture.md`.

- **Instanz** — ein verwaltetes Gerät (Firewall oder Server) als DB-Objekt
  (`Instance`, `db/models.py`). Träger von `device_type`, `transport`, Credentials,
  Gruppen-Zuordnung.
- **Device-Type** — Geräteklasse einer Instanz (`devices/types.py`): `opnsense`,
  `pfsense`, `securepoint`, `proxmox`, `truenas`, `qnap`, geplant `linux` (§25).
  Bestimmt Client-Wahl und Capabilities, nicht den Transport.
- **Transport** — wie Daten die Instanz erreichen/verlassen: `pull` (Backend pollt
  HTTP-API) oder `push` (Agent liefert per WebSocket). Entkoppelt vom Device-Type
  (DR-1).
- **Capability-Map** — zentrale Tabelle `DEVICE_CAPS[device_type]` → welche Features
  (Tunnel, Webif, Firewall-Rules, Capture, Shell, Relay, Updates-Stil) ein Typ hat;
  ersetzt verstreute Typ-Checks (DR-8, §25).
- **Agent** — `agent/orbit_agent.py`: eine stdlib-only Python-Datei (Floor 3.8), läuft
  als root auf der Box, pusht Snapshots, führt Commands aus, updatet sich signiert
  selbst (§3, §5).
- **Hub** — In-Memory-Verwaltung der verbundenen Agent-WebSockets im Backend
  (`app/agent_hub/`); hält letzte Snapshots pro Instanz. Ungescoped — Konsumenten
  filtern über `_visible_instance_ids`.
- **Enrollment / Enroll-Code** — Einmal-Code, den das Dashboard pro Instanz ausstellt;
  der Agent tauscht ihn gegen sein `agent_token` und setzt `transport=push`
  (`agent_hub/routes/enroll.py`).
- **Collector / Section** — parameterlose `collect_*()`-Funktion im Agent; ihr Ergebnis
  wird unter einem Section-Namen (`cpu`, `ipsec`, `firmware`, …) im Snapshot gepusht.
  Registry: `_SNAPSHOT_SECTIONS`.
- **Snapshot** — vollständiger Push eines Agents (alle Sections); Basis des Hub-Caches
  und der Checks.
- **Checkmk-Agent (vendored)** — upstream `check_mk_agent.linux` (GPLv2-Shellskript),
  unverändert im Repo gepinnt, Ed25519-signiert an Linux-Nodes ausgeliefert; sein
  Output landet als Section `checkmk_raw` im Snapshot, das Backend parst die
  Checkmk-Sections schrittweise (DR-10, §25).
- **Check / Check-Familie** — pure, DB-freie Bewertungsfunktion
  (`checks/evaluate.py`) → Zustand 0=OK 1=WARN 2=CRIT 3=UNKNOWN (Checkmk-Konvention).
  Familien-Keys `family:stable-id`. Kein Check auf fehlende Daten.
- **Overlay** — `overlay_checks(...)`: legt Staleness-Cap, Probe-Checks und
  Maintenance-Ceiling über die Roh-Checks; alle vier Ausgabe-Flächen (Checkmk,
  Prometheus, Alerts-Seite, Instanz-Tab) müssen identisch sein.
- **Self-Heal** — Backend korrigiert den `device_type` einer Instanz anhand der
  `platform` im Hello-Frame des Agents (`_sync_device_type`, heute OPN↔PFS, geplant
  + `linux`).
- **Supervisor** — `run-agent.sh`: Respawn-Loop um den Agent; exit 42 = Update-Respawn,
  Marker + Kurzlaufzeit + `.bak` = Rollback (DR-5). Außerhalb des Self-Update-Pfads.
- **Probation** — Bewährungsfenster nach Agent-Self-Update; scheitert es, rollt der
  Supervisor auf `.bak` zurück (§5.2).
- **Signatur (`.sig`)** — Ed25519-Signatur über `orbit_agent.py`; Pubkey im Agent
  eingebacken, Flotte lehnt unsignierte/veraltete Updates ab (`just sign-agent`).
- **Canary** — Rollout-Muster: Update erst auf eine Box, dann Flotte (DR-6).
- **Relay** — vom Agent ausgerollter transparenter HTTP-Tunnel zur Box-API/Webif;
  Dashboard bleibt keyless (DR-3, DR-7, §15). Für `linux` in v1 deaktiviert.
- **GUI-Proxy** — Reverse-Proxy-Zugriff aufs Box-Webif über die Agent-WS (§18).
- **Scope / Gruppen-Scoping** — Sichtbarkeitsmodell: User sieht nur Instanzen seiner
  Gruppen (`auth/scope.py`); out-of-scope antwortet 404, nie 403. User ohne Gruppen
  sieht nichts; ApiKey ohne Bindings sieht alles.
- **Principal** — auth-Kontext einer Anfrage (User oder ApiKey); `None` = interner
  Aufrufer (Poller/Hub), ungescoped.
- **GeoIP-Restriktion** — globale, superadmin-verwaltete Zugriffsschicht: Client-IP →
  Land (lokale GeoLite2-mmdb) gegen Länder-Allowlist, geprüft per ASGI-Middleware auf
  jeder Session-Request (`app/geoip/`, ADR `docs/geoip-access-restriction.md`).
  Agent-WS und `orbit_`-API-Keys sind ausgenommen; leere Config = allow all.
- **GeoIP-Whitelist** — Bypass-Liste der GeoIP-Restriktion; Einträge sind CIDRs
  (v4/v6) oder DynDNS-Hostnames (periodisch A+AAAA aufgelöst, letzte bekannte IPs
  bleiben bei DNS-Fehlern gültig).
- **Kill-Switch (GeoIP)** — `DASH_GEOIP_DISABLE=true`, env-only: schaltet die
  GeoIP-Prüfung ab, wenn eine Fehlkonfiguration aussperrt; bewusst nicht im UI.
- **CrowdSec-Blocklist** — optionale zweite Signalquelle der GeoIP-Restriktion
  (DR-G8): Ban-Decisions eines CrowdSec-Sidecars, per Stream-Pull (30 s) in einen
  Prozess-Cache; Whitelist schlägt Blocklist, Blocklist schlägt Länder-Allow.
  Aktiv sobald `DASH_CROWDSEC_API_KEY` gesetzt; `DASH_CROWDSEC_DISABLE=true`
  schaltet ab (Form wie `DASH_GEOIP_DISABLE`); LAPI-Ausfall behält letzte Bans.
- **Session-Registry** — server-seitige Buchführung der Login-Sessions
  (`auth_sessions`: sid, User, Login-IP, created/last_seen/ended). Bewusst OHNE
  Enforcement: der Session-Cookie (+ `password_version`) bleibt alleinige
  Auth-Wahrheit (ADR `docs/access-log.md`, DR-AL3). „Online" = last_seen ≤ 5 min.
- **Access-Aggregat / Access-Sample** — zweistufige Request-Erfassung nach dem
  Denial-Muster (DR-G9): `access_stats` zählt jeden Request pro (Stunde,
  Principal), `access_events` hält pro Flush-Intervall gedeckelte Einzel-Samples;
  Request-Pfad schreibt nur in bounded Puffer, 15s-Job flusht (DR-AL2).
- **Access-Timeline** — admin-sichtbare, chronologisch gemergte Ereignisliste im
  Access-Tab der Audit-Seite: Logins/Fails/Logout/Session-expired (Audit),
  GeoIP-CrowdSec-Denials, Request-Samples — mit Typ-Filter (DR-AL7/AL9).
- **Auto-Logout** — Ablauf der 12h-Cookie-max_age; seit der Session-Registry als
  echtes Ereignis sichtbar: Expiry-Job markiert die Registry-Zeile
  (`end_reason="expired"`) und schreibt `auth.session_expired` ins Audit (DR-AL4).
