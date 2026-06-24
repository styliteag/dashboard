# Agent- & Connectivity-Architektur (Design-Doc)

Status: **Entwurf zur Review** · Stand: 2026-06-23 · Betrifft: `agent/`, `backend/src/app/agent_hub/`, `backend/src/app/opnsense/`

Dieses Dokument hält die Architektur-Entscheidungen für die Anbindung von Kundensystemen
(OPNsense, pfSense, später Proxmox/TrueNAS/QNAP) fest und beschreibt das geplante
Agent-Selbstupdate. Es ist die Diskussionsgrundlage *vor* der Implementierung.

---

## 1. Ziel & Randbedingungen

- Dashboard läuft zentral im Internet (öffentliche IP, HTTPS).
- Kundensysteme stehen oft **hinter NAT** → direkter API-Zugriff vom Dashboard nicht immer möglich.
- Geräte sind heterogen: OPNsense/pfSense (FreeBSD-Firewalls), später Proxmox (Debian),
  TrueNAS, QNAP (API-first-Appliances).
- Flotte mittelfristig **20–200 Standorte**.
- Steuerung (reboot, firmware, config) kommt **später, anfangs wenig** — aber wir designen dafür.

## 2. Kernentscheidung: Transport und Integration entkoppeln

Heute verheiratet das Flag `Instance.agent_mode: bool` zwei Achsen, die getrennt gehören:

- **Transport** — *wie* erreiche ich das Gerät? `direct` | `relay` | `push`
- **Device-Type** — *wie* lese/steuere ich es? `opnsense` | `pfsense` | `proxmox` | `truenas` | `qnap`

→ **DR-1: `agent_mode: bool` wird ersetzt durch `transport` (Enum) + `device_type` (Enum).**
`OPNsenseClient` wird eine Implementierung eines `DeviceClient`-Protocols. Neue API-Geräte
kommen als weitere `DeviceClient` ins Backend, **nicht** als Shell-Agenten.

### Die drei Transporte

| Transport | Wer initiiert | Wer sammelt | Einsatz |
|---|---|---|---|
| `direct` | Dashboard → Gerät-API | Backend `DeviceClient` | Gerät direkt erreichbar |
| `push` | Gerät → outbound `wss://…/ws/agent` | Agent lokal (Shell) | **Primär für OPNsense/pfSense hinter NAT** |
| `relay` | Agent hält Tunnel, Dashboard proxyt HTTP durch | Backend `DeviceClient` über Tunnel | **Optionaler dritter Weg** — LAN-Geräte am Standort |

**DR-2: Für OPNsense & pfSense ist `push` der primäre Weg.** Shell-Zugriff ist dort
sinnvoll (IPsec, Gateways, Firmware lassen sich lokal sauber abfragen/steuern, ohne API-Key).

**DR-3: `relay` ist optional und wird vom Agenten ausgerollt.** Die Firewall ist der
de-facto Always-on-Host am Standort und sitzt im selben LAN wie Proxmox/TrueNAS/QNAP.
Auf Dashboard-Befehl aktiviert der Agent eine Reverse-Proxy-Funktion und macht damit
andere LAN-Geräte erreichbar — ohne auf ihnen etwas zu installieren. Erst relevant, wenn
API-Geräte angebunden werden.

## 3. Agent-Stack: pure-stdlib Python (keine `websockets`-Dependency)

**DR-4: Der Agent bleibt Python, wird aber dependency-frei.** Die `pip install websockets`-
Abhängigkeit fällt weg; der WebSocket-Client (RFC 6455 Subset: Handshake + **Client-Masking
(Pflicht)** + Fragmentierung + Ping/Pong + Close-Handshake) wird über stdlib selbst
implementiert. Realistisch mehr als ~150 Zeilen — robustes Framing ist der Aufwand.
**`asyncio.open_connection` (stdlib) nutzen** → das bestehende async-Modell
(`_push_loop`/`_listen_loop` nebenläufig) bleibt erhalten, nur Handshake/Framing wird getauscht,
nicht die Concurrency neu gebaut.

Begründung:
- **Entschärft pfSense CE** (siehe §7) — kein Fremdpaket-`pkg`/`pip` nötig.
- **Simpleres Selbstupdate** — genau *eine* Datei, null Deps zu mit-managen.
- Passt zu CLAUDE.md: „Agent-Deps minimal, FreeBSD, keine Linux-Annahmen".

Fallback (nur falls pfSense *gar kein* Python mitbringt): statisches FreeBSD-Binary (Go).
Größerer Pivot, hier bewusst zurückgestellt bis der pfSense-Spike (§7) entscheidet.

## 4. Platform-Abstraktion im Agenten (OPNsense vs. pfSense)

Beide sind FreeBSD → viele Collectors identisch, einige unterscheiden sich.

- **Plattform-Detection** beim Start (z. B. `/usr/local/opnsense/version/` ⇒ OPNsense;
  `/etc/version` + pfSense-Marker ⇒ pfSense). Ergebnis geht ins `hello`.
Divergenz **per Spike auf pfSense Plus 26.03 bestätigt** (2026-06-23):

- **Geteilt** (sysctl/netstat/ifconfig): CPU, Memory, Disk, Interfaces.
  - IPsec: `swanctl` auf beiden vorhanden ✓ → geteilt.
  - Config: `/conf/config.xml` auf beiden nutzbar ✓ (pfSense: Symlink → `/cf/conf/config.xml`).
  - Firewall-Log: `/var/log/filter.log` auf beiden, **kein `clog` auf pfSense Plus** → Klartext
    (filterlog-CSV), `tail`-bar wie OPNsense. Zeilenformat ggf. minimal anders, Parser anpassbar.
- **Divergiert** — nur diese zwei pro Plattform neu:
  - Gateways: OPNsense `pluginctl -r return_gateways_status` ↔ pfSense **`pluginctl` fehlt** →
    `/usr/local/sbin/pfSsh.php` (playback / PHP).
  - Firmware: OPNsense `opnsense-update -c` ↔ pfSense **`opnsense-update` fehlt** →
    `/usr/local/sbin/pfSense-upgrade`.

→ Collectors hinter eine kleine Dispatch-Schicht (`collect_*` pro Plattform), gemeinsame
Funktionen wiederverwenden. Aufwand pfSense-Port: **2 Collectors** (Gateways, Firmware),
Rest geteilt.

## 5. Agent-Selbstupdate (dashboard-gesteuert)

Höchster Hebel bei 20–200 Sites: ohne Remote-Update = jeder Agent-Bugfix = 200 SSH-Sessions.
Gleichzeitig **RCE-by-Design** über alle Kunden-Firewalls → höchste Sorgfaltsstufe.

### 5.1 Protokoll

1. Agent meldet `agent_version` im `hello` (tut er schon).
2. Soll-Version = `__version__` der **vom Container ausgelieferten** `agent/opnsense_agent.py`
   — **kein separater Blob-Store**. Dashboard vergleicht gemeldet vs. ausgeliefert.
3. Update wird **durch den authentifizierten WS** gepusht:
   `{"type":"agent.update","version":…,"sha256":…,"code":<b64>}` (10 MB `max_size` reicht).
   **Nicht** über das offene `/agent/script` (das bleibt nur für Bootstrap-Install — anderer
   Trust-Kontext, kurz erwähnt in §6).
4. Agent: `opnsense_agent.py.new` **im Zielverzeichnis** schreiben (nicht `/tmp`; `os.rename`
   ist nur dateisystem-intern atomar) → sha256 verifizieren → `.bak` anlegen → atomic swap →
   Update-Marker setzen → Restart.

### 5.2 Restart & Rollback (zwei Ebenen)

Befund aus `agent/rc.d/opnsense_dash_agent`: `daemon(8)` läuft **ohne `-r`** → kein Respawn,
**heute kein Watchdog**. Ein toter Agent kann sich nicht selbst zurückrollen.

→ **DR-5: Ein Supervisor-Wrapper `run-agent.sh` wird eingeführt** (rc.d ruft ihn statt direkt
Python). Er macht Selbstupdate erst sicher benutzbar. Zwei Rollback-Ebenen:

- **Agent-Ebene (Probation):** Startet der Agent mit gesetztem Update-Marker, muss er binnen
  ~60 s einen gesunden WS-`welcome` mit der neuen Version erreichen. Sonst: `.bak` restaurieren
  und in alten Code `execv`en. Fängt „läuft, redet aber nicht" (Config-Inkompat, falsche URL).
- **Supervisor-Ebene (Wrapper):** Crasht der neue Code sofort/wiederholt (kommt nicht mal in
  die Probation-Logik), restauriert der Wrapper `.bak`. Fängt Hard-Crashes.

Zwei Ebenen, weil jede fängt, was die andere nicht kann. **`py_compile` ist Scheinsicherheit**
(nur Syntax) — der einzige echte Gesundheitstest ist „gesund reconnected mit neuer Version".

**Wichtig: Der Supervisor liegt außerhalb des Selbstupdate-Pfads.** `agent.update` (§5.1)
tauscht nur `opnsense_agent.py` — der Wrapper + rc.d, also genau die Komponente, die Updates
sicher macht, wird *nicht* mit-aktualisiert. Daraus folgt eine Design-Vorgabe: **der Supervisor
muss bewusst minimal & stabil sein**, weil er sich nicht selbst updaten kann; ein Bug darin =
manueller Fix auf allen Boxen. Ob das Update-Protokoll später Multi-File kann (agent.py +
Wrapper + rc.d), ist offen (§11).

### 5.3 Rollout

**DR-6: Canary vor Flotte.** Nie alle Sites gleichzeitig: erst 2–3 Kanarien, gesunden
Reconnect@neueVersion abwarten, dann der Rest. Wichtiger als Signatur für v1. Jeder
Update-Versuch + Ergebnis ins bestehende `audit_log`.

### 5.4 Selbst-Bootstrap-Risiko

Ein Bug **im Update-/Rollback-Pfad selbst** ist nicht remote fixbar → wirft auf manuelles
Recovery (SSH auf alle Boxen) zurück. → Diesen Pfad **härter testen als alles andere**,
*vor* dem einen manuellen Rollout, der v0.2 in die Flotte bringt.

## 6. Security-Modell

| Thema | Heute | Plan |
|---|---|---|
| Agent-Auth | Bearer `agent_token` (random, DB-Lookup), pro Instance | v1 ok |
| Token-Rotation/-Expiry | keine | mit Steuerung (§ Phasen) Pflicht |
| Dashboard→Agent-Authentizität | wss + TLS-Server-Cert (gepinnte Dashboard-URL) | v1-Basis |
| Update-Integrität | — | v1: sha256 + TLS · **später: Signatur** |
| `/agent/script`, `/agent/rc` | **ohne Auth** | nur Bootstrap, kein Geheimnis; Update läuft über WS |
| `config.backup` | liefert ganze `config.xml` (Secrets im Klartext) über WS | scoped/Access-Control mit Steuerung |

**Genannte Entscheidung (Signatur):** Retrofit über eine deployte Flotte ist Henne-Ei
(erst Public-Key ausrollen, dann ab da signiert). v1 ohne Signatur ist vertretbar. Der
eigentliche Hebel ist ein **Offline-Signing-Key, NICHT auf dem Dashboard** — dann bricht
ein Dashboard-Compromise nicht die ganze Flotte. Bewusst zu wählen, weil „Steuerung später"
genau diese Sicherheit betrifft.

**Bekannte Grenze (in-memory Hub):** `AgentHub` ist Singleton/Single-Process. Bei mehreren
Backend-Replicas kleben WS-Connections an einem Prozess; `send_agent_command` auf Replica B
findet den Agent nicht. Bis ~200 Sites / Single-Process unkritisch — bei Scale-out
Redis-Pub/Sub oder sticky-routing revisiten.

## 7. pfSense + Python — Spike-Ergebnis

**Spike (2026-06-23) auf Netgate-Box `cvo-gigu`:**

```
FreeBSD 16.0-CURRENT … plus-RELENG_26_03 … pfSense arm64
/usr/local/bin/python3.11  ·  Python 3.11.14  ·  stdlib ssl+socket OK
```

→ **Bestätigt für pfSense Plus / arm64:** python3.11 vorhanden, stdlib `ssl`/`socket` da.
**DR-4 (stdlib-Agent) trägt** — keine pip-Frage. **arm64 verstärkt die Wahl:** der
stdlib-Python-Agent ist architekturunabhängig; ein Go-Binary-Fallback müsste freebsd/arm64
*und* amd64 cross-compilen → stdlib umgeht das.

**Collector-Tooling — bestätigt (2026-06-23, pfSense Plus 26.03):** `swanctl` ✓, `pfSsh.php` ✓,
`pfSense-upgrade` ✓, `filter.log` ✓ (kein `clog`, Klartext), `/conf/config.xml` ✓. `pluginctl`
und `opnsense-update` fehlen (OPNsense-only). Divergenz-Map in §4.

**Noch offen:**
- **pfSense CE** — diese Box ist **Plus** (liefert Python). CE bringt Python nicht per
  default; falls die Flotte gemischt ist, CE-Subset separat prüfen.

## 8. Backend-Änderungen (Fundament)

- Schema: `Instance.agent_mode` → `transport` + `device_type` (Enums). **Alembic-Revision**
  Pflicht (CLAUDE.md done-criteria: numbered `NNN_*.py`, sequential).
- `DeviceClient`-Protocol (Python `Protocol`); `OPNsenseClient` implementiert es.
- `poller/scheduler.py`: pollt nur `transport == direct` (bzw. `relay`); `push` bleibt außen vor.
- Enrollment: bei 20–200 Sites lohnt One-Time-Code → Self-Register (statt manuellem Token-Paste).

## 9. Phasenplan

0. **Fundament (Backend) — ✅ umgesetzt (2026-06-23):** Schema-Split `transport`+`device_type`
   (`app/devices/types.py`), `DeviceClient`-Protocol (`app/devices/protocol.py`, von
   `OPNsenseClient` erfüllt), `agent_mode` als read-only Back-compat-Property am Model,
   Poller filtert `transport == direct`, Migration `002` (MariaDB, dialekt-gerendert verifiziert).
   `agent_mode` bleibt in der API (Frontend-kompatibel). Tests: `tests/test_devices.py`.
   Migration appliziert automatisch beim nächsten dev/prod-Container-Start (nicht manuell).
   Kein Verhaltenswechsel.
1. **Agent v0.3 (OPNsense, verifiziert gut):**
   - ✅ **stdlib-WS (DR-4) umgesetzt (2026-06-23)**: `websockets`-Pip-Dep entfernt, RFC-6455-
     Client in `opnsense_agent.py` (Handshake, Client-Masking, Fragment-Reassembly, Ping/Pong,
     Close, NAT-Keepalive). Tests `agent/tests/test_ws.py` — Framing-Unit + **Interop gegen
     `websockets`-Referenzserver** (`just agent-test`). Agent dependency-frei.
   - ✅ **Selbstupdate umgesetzt (2026-06-23, `__version__` 0.3.0)**:
     - Supervisor `agent/run-agent.sh` (DR-5): Respawn-Loop + Rollback; rc.d ruft ihn statt
       Python direkt (Interpreter als `$1`), SIGTERM wird an den Child weitergereicht.
     - `agent.update` über den authentifizierten WS: sha256 + `compile()`-Verify → atomic swap
       (tmp im Zielverzeichnis) → Probation-Marker → Exit 42 → Supervisor respawnt neuen Code.
     - **Zwei-Ebenen-Rollback**: Agent-Probation (kein gesunder `welcome` in 60s → `.bak`
       zurück, Exit) + Supervisor (schneller Crash mit Marker → `.bak` zurück vor Respawn).
       Exit-Code 42 trennt gewollten Update-Restart von Crash.
     - Backend: `POST /instances/{id}/agent/update` (per-Instance = Canary, DR-6), sendet den
       Container-Agent (`__version__` als Soll-Version); `/agent/status` zeigt
       gemeldete vs. gelieferte Version + `update_available`; `agent_version`/`platform` aus
       hello gespeichert. `/agent/run` serviert den Supervisor.
     - Tests: `agent/tests/test_selfupdate.py` (verify/apply/rollback/probation),
       `tests/test_agent_update.py` (Versions-Parser).
   - ⛔ **Vor Produktiv-Rollout**: Restart + Supervisor-Rollback **live auf echter Box** testen
     (deterministische Primitive sind unit-getestet; der Prozess-Restart/Crash-Pfad nicht).
     Signatur (Offline-Key) bleibt für später (§6) — v1 = sha256 + TLS + Canary + Audit.
2. **pfSense-Spike (§7)** — gates 3. Läuft parallel zu 0/1.
3. **pfSense-Support:**
   - ✅ **Plattform-Detection + Dispatch umgesetzt (2026-06-23)**: `detect_platform()` (Marker
     aus dem Spike), Agent meldet `platform` im `hello`, `collect_firmware`/`collect_gateways`
     dispatchen pro Plattform. pfSense-**Firmware-Version** via `/etc/version`. Geteilte
     Collectors (cpu/mem/disk/iface/ipsec/firewall_log/config) unverändert. Tests
     `agent/tests/test_collectors.py`. → Agent läuft jetzt auf pfSense für System-Metriken.
     Backend-seitig: `hub`-Konverter (`status/gateways/ipsec/firmware_from_agent`) extrahiert +
     kontraktgetestet (`tests/test_agent_hub.py`); gemeldetes `platform` fließt in
     `SystemStatus.platform`.
   - ✅ **Gateways + Update-Check finalisiert (2026-06-23, echte Samples)**: pfSense-Gateways via
     `php -r 'return_gateways_status(true)'` (sauberes JSON → `_collect_gateways_pfsense()`);
     Update-Check via `pfSense-upgrade -c` (Negativ-Fall „up to date" bestätigt; Positiv-Wording
     inferiert, gegen Box mit pending Update nochmal verifizieren). Tests mit Real-Sample.
   - ✅ **Interpreter-Fix (2026-06-23)**: auf der Box gibt es **kein `/usr/local/bin/python3`**,
     nur `python3.11`. `rc.d` + `install.sh` lösen den Interpreter jetzt robust auf
     (`python3` → `python3.11` → …). Ohne das wäre der Agent auf pfSense nicht gestartet.
   - ⬜ Command-Side (`execute_command` firmware.check/update + reboot) pro Plattform dispatchen
     (Control-Plane, später). Aktuell OPNsense-spezifisch.
4. **Relay (optionaler dritter Weg):** WS um `http_request`/`http_response` erweitern;
   Dashboard-Befehl `proxy.enable` (Ziel-Allowlist).
5. **API-Geräte:** Proxmox (sauberste API) als erstes relay-only `device_type`, dann
   TrueNAS, QNAP — reiner Backend-Code.
6. **Steuerungs-Hardening (wenn Control wächst):** Token-Rotation/-Expiry, Update-Signatur
   (Offline-Key), scoped Commands, `config.xml`-Schutz, Enrollment-Automatik.
7. **Checkmk/OMD-Integration (§13):** State-Layer (green/red) + `/checks`-Export-Endpoint →
   Checkmk special-agent Plugin (Piggyback pro Firewall) → mehr Collector-Checks.

## 10. Decision Record (Kurzfassung)

- **DR-1** Transport + Device-Type entkoppeln (`agent_mode` raus).
- **DR-2** `push`-Agent primär für OPNsense/pfSense.
- **DR-3** `relay`/Reverse-Proxy optional, vom Agenten ausgerollt.
- **DR-4** Agent = pure-stdlib Python, keine `websockets`-Dependency.
- **DR-5** Supervisor-Wrapper `run-agent.sh` + Zwei-Ebenen-Rollback.
- **DR-6** Canary-Rollout vor Flotte; Update über authentifizierten WS, nicht `/agent/script`.

## 11. Offene Punkte

- pfSense-Spike-Ergebnis (§7) — gates pfSense-Weg komplett.
- pfSense Collector-Details (Gateways, Firmware, Firewall-Log-Binärformat).
- Offline-Signing-Key: ja/nein für v1, Schlüsselverwaltung.
- Enrollment-Flow konkret (One-Time-Code, Token-Vergabe, Self-Register).
- Multi-File-Update: bleibt der Supervisor/rc.d für immer manuell, oder kann `agent.update`
  später agent.py + Wrapper + rc.d atomar mit-tauschen? (Architektur-Frage, jetzt nur benannt.)
- **pfSense-Interpreter:** `rc.d`/`install.sh` rufen `/usr/local/bin/python3`; auf der Box ist
  nur `python3.11` bestätigt. Ohne `python3`-Symlink startet der Agent nicht → Spike §12 prüft
  `ls -l /usr/local/bin/python3*`; ggf. rc.d auf konkreten Pfad anpassen. Gated pfSense-Deployment.
- **Checkmk-Export (§13):** Service-Key-Schema + Schwellen-Defaults + Perfdata-Namen festlegen,
  bevor das Plugin gebaut wird (stabile Kontrakt-Fläche — Checkmk-Discovery hängt an Service-Keys).

## 12. pfSense Collector-Spike — ✅ erledigt (2026-06-23)

Auf `cvo-gigu` (pfSense Plus 26.03) ausgeführt; Ergebnisse eingearbeitet (Phase 3 §9):
- **python**: nur `python3.11`, kein `python3`-Symlink → rc.d/install.sh-Interpreter-Fix.
- **Gateways**: `php -r 'return_gateways_status(true)'` liefert sauberes JSON → Parser fertig.
- **Update-Check**: `pfSense-upgrade -c` → „Your system is up to date" (Negativ bestätigt).
- **Version**: `/etc/version` = `26.03-RELEASE`.

Der Spike-Befehl bleibt als Referenz (read-only, auf einer pfSense-Box ausführbar):

```sh
ssh -p9922 root@<box> '
echo "== python interpreter (rc.d/install.sh assume /usr/local/bin/python3) =="; ls -l /usr/local/bin/python3*
echo "== gateways: pfSsh playback =="; pfSsh.php playback gatewaystatus 2>&1 | head -40
echo "== gateways: PHP return_gateways_status =="; php -r '\''require_once("/etc/inc/gwlb.inc"); echo json_encode(return_gateways_status(true));'\'' 2>&1 | head -40
echo "== gateways: dpinger sockets =="; ls -la /var/run/dpinger_* 2>/dev/null
echo "== firmware: pfSense-upgrade check =="; /usr/local/sbin/pfSense-upgrade -c 2>&1 | head -40
echo "== firmware: version file =="; cat /etc/version /etc/version.patch 2>/dev/null
'
```

Erwartung: eine der Gateway-Methoden liefert strukturierten Status (Name/Adresse/Loss/Delay/RTT),
`pfSense-upgrade -c` einen Text/Code, aus dem „Update verfügbar" ableitbar ist. Damit werden
`_collect_gateways_pfsense()` und der pfSense-Zweig in `collect_firmware()` fertiggestellt.

## 13. Checkmk/OMD-Integration + Zustandsbewertung (geplant, nicht jetzt bauen)

**Ziel** (User, 2026-06-24): Das Dashboard wird in ein bestehendes **check_mk/OMD**-Setup
eingebunden. Checkmk fragt uns über ein **Plugin (special agent)** ab und bekommt pro Firewall
Services mit Zustand **OK/WARN/CRIT** (Memory, Interfaces, VPN/IPsec up/down, Gateways, Firmware,
…) inkl. **Perfdata** für Graphen. Dazu: green/red-Entscheidungen auf Fehler/Schwellen.

**Architektur — forward-compatible, nichts davon blockiert heute:**
- **Neutrale Export-API statt Checkmk-Format im Core**: `GET /api/instances/{id}/checks`
  (+ `/api/export/checkmk` über alle) liefert pro Instanz eine Liste Services:
  `{key, state (0|1|2|3), summary, metrics[{name,value,warn,crit,unit}]}`. Stabiles, versioniertes
  JSON. Checkmk-Spezifika bleiben draußen.
- **Checkmk special agent (Plugin) auf der Checkmk-Seite**: dünnes Python-Script, ruft unsere API,
  emittiert Checkmk-Agent-Output (Sections + **Piggyback** `<<<<hostname>>>>` pro Firewall → jede
  Firewall wird ein Checkmk-Host mit Services). Liegt im Repo unter z.B. `checkmk/`.
- **State-Evaluation-Layer im Backend (neu)**: rohe Metriken → green/red, *eine* Stelle, genutzt
  von Dashboard-UI **und** Export (keine doppelte Logik). Schwellen z.B.: Gateway loss=100% → CRIT,
  mem>90% → WARN, IPsec-Tunnel down → CRIT, Interface down → CRIT/WARN je Rolle, Firmware-Update
  verfügbar → WARN. Schwellen konfigurierbar (global + pro Instanz).
- **Perfdata**: vorhandene Metriken (cpu%, mem%, iface bytes/rates, gw delay/loss/stddev) mappen
  direkt auf Checkmk-Perfdata.

**Was heute schon passt (Antwort auf „können wir später exportieren?" → ja):** Agent + Hub liefern
die nötigen Rohdaten (mem/iface/ipsec/gw/firmware); `_last_status`-Cache + Time-Series sind die
Quelle. Kein Umbau nötig — alles additiv: State-Layer + Export-Endpoint + Plugin. Wir werfen keine
Daten weg, die der Export bräuchte.

**Mehr Checks (Agent erweitern):** Service-/Daemon-Status, CARP/HA-Status, Zertifikats-Ablauf,
DHCP-Leases, Sensoren/Temperatur, Paket-Health. Collector bleibt erweiterbar (Plattform-Dispatch
wie §4).

**Phase (nach Self-Update/Relay):**
- ✅ **(1) State-Layer + `/checks`-Endpoint umgesetzt (2026-06-24)** — `app/checks/` (pure
  OK/WARN/CRIT-Logik + Perfdata: memory/disk/cpu/gateways/ipsec/firmware), `GET
  /api/instances/{id}/checks` (Hub-Cache für push, live für direct), `tests/test_checks.py`.
  Live gegen .199 verifiziert. Schwellen sind Konstanten — per-Instance-Config offen.
- ✅ **(2) Checkmk special-agent Plugin umgesetzt (2026-06-24)** — `GET /api/export/checkmk`
  (alle Instanzen) + `checkmk/agent_styliteorbit.py` (stdlib, Piggyback pro Firewall →
  `<<<local>>>` mit State+Perfdata). `render_checkmk` pure + getestet (`just checkmk-test`),
  `checkmk/README.md`. **Live end-to-end gerendert** (beide Boxen, fand echtes CRIT: down-Tunnel).
- ✅ **Read-only API-Key (2026-06-24)** — `ApiKey`-Model + Migration `003`, `POST/GET/DELETE
  /api/apikeys`, `read_principal`-Dep (User ODER `orbit_`-Key; Keys read-only → 403 auf non-GET),
  auf `/checks` + `/export/checkmk`. Plugin nutzt `ORBIT_API_KEY` → **prod-tauglich, kein
  Admin-Passwort**. Live verifiziert. Voll-RBAC (Rollen/Multi-Tenant) bleibt Folgeschritt (§14).
- ⬜ (3) weitere Collector-Checks · Frontend zeigt die Checks (Grün/Rot je Service).

## 14. Bekannte Lücken / Backlog (ehrliche Selbstkritik, 2026-06-24)

**Tier 1 — Korrektheits-Löcher (Kernzweck):**
- ✅ **Toter Agent zeigte „online"** — behoben (Staleness-Watchdog: `agent_last_seen` älter als
  `DASH_AGENT_STALE_SECONDS`/120s → offline + Notify; Recovery beim nächsten Push;
  `is_online()`-Helper). Test live: Box-Agent stoppen → Karte rot in ~120s.
- ✅ **Rollback im Feld bewiesen (2026-06-24)** — kaputter Agent live auf .199 gepusht →
  Supervisor stellte `.bak` zurück → guter Agent reconnectet. Zwei-Ebenen-Rollback funktioniert.
- ⬜ **Backend-Restart = blind + Reconnect-Storm** — in-memory Hub; `_last_status` weg, Live-Status
  leer bis nächster Push. Status-Persistenz oder schnelles Re-Push erwägen. (Teil-entschärft:
  Dead-Peer-Fix sorgt dafür, dass Agents nach Backend-Restart binnen 60s reconnecten.)
- ✅ **`/ws/agent`-Integrationstest (2026-06-24)** — `tests/test_agent_ws.py` (in-process
  TestClient, DB/Scheduler gestubt): Token-Auth (valid/missing/invalid), hello/welcome +
  Hub-register/unregister, und Regression „failing push disconnectet nicht".

**Live-Test (2026-06-24) deckte 3 Bugs auf, die in Unit-Tests unsichtbar waren — alle gefixt:**
- `service stop/restart` kaputt mit Supervisor (rc.subr-Mismatch) → `stop_cmd`/`status_cmd`
  (`3e309c8`).
- stdlib-WS-Client merkte toten Peer nicht (kein Pong-Timeout) → Recv-Timeout, v0.3.4 (`0eaf906`).
- WS-Endpoint schluckte Exceptions still → Disconnect-Loop → loggen + Verbindung halten (`1b5a359`).
- Dev-Churn-Quelle: Vite-`5173`-Proxy droppt langlebige WS bei HMR → Agents auf `8000` direkt.

**Tier 2 — geflaggt, unterbewertet:**
- ⬜ **Update-Signatur (Offline-Key)** — v1 nur sha256+TLS; Dashboard-Compromise = RCE auf alle
  Firewalls. Größte Security-Schuld (§6).
- ⬜ **Metric-Retention/Rollup nicht gebaut** (Tabelle wächst unbegrenzt; APScheduler-Job-TODO).
- ⬜ **Multi-Tenancy/RBAC fehlt** — ein Admin-User; MSP-Scale braucht Orgs/Rollen/Scoping.
- ⬜ **Interface-Durchsatz-Raten** — Poll difft zwei Polls; Push schickt nur rohe Counter →
  Raten fehlen agentseitig (Metrik-Parität).

**Tier 3 — Lifecycle/Betrieb:**
- ⬜ Agent-Uninstall · Versions-Pinning/Downgrade · Supervisor/rc.d nicht self-updatebar (Multi-File)
  · Enrollment-Automatik (One-Time-Code) · pfSense CE unbestätigt · Hub-Observability (Agent-Count,
  Push-Rate, Fehler).

**Prozess:** Backend-Lint-Baseline rot (~127 B008 etc.) — Gate ist keins (siehe Phase 0 §9, B008-
Config-Fix steht aus). Commits nur lokal, nie gepusht.
