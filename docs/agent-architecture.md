# Agent- & Connectivity-Architektur (Design-Doc)

Status: **Entwurf zur Review** · Stand: 2026-06-23 · Betrifft: `agent/`, `backend/src/app/agent_hub/`, `backend/src/app/xsense/`

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
2. Soll-Version = `__version__` der **vom Container ausgelieferten** `agent/orbit_agent.py`
   — **kein separater Blob-Store**. Dashboard vergleicht gemeldet vs. ausgeliefert.
3. Update wird **durch den authentifizierten WS** gepusht:
   `{"type":"agent.update","version":…,"sha256":…,"code":<b64>}` (10 MB `max_size` reicht).
   **Nicht** über das offene `/agent/script` (das bleibt nur für Bootstrap-Install — anderer
   Trust-Kontext, kurz erwähnt in §6).
4. Agent: `orbit_agent.py.new` **im Zielverzeichnis** schreiben (nicht `/tmp`; `os.rename`
   ist nur dateisystem-intern atomar) → sha256 verifizieren → `.bak` anlegen → atomic swap →
   Update-Marker setzen → Restart.

> **Implementierungsstand Signatur (Stand 2026-06-24):** Der Push trägt zusätzlich eine
> Ed25519-Signatur (`orbit_agent.py.sig`, offline erzeugt). Sie ist aktuell **nicht
> erzwungen** — `_UPDATE_PUBKEY` im Agent ist leer, daher gibt `_signature_ok()` `True`
> zurück (Dev-Modus); fehlt die `.sig`, schickt das Backend eine leere Signatur. Self-Update
> läuft also **unsigniert**. Scharfschalten: `scripts/sign_agent.py --gen` → `PUB_HEX` in
> `_UPDATE_PUBKEY` einbacken, `PRIV_B64` offline halten, dann `just sign-agent`.

### 5.2 Restart & Rollback (zwei Ebenen)

Befund aus `agent/rc.d/orbit_agent`: `daemon(8)` läuft **ohne `-r`** → kein Respawn,
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
tauscht nur `orbit_agent.py` — der Wrapper + rc.d, also genau die Komponente, die Updates
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
     Client in `orbit_agent.py` (Handshake, Client-Masking, Fragment-Reassembly, Ping/Pong,
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
- **DR-7** Relay = transparenter HTTP-Tunnel; Agent injiziert lokal-provisionierte Creds, Dashboard bleibt keyless (§15).

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
- ✅ **Update-Signatur (Offline-Key) (2026-06-24)** — Ed25519, offline signiert, Dashboard
  relayt nur Code+Signatur (hat den Private Key nie → kann nichts fälschen). Agent verifiziert
  mit eingebackenem `_UPDATE_PUBKEY` per **pure-stdlib-Ed25519** (DR-4 bleibt). Default leer →
  Enforcement aus (dev); Prod-Release backt Pubkey + signiert (`scripts/sign_agent.py`,
  `just sign-agent`). Pure-Verify gegen `cryptography` kreuzvalidiert, Roundtrip live geprüft.
  Offen: Key-Rotation-Flow (Henne-Ei über die Flotte) + Bootstrap-Doku.
- ✅ **Metric-Retention/Rollup (2026-06-24)** — `app/maintenance/jobs.py`: 5-Min-Rollup +
  Retention (30d raw / 365d 5m), im Scheduler. Rollup-SQL live gegen MariaDB validiert.
- ✅ **Interface-Durchsatz-Raten (2026-06-24)** — `to_rate()` (Counter→bytes/s) + `?rate=true`;
  Frontend `InterfacesSection` mit live RX/TX. Push/Poll-Parität.
- ⬜ **Multi-Tenancy/RBAC fehlt** — ein Admin-User; MSP-Scale braucht Orgs/Rollen/Scoping.
- ⬜ **Interface-Durchsatz-Raten** — Poll difft zwei Polls; Push schickt nur rohe Counter →
  Raten fehlen agentseitig (Metrik-Parität).

**Tier 3 — Lifecycle/Betrieb:**
- ⬜ Agent-Uninstall · Versions-Pinning/Downgrade · Supervisor/rc.d nicht self-updatebar (Multi-File)
  · Enrollment-Automatik (One-Time-Code) · pfSense CE unbestätigt · Hub-Observability (Agent-Count,
  Push-Rate, Fehler).

**Prozess:** Backend-Lint-Baseline rot (~127 B008 etc.) — Gate ist keins (siehe Phase 0 §9, B008-
Config-Fix steht aus). Commits nur lokal, nie gepusht.

## 15. Relay — lokaler API-Tunnel (✅ Phase 1, 2026-06-24)

**Ziel (Userwunsch):** „die API der OPNsense direkt erreichen … evtl. sogar ohne extra Key,
weil die Request von localhost kommt." Das Dashboard sitzt auf öffentlicher IP, die Firewall
oft hinter NAT — ihre REST-API ist von außen nicht erreichbar. Der Relay tunnelt eine HTTP-
Request über die **bestehende Agent-WebSocket** an die *eigene* API der Box.

**Live-Befunde (.199, OPNsense 26.1.10):**
- GUI/API lauscht auf **Port 4444** (custom, nicht 443) — `<webgui><port>4444</port>`; auf
  `127.0.0.1` erreichbar (lighttpd `*:4444`). Mein 443-Test war deshalb „Connection refused".
- **Kein localhost-Auth-Bypass:** die API verlangt auch von localhost Basic-Auth (key:secret).
  Die localhost-Intuition stimmt trotzdem — realisiert über den *Agenten auf localhost*, nicht
  über einen API-Bypass.
- OPNsense speichert das API-**Secret als bcrypt** (`password_verify`), und bringt mit
  `API.php::createKey()` → `$user->apikeys->add()` **seinen eigenen Key-Generator** mit. Wir
  hashen nie selbst — OPNsense erzeugt key+secret und gibt das Klartext-Paar einmalig zurück.

**Mechanik (kein neuer Korrelations-Mechanismus nötig):** wiederverwendet die vorhandene
`send_command`/`resolve_command`-Future-Korrelation (request_id + Timeout).
- Backend: `@router.api_route("/instances/{id}/relay/{path:path}")` (GET/POST/PUT/DELETE/PATCH),
  **`current_user`-Pflicht** (Admin-Session). Base64-tunnelt method/path/headers/body → Agent →
  Response. Dashboard-eigene Header (cookie/authorization/host) werden **nicht** weitergereicht.
  `status 0` vom Agenten = Transport-/Credential-Fehler → **502**, echte API-Status (403/200…)
  werden 1:1 durchgereicht.
- Agent: `http.relay`-Action → `_relay_http()` injiziert `Authorization: Basic` lokal, forwardet
  an `opnsense_api_url` (default `https://127.0.0.1:4444`, self-signed → unverified ctx).

**Keyless aus Admin-Sicht (Auto-Provisioning):** fehlen Credentials, mintet der Agent (läuft als
root) per OPNsense-eigenem PHP (`legacy_bindings.inc`) einen dedizierten User **`orbit`**
(scope `automation`, `page-all`) + API-Key, cached das Paar (`…agent.apikey`, mode 600) und
injiziert es. **Das Dashboard hält null Firewall-Credentials.** Credential-Präzedenz:
config-pasted (`opnsense_api_key/secret`) > Cache > Auto-Provision (`relay_provision`, nur OPNsense).
Live bewiesen: provisionierter Key → `GET /api/core/firmware/status` → **HTTP 200** + JSON.

→ **DR-7: Relay = transparenter HTTP-Tunnel; der Agent injiziert lokal-provisionierte Creds;
das Dashboard bleibt keyless.** Variante „inject the Bearer" (A), nicht „Key ans Dashboard
geben" (B) — letzteres legte Firewall-Admin-Creds ins Dashboard.

**Sicherheits-Tradeoff (geflaggt, bewusst):** ein Voll-API-Tunnel heißt: ein kompromittiertes
**Dashboard** bekommt Voll-Admin-API auf *jeder* NAT'd Firewall. `page-all` ist für dev gewählt.
Der Agent läuft eh als root → der Key ist *keine* Eskalation der Agent-Macht; die Vertrauens-
grenze ist das Dashboard (Relay-Route braucht Admin-Session). **Prod-Hebel:** Path-Whitelist im
Relay + `orbit`-Privilegien auf das real Genutzte scopen. Tests: `agent/tests/test_relay.py`
(15) + `backend/tests/test_relay.py` (7).

**✅ End-to-end live verifiziert (2026-06-24):** Agent-0.4.0 via Self-Update auf .199 deployt,
dann `GET /api/instances/3/relay/api/core/firmware/status` durchs **laufende Dashboard** (Admin-
Session) → **HTTP 200** + Firmware-JSON, ~0,1 s warm. Der Agent provisionierte den Key beim
ersten (kalten) Call **selbst** (Cache-Datei mode 600 angelegt) — kein Timeout, die vermutete
First-Call-Provisioning-Latenz schlug nicht durch. Damit ist die zuvor nur-gemockte WS-Wire-Naht
(Route→`send_command`→Frame→Dispatch→`command_result`→`resolve_command`→Response) real durchlaufen.

**Offen:** pfSense-Relay (anderes API-Modell, kein `apikeys->add()`) · Least-Privilege-Scoping +
Path-Whitelist · Cache-Verlust mintet einen weiteren Key (Orphan-Keys; später aufräumen) ·
Provisioning bei Agent-Start statt First-Call (falls die Latenz auf langsamen Boxen doch stört).

## 16. Plan-Update / Entscheidungen (2026-06-24, nach Relay-§15)

Userentscheid zu den §15-Offenen + Backlog. Recon bestätigt: keine Status-Snapshot-Tabelle,
kein Enrollment, kein Uninstall vorhanden; Agent-Actions = ipsec/firmware/config/reboot/
http.relay/ping/agent.update; pfSense .200 hat **keine** REST-API, aber `php`+`pfSsh.php`.

**Bewusst NICHT (bleibt so):**
- **Path-Whitelist** — verworfen, Relay bleibt voll-transparent (dev).
- **Least-Privilege / `page-all`** — bleibt admin-äquivalent.
- **RBAC/Multi-Tenancy** — nicht gebraucht.

**Entscheidung, aber jetzt nur dokumentiert (nicht bauen):**
- **#3 pfSense-Relay → Option α:** kein HTTP-Relay auf pfSense. Spezialaufgaben (#6: ipsec/
  user anlegen) laufen als **strukturierte Agent-Command-Actions**, lokal via `php`/`pfSsh.php`
  (keyless, kein Zusatzpaket). Option β (Community-`pfSense-pkg-API` installieren) verworfen als
  zu invasiv auf Kundenboxen. OPNsense-Spezialaufgaben gehen **heute schon** durch den Voll-API-
  Relay (POST) — kein Extra-Framework nötig. Bauen erst wenn #6 konkret wird.

**Zu bauen — als unabhängig auslieferbare Chunks:**

- **Chunk A — Relay-Härtung (OPNsense, klein, auf .199 testbar):**
  - **Port-Discovery** (`TODO.md`): Agent liest `<webgui><port>` aus `/conf/config.xml` statt
    hartkodiertem 4444; Fallback `<protocol>`→443. Ersetzt das fixe `local_api_url`-Default.
  - **#4+#5 als EIN idempotentes `ensure_credentials` beim Agent-Start** (nicht zwei Patches):
    gültiger Cache → reuse (kein Config-Write); fehlt/ungültig → provisionieren **und dabei alte
    `orbit`-Keys vor dem Add löschen** (verhindert Orphan-Keys bei Cache-Verlust + nimmt die
    First-Call-Latenz raus). Versionsbump.

- **Chunk B — Backend-Restart-Persistenz (DB, nicht File):** keine Snapshot-Tabelle existiert →
  pro Instance ein JSON-Snapshot (Spalte auf `instances` oder 1:1-Tabelle) der Hub-Caches
  (status/gateways/ipsec/firmware/firewall_log), Upsert in `handle_metrics`, Cold-Load in den Hub
  beim Start. Alembic-Migration nötig. Begründung File→DB: async SQLAlchemy + MariaDB-JSON da
  (`tags`), Push schreibt eh Metriken; numerische Metrik-Tabellen halten diese Strukturen nicht.

- **Chunk C — Lifecycle:** C1 **Agent-Uninstall** (Action `agent.uninstall` + Backend-Route, ggf.
  über `bulk/action`); C2 **Enrollment-Automatik** (One-Time-Code → Agent-Token, statt Token
  manuell pasten). Version-Pinning/Downgrade + Hub-Observability als kleinere Folgeschritte.

**Reihenfolge:** A → B → C (A zuerst: klein, OPNsense-only, sofort auf .199 verifizierbar).
**Erledigt:** Lint 142→0 (`9a4c018`, vom User). · Relay §15 e2e live.

### §16 Status — A/B/C erledigt + live verifiziert (2026-06-24)

- **✅ Chunk A (Relay-Härtung, Agent v0.6.0):** Port-Discovery (`<system><webgui><port>`,
  Fallback protocol→443/80; pinned `local_api_url` schlägt Discovery aus) + idempotentes
  Startup-Provisioning. Live auf .199: Orphan-Keys 2→1 (clear-before-add), Key beim Start
  gemintet (kein First-Call-Timeout), Cache mode 600, Relay 200.
- **✅ Chunk B (Restart-Persistenz):** `instances.status_snapshot` (JSON, Migration 004); Hub
  serialisiert Caches pro Push, `hydrate_from_db()` im Lifespan. Live: Backend-Restart →
  `hub.hydrated instances=3`, `GET /instances/3/status` sofort 200 mit Daten.
- **✅ Chunk C (Lifecycle, Agent v0.7.3):**
  - **Uninstall:** Backend `POST /instances/{id}/agent/uninstall` → Agent ackt, detached Script
    killt Baum (daemon→supervisor→agent) + entfernt rc.d/files/config/cache + `orbit`-User;
    Backend revoked Token + transport=direct. **Wichtiger Live-Fund (via `sh -x` auf .199):** ein
    *laufender Descendant* kann seine Ancestors auf FreeBSD nicht zuverlässig SIGKILLen (Kill
    no-opt still) — derselbe Loop aus einer ssh-Shell (außerhalb des Baums) killt sofort. Fix:
    Agent `os._exit(0)` direkt nach dem Ack → Script reparentet zu init → killt von außen
    (Supervisor respawnt 1×, Retry-Loop reapt). Verifiziert: procs 0, daemon 0, alles entfernt.
  - **Enrollment:** `enrollment_codes` (Migration 005, SHA-256, single-use, 1h, IP-rate-limited).
    Admin `POST /instances/{id}/agent/enroll-code`; öffentlich `POST /agent/enroll`. Agent tauscht
    `enroll_code`→Token beim Start und **persistiert ihn in die Config** (Code verworfen) — der
    Single-Use-Code darf einen Restart nicht erneut ausgeben. Live: .199 nur mit Code gebootet →
    enrollt → Token persistiert → orbit re-provisioniert → connected.
  - **Bewusst zurückgestellt:** Version-Pinning/Downgrade, Hub-Observability.

**Nicht gebaut (Entscheid):** Path-Whitelist, Least-Privilege (`page-all` bleibt), RBAC,
pfSense-Relay (→ später als lokale Command-Actions, §16 #3). Tests gesamt: Agent 101, Backend 78.

## 17. pfSense-Relay — via Community-REST-API-Paket (✅ 2026-06-24, Option β)

pfSense CE hat **keine native REST-API** (anders als OPNsense, kein `apikeys->add()`).
Userentscheid: das Community-Paket **pfRest** installieren statt lokaler Command-Actions.

**Make-or-Break (zuerst geprüft, Advisor):** Kann root *ohne* Admin-Passwort provisionieren?
**Ja** — pfRest-Default-Auth ist `BasicAuth` (gegen die pfSense-Local-User-DB, `RESTAPISettings.inc:182`),
also legt der Agent (root) einen eigenen pfSense-User `orbit` (page-all, selbstgesetztes bcrypt-
Passwort) an und nutzt Basic-Auth `orbit:pw`. Das `(key, secret)`-Paar = `(username, password)` —
**dieselbe Basic-Injektion wie OPNsense**, nur das Credential unterscheidet sich.

**Bewusst anders als OPNsense (Advisor):** der Paket-Install ist **explizit dashboard-getriggert**
(`relay.enable`), **nicht** auf dem Startup-Pfad — ein Boot-Zeit-Download aus dem Internet ist das
falsche Default (Egress + Angriffsfläche). OPNsense-Startup-Provisioning bleibt (nativ, kein Egress).

**Mechanik:**
- Agent-Action `relay.enable` (Backend `POST /instances/{id}/relay/enable`, Admin): pfSense →
  pfRest installieren (`pkg-static add` vom version-abgeleiteten Asset `pfrest/pfSense-pkg-RESTAPI`,
  `latest`) DANN provisionieren; OPNsense → nur provisionieren. Idempotent.
- `_provision_api_credentials` ist platform-aware; pfSense provisioniert nur wenn pfRest schon
  installiert ist (sonst None — Install gehört zu relay.enable, nie als Seiteneffekt).
- Relay-Pfade: OPNsense `/api/core/...`, pfSense `/api/v2/...` (transparent durchgereicht).
- **Uninstall** entfernt auf pfSense zusätzlich orbit-User (`local_user_del`) + pfRest-Paket
  (`pkg-static delete`), sonst bliebe eine erreichbare REST-API zurück.

**Gotcha:** `local_user_set_password(&$cfg, $pw)` erwartet `['item'=>$user]` und no-opt sonst still →
bcrypt direkt via `password_hash($pw, PASSWORD_BCRYPT)` setzen.

**Live auf .200 (pfSense CE 2.8.1):** Clean-Slate → `relay.enable` durchs Dashboard installierte
pfRest + provisionierte orbit (page-all, Cache mode 600) → `GET /instances/4/relay/api/v2/system/version`
→ **HTTP 200**, ~0,1s. Teardown-Befehle (User+Paket) separat bestätigt. Tests: Agent 109, Backend 80.

**Integrierter Uninstall live bestätigt (.200):** Uninstall durchs Dashboard → procs 0, pfRest-CLI
weg, orbit-User weg; danach Enrollment + `relay.enable` → wiederhergestellt, Relay 200.

**✅ Relay-Write-Pfad live verifiziert (2026-06-24, beide Plattformen, reversibel):**
- OPNsense .199: `POST …/relay/api/firewall/alias/addItem` → `saved`+uuid, `delItem/{uuid}` →
  `deleted`, `reconfigure` → ok, `searchItem` → 0 rows (sauber).
- pfSense .200: `POST …/relay/api/v2/firewall/alias` → 200 (id=0), **`DELETE …?id=0`** → 200
  (testet den DELETE-Verb), Liste danach ohne den Test-Alias.
- Beide Verben + JSON-Body + Response forwarden korrekt; kein Code-Fix nötig. Regression:
  `test_write_verbs_pass_through` (PUT/DELETE/PATCH-Passthrough).

**Caveat (offen):** `relay.enable` hat 200s Timeout; ein langsamer GitHub-Install/Schema-Gen kann den
`send_command`-Timeout reißen und „failed" melden, obwohl der Install fertig läuft — idempotenter
Retry rettet es, aber „looks-failed-but-worked"-Wart.

## 18. GUI-Proxy — roher TCP-Tunnel über die Agent-WS (✅ Feasibility 2026-06-24)

Die Firewall-Web-GUI lässt sich **nicht** per Pfad-Präfix proxen: Browser lösen `/css/…`,
`/firewall_rules.php` und jeden XHR gegen den **Origin-Root** auf → unter `/instances/3/gui/`
landen die beim Dashboard, nicht beim Proxy. Transparentes GUI-Proxying braucht einen eigenen
Origin pro Firewall. Userentscheid: **TCP-Tunnel via Agent** (statt Wildcard-Subdomain oder
brüchigem HTML-Rewriting) — nah an `TODO.md` „agent-proxy".

**Mechanik:** ein lokaler Forwarder (`scripts/orbit-gui-tunnel.py`) lauscht auf `localhost:8443`;
pro Browser-Verbindung öffnet er eine WS zum Dashboard (`/api/ws/tunnel/{id}`, Admin-Session) und
pipet rohe TCP-Bytes. Das Dashboard bridged auf die **Agent-WS**; der Agent öffnet TCP zu seiner
GUI (`127.0.0.1:4444`) und pipet zurück. **Der Browser spricht TLS end-to-end mit der Firewall**
(Self-Signed-Cert) — kein HTML-Rewriting, AJAX/Forms/Live/HTTP-2 funktionieren transparent.
Streams sind per `stream`-id über die eine Agent-WS gemultiplext (Bytes als base64 in JSON
`tunnel`-Frames, da der stdlib-WS-Client text-only ist).

- Agent: `_TunnelManager` (open→`asyncio.open_connection`, pump TCP→WS, data WS→TCP, close);
  Dispatch in `_listen_loop`, Cleanup bei Disconnect. v0.9.0.
- Backend: `hub.open/deliver/close_tunnel` (stream→Queue); `tunnel`-Dispatch im `agent_websocket`;
  WS-Endpoint `/ws/tunnel/{id}` (Admin-Session-Auth) bridged Client↔Agent.

**✅ Live verifiziert (.199, OPNsense):** `curl -k https://localhost:8443/` → GUI-HTML durch den
Tunnel; **3 parallele Streams** je 200 (~0,067s, Multiplexing); Firewall sprach **HTTP/2 via ALPN**
end-to-end (Tunnel voll transparent). Tests: Agent `_TunnelManager` (5), Backend Registry (3).

**Offen (Phase 2):** Frontend-„Open GUI"-Button (zeigt/startet den Tunnel-Befehl) · der Forwarder
braucht aktuell `pip install websockets` (oder ein stdlib-WS-Client wie im Agent) · Prod: WS-Auth
über Session hinaus (kurzlebiges Tunnel-Token), Tunnel-Audit, Egress-/Port-Policy · Backpressure
bei großen Downloads · pfSense identisch (Agent öffnet seinen GUI-Port — nicht separat getestet,
gleicher Pfad).

### §18 GUI-Proxy — HTTP-Reverse-Proxy per Port/Subdomain (✅ dev-verifiziert 2026-06-24)

Userentscheid (nach „kein lokales pip/python, im Container an eine URL binden, dev mit Ports,
prod hinter Wildcard"): **HTTP-Reverse-Proxy, Per-Origin**. Der lokale CLI-Forwarder wandert in
den **Backend-Container**; ein Reverse-Proxy (**Caddy**) terminiert TLS und liefert den
Per-Instanz-Origin.

- **In-Container-Forwarder** (`app/agent_hub/gui_tunnel.py`): bindet pro Instanz einen Port
  (`DASH_GUI_TUNNELS="3:14444"`), bridged jede TCP-Verbindung in-process über den Hub zum Agent
  → firewall:4444 (reuse §18-Tunnel, Agent unverändert). Kein lokales Tool nötig.
- **Caddy** (`docker/Caddyfile.dev`, neuer Service in `compose-dev.yml`): `localhost:9003`
  (tls internal) → `reverse_proxy https://backend:14444` (`tls_insecure_skip_verify`). Caddy macht
  Cookies/Redirects/WS/Keep-Alive nativ. **Prod:** Wildcard-Subdomain statt Port
  (`docker/Caddyfile.prod.example`) — gleicher `reverse_proxy`-Block.

**Warum Per-Origin (Port ODER Subdomain) das Absolute-URL-Problem löst:** der Browser-Origin ist
`localhost:9003` (bzw. `gui-3.example.com`); absolute Pfade wie `/ui/.../main.css` lösen gegen
diesen Origin auf → treffen Caddy → werden durchproxyt. Ein Port ist ein eigener Origin, **ein
Cert für den Basis-Host deckt alle Ports** → kein Wildcard-DNS in dev nötig.

**✅ Live in `just dev` (Browser-Origin → Caddy → Forwarder → Agent → .199):**
`https://localhost:9003/` → OPNsense-GUI; **absoluter** CSS-Pfad → 200 text/css (160 KB); JS → 200;
`Set-Cookie: PHPSESSID=…; secure; HttpOnly` ohne Domain → host-only → auf den Origin gescoped →
Login/Session tragen. 3 parallele Streams ~0,03 s. Tests: `parse_tunnel_spec` + Hub-Registry.

**Offen (Phase 2):** Auth-Gate am Caddy-Origin (Forward-Auth zur Dashboard-Session — **wichtig**,
sonst hängt die Firewall-Admin-GUI offen; aktuell nur durch den Firewall-eigenen Login geschützt)
· dynamische Per-Instanz-Port/Subdomain-Allokation (statt statischem `DASH_GUI_TUNNELS`) ·
Frontend-„Open GUI"-Button · prod-Caddyfile produktiv machen (DNS-01-Wildcard). Der lokale
`scripts/orbit-gui-tunnel.py` bleibt als Alternative ohne Port-Exposure.

### §18 GUI-Proxy — Auth-Gate + dynamische Allokation + Frontend (✅ 2026-06-24)

Phase 2 (Userwunsch 1+2+3), Advisor-Sequenz befolgt (Gate zuerst, dann dynamisch, dann Button).

**1. Auth-Gate (Token-Handoff + Caddy `forward_auth`):** der GUI-Origin ist cross-origin zum
Dashboard, also gatet ihn nicht die Dashboard-Session. `POST /instances/{id}/gui/open` (Admin)
mintet einen kurzlebigen HMAC-Handoff-Token; der Browser ruft `/__orbit/auth`, Caddy routet das
ans Backend (`/api/gui/handoff`), das gegen einen **origin-scoped `orbit_gui`-Cookie** tauscht
(302); `forward_auth` prüft den Cookie bei jedem Request (`/api/gui/authcheck`, **zero-I/O HMAC**,
an *diese* Instanz gebunden). `gui_auth.py`: sign/verify, exp + instance im Token.

**2. Dynamische, stabile Allokation:** `GuiTunnelManager` startet pro Instanz on-demand einen
Forwarder auf **stabilem** Port `14400+id` (nie für eine andere Instanz wiederverwendet — der
Cross-Tenant-Footgun an der Wurzel vermieden, statt Recycling-Pool). `/gui/open` ruft `ensure()`.
Caddy dev: Vhosts 9001–9010 (Snippet `gui_vhost {args}` → `forward_auth instance=id` +
`reverse_proxy backend:1440id`). Prod: ein Wildcard-Vhost (`Caddyfile.prod.example`),
`DASH_GUI_BASE_TEMPLATE=https://gui-{id}.…`.

**3. Frontend:** „Open GUI"-Karte in `AgentSection` → `POST /gui/open` → öffnet die Handoff-URL im
neuen Tab.

**✅ Live (`just dev`, beide Plattformen):**
- **Negativtest** (Advisor-Beweis): `https://localhost:9003/` ohne Cookie → **401** (Seite + Asset);
  `dash_session`-Bleed maskiert nichts (curl ohne Cookies → 401).
- **Positiv:** Handoff → `orbit_gui`-Cookie → 200.
- **Cross-Tenant:** Cookie-für-Instanz-3 gegen `authcheck?instance=7` → **401**; manipuliert → 401.
- **Dynamisch + pfSense:** `/gui/open` instance 4 → Forwarder 14404 on-demand → `:9004` → pfSense-GUI
  200 (CsrfMagic), vorher nirgends vorkonfiguriert.
- User bestätigte: Login in die OPNsense-GUI über `:9003` im echten Browser.

**Offen:** Forward-Auth in Prod scharfschalten (das Gate ist da, aber Prod-Caddyfile + DNS-01-Wildcard
müssen ausgerollt werden) · Single-Use-Handoff-Token (aktuell 60s-TTL) · Forwarder-Teardown bei Idle ·
echte On-Demand-Caddy-Routen statt Vhost-Range/map (Caddy-Admin-API). Tests: gui_auth (8), port_for,
Hub-Registry; Backend 94, Frontend grün.

**Idle-Teardown (2026-06-24):** `GuiTunnelManager` zählt aktive Verbindungen pro Forwarder; ein
Reaper (60s-Tick) schließt einen Forwarder nach `DASH_GUI_IDLE_MINUTES` ohne aktive Verbindung
(default 15, 0 = aus) — der nächste „Open GUI" startet ihn neu. Per-Verbindung räumt der Bridge
ohnehin beim Tab-Schließen auf. Live: bei idle=1min war die GUI nach ~75s reaped (502). compose
muss `DASH_GUI_IDLE_MINUTES` durchreichen (sonst Container-Default).

**Opt-in + Prod (2026-06-24):** GUI-Proxy ist **default aus** (`DASH_GUI_PROXY_ENABLED=false`) —
Nutzer ohne Reverse-Proxy/Wildcard lassen es weg (Frontend-Button via `gui_proxy_enabled` im
Agent-Status ausgeblendet, `/gui/open` → 404). Dev: an (compose-dev, Caddy/Ports). Prod hinter
**Traefik**: `app` ins Traefik-Netz, Wildcard-Cert `*.gui.<domain>` (DNS-01),
`docker/traefik-gui.example.yml` (Router pro Firewall → `app:14400+id`, geteilte `forwardAuth`-
Gate, `insecureSkipVerify`), `DASH_GUI_BASE_TEMPLATE=https://gui-{id}.<domain>`. `authcheck` ist
Host-aware (Instanz aus `?instance` ODER `X-Forwarded-Host` gui-<id>). README-Sektion „Firewall GUI
proxy". Tests: Host-aware authcheck, gui_open-disabled→404. Backend 97.
