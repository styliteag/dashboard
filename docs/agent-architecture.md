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
1. **Agent v0.2 (OPNsense, verifiziert gut):**
   - ✅ **stdlib-WS (DR-4) umgesetzt (2026-06-23)**: `websockets`-Pip-Dep entfernt, RFC-6455-
     Client in `opnsense_agent.py` (Handshake, Client-Masking, Fragment-Reassembly, Ping/Pong,
     Close, NAT-Keepalive). Tests `agent/tests/test_ws.py` — Framing-Unit + **Interop gegen
     `websockets`-Referenzserver** (`just agent-test`). Agent jetzt dependency-frei, `__version__`
     0.2.0. **Offen: Integrationstest gegen das echte Backend-`/ws/agent` vor Produktiv-Rollout.**
   - ⬜ `run-agent.sh`-Supervisor, `agent.update` über WS, Zwei-Ebenen-Rollback, Canary-Logik
     im Backend. **Hart testen.** → der *letzte manuelle Rollout*.
2. **pfSense-Spike (§7)** — gates 3. Läuft parallel zu 0/1.
3. **pfSense-Support:**
   - ✅ **Plattform-Detection + Dispatch umgesetzt (2026-06-23)**: `detect_platform()` (Marker
     aus dem Spike), Agent meldet `platform` im `hello`, `collect_firmware`/`collect_gateways`
     dispatchen pro Plattform. pfSense-**Firmware-Version** via `/etc/version`. Geteilte
     Collectors (cpu/mem/disk/iface/ipsec/firewall_log/config) unverändert. Tests
     `agent/tests/test_collectors.py`. → Agent läuft jetzt auf pfSense für System-Metriken.
   - ⬜ **Real-Box-Format nötig** (nicht raten): pfSense **Gateway-Status** (dpinger/
     `return_gateways_status()`) und **Update-Check** (`pfSense-upgrade -c`) — Output-Format auf
     einer Box erfassen, dann Parser finalisieren. Bis dahin: Gateways `[]`, Firmware nur Version.
   - ⬜ Command-Side (`execute_command` firmware.check/update) pro Plattform dispatchen (Control,
     später).
4. **Relay (optionaler dritter Weg):** WS um `http_request`/`http_response` erweitern;
   Dashboard-Befehl `proxy.enable` (Ziel-Allowlist).
5. **API-Geräte:** Proxmox (sauberste API) als erstes relay-only `device_type`, dann
   TrueNAS, QNAP — reiner Backend-Code.
6. **Steuerungs-Hardening (wenn Control wächst):** Token-Rotation/-Expiry, Update-Signatur
   (Offline-Key), scoped Commands, `config.xml`-Schutz, Enrollment-Automatik.

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
