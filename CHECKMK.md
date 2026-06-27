# Checkmk integration

Monitor every firewall the dashboard knows about as a **Checkmk host** — without
installing a Checkmk agent on the firewall. The dashboard is the single source:
Checkmk pulls evaluated service checks from it and turns each firewall into a
piggyback host with services (memory, CPU, disks, gateways, IPsec service +
tunnels, IPsec ping monitors, firmware).

This is the operator guide. For the design rationale see
[`docs/agent-architecture.md` §13](docs/agent-architecture.md); the plugin's own
short note lives in [`checkmk/README.md`](checkmk/README.md).

---

## How it works

Pull model. Nothing runs on the firewall for Checkmk. The dashboard already
knows each firewall (via its push agent or direct polling); Checkmk reaches out
to the dashboard.

```
Checkmk site                              Dashboard
┌───────────────────────────┐             ┌────────────────────────────┐
│ special agent             │  GET +      │ GET /api/export/checkmk    │
│ agent_styliteorbit  ──────┼─ Bearer ───▶│   → loop all instances     │
│                           │             │   → evaluate_checks()      │
│ render_checkmk()  ◀───────┼─ JSON ──────┤   {version, instances:[…]} │
│   → piggyback output      │             └────────────────────────────┘
└─────────┬─────────────────┘
          ▼
  one piggyback host per firewall, each with a <<<local>>> section
```

1. `GET /api/export/checkmk` walks every (non-deleted) instance. Per box it
   gathers four aspects — system status, gateways, IPsec, firmware — from the
   agent-hub cache (push instances, cheap) or by polling live (direct
   instances). `evaluate_checks()` turns those into OK/WARN/CRIT service checks
   with perfdata. Response: `{"version":1,"instances":[{instance_id, name, host,
   device_type, checks:[…]}]}` (`host` = the instance name = the piggyback host
   name).
2. The special agent `checkmk/agent_styliteorbit.py` fetches that JSON and
   `render_checkmk()` emits Checkmk agent output: **one piggyback host per
   firewall** (`<<<<hostname>>>>`), each with a `<<<local>>>` section, one local
   check line per service.

---

## What gets exposed

One `<<<local>>>` service per row below, per firewall host. Source of truth:
`backend/src/app/checks/evaluate.py`.

| Service key | When | State logic | Perfdata |
|---|---|---|---|
| `memory` | always | OK <80, WARN ≥80, CRIT ≥90 (% used) | `mem_used_pct;80;90` |
| `cpu` | always | OK, WARN ≥95 — **never CRIT** (CPU is spiky) | `cpu_used_pct;95` |
| `disk:<mount\|device>` | per disk | OK <80, WARN ≥80, CRIT ≥90 | `disk_used_pct;80;90` |
| `gateway:<name>` | per gateway (if present) | CRIT on `down`/`force_down`/`offline` **or** loss ≥80; WARN loss ≥20; else OK | `gw_loss_pct;20;80` (when loss is parseable) |
| `ipsec.service` | if IPsec present | OK running / CRIT not running | — |
| `ipsec.tunnel:<desc\|id>` | per tunnel | OK up / CRIT down (Phase-1 status) | — |
| `ipsec.tunnel_ping:<label>/<selector>` | per Phase-2 child **with a ping monitor** | OK `ping ok` / **CRIT `ping FAILED`** / WARN `ping error` | `ping_loss_pct`, `ping_rtt_ms` |
| `firmware` | if firmware + `product_version` known | WARN update available / OK up to date | — |

### IPsec ping checks — the conditions

The ping monitors **are** exported, but only show up when:

- **A ping monitor is configured** for that Phase-2 child. Children without one
  (`ping_state = "none"`) are skipped — no service. So only tunnels where you
  hit *Add ping* in the UI produce `ipsec.tunnel_ping:*` services.
- **The instance runs in agent mode.** Pings execute on the firewall through the
  agent. Direct-poll instances (Securepoint, direct OPNsense) have no ping
  monitors → no ping services.

Semantics that matter: a configured ping that gets **no reply is CRIT even when
the child SA is INSTALLED** — that is the whole point (tunnel up but not passing
traffic). A misconfigured probe (bad source / no route) is **WARN**, not CRIT,
so it is not mistaken for a real outage.

> Because these services appear/disappear as you add/remove monitors, **re-run
> service discovery** on the affected host after changing ping monitors.

### What is NOT exposed

Only evaluated check states, numeric perfdata and a summary string. **No
secrets** — no API key/secret, no IPsec PSK, no raw config. It is the same
`evaluate_checks()` logic that drives the dashboard's green/red UI layer.

---

## Prerequisites

- A reachable dashboard URL (the Checkmk site must be able to HTTP(S) to it).
- A Checkmk site (`~` = the site user's home, e.g. `/omd/sites/<site>`).
- Admin access to the dashboard to mint an API key.

---

## Setup

### 1. Mint a read-only API key

There is no UI for keys yet — create one via the API with an admin session/token:

```sh
curl -X POST https://dashboard.example.com/api/apikeys \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"checkmk"}'
# → {"id":1,"name":"checkmk","prefix":"orbit_xxxx","key":"orbit_………"}
```

The full `key` (prefix `orbit_`) is **shown once** — store it now. It is stored
hashed, accepted only as a `Bearer` token, **rejected on any non-GET request**,
and revocable later:

```sh
curl https://dashboard.example.com/api/apikeys \
  -H "Authorization: Bearer <admin-token>"                 # list (id, name, prefix)
curl -X DELETE https://dashboard.example.com/api/apikeys/1 \
  -H "Authorization: Bearer <admin-token>"                 # revoke
```

### 2. Install the special agent on the Checkmk site

```sh
cp checkmk/agent_styliteorbit.py \
   ~/local/share/check_mk/agents/special/agent_styliteorbit
chmod +x ~/local/share/check_mk/agents/special/agent_styliteorbit
```

### 3. Test from the CLI first

```sh
ORBIT_URL=https://dashboard.example.com ORBIT_API_KEY=orbit_……… \
  ~/local/share/check_mk/agents/special/agent_styliteorbit
```

You should see one `<<<<hostname>>>>` … `<<<<>>>>` block per firewall:

```
<<<<opnsense-fw01>>>>
<<<local>>>
0 memory mem_used_pct=19;80;90 Memory 19% used (ok)
0 cpu cpu_used_pct=4;95; CPU 4%
0 ipsec.service - IPsec service running
0 ipsec.tunnel:to-branch - Tunnel to-branch up (ESTABLISHED)
2 ipsec.tunnel_ping:to-branch/10.0.5.0/24 - Tunnel to-branch P2 10.0.5.0/24 ping FAILED (no reply)
2 gateway:WAN - Gateway WAN down
1 firmware - Update available: 24.1 → 24.7
<<<<>>>>
```

Local check line format: `<state> <service> <perfdata|-> <summary>` (state
`0=OK 1=WARN 2=CRIT 3=UNKNOWN`).

### 4. Wire it as a datasource program

The special agent reads its config from **environment variables**, not from
`$HOSTADDRESS$`, and it emits piggyback data for *all* firewalls at once. The
simplest robust wiring is a tiny wrapper that exports the env and execs the
agent:

```sh
cat > ~/local/share/check_mk/agents/special/agent_styliteorbit_run <<'EOF'
#!/bin/sh
export ORBIT_URL=https://dashboard.example.com
export ORBIT_API_KEY=orbit_………
exec ~/local/share/check_mk/agents/special/agent_styliteorbit
EOF
chmod +x ~/local/share/check_mk/agents/special/agent_styliteorbit_run
```

In WATO, create **one "source" host** (e.g. `orbit-export`, IP can be
`127.0.0.1`) and give it:

> **Setup → Hosts → Datasource programs → "Individual program call instead of
> agent access"** → command = the wrapper above.

That source host carries no services of its own — its agent output is entirely
piggyback for the firewall hosts.

### 5. Create the firewall (piggyback) hosts

Checkmk distributes the piggyback blocks to hosts whose name matches the block
name. The block name is the **instance name**, sanitized to `[A-Za-z0-9.-_]`
(any other character → `_`; see `_host()` in the special agent).

- Add one Checkmk host per firewall, **host name = that sanitized instance
  name** (e.g. dashboard instance `opnsense-fw01` → Checkmk host `opnsense-fw01`).
- These hosts need no agent of their own; they only consume piggyback.

> Name mismatch is the #1 reason services don't appear. Keep instance names
> clean, or mirror the sanitized form exactly.

### 6. Service discovery

Run discovery on each firewall host (or bulk discovery), accept the services,
and activate changes. The `memory` / `cpu` / `disk:*` / `gateway:*` /
`ipsec.*` / `firmware` checks appear as **Local checks**.

---

## Authentication & security

- **Read-only API key** (`orbit_…`), passed as `Authorization: Bearer …`. Stored
  hashed; accepted only on `GET`/`HEAD`/`OPTIONS`; `403` on anything else; `401`
  if unknown/revoked. Revoke any time via `DELETE /api/apikeys/{id}`. This keeps
  the admin password out of WATO.
- **Dev-only fallback:** `ORBIT_USER` / `ORBIT_PASSWORD` log in via
  `/api/auth/login`. This only works when the dashboard runs `DASH_ENV=dev`
  (dev bearer token) — **do not** rely on it in production; use an API key.
- Prefer **HTTPS** for `ORBIT_URL` so the key isn't sent in clear text. The agent
  uses the system trust store for `https://` URLs.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Source host works, firewall host has no services | Piggyback host-name mismatch — Checkmk host name must equal the sanitized instance name. Check `~/tmp/check_mk/piggyback/` for the emitted host names. |
| `401 invalid API key` | Wrong/typo'd or revoked key. Re-mint. |
| `403 API key is read-only` | Something issued a non-GET with the key. The export is GET-only; check the wiring. |
| Empty output from the CLI test | `ORBIT_URL` wrong/unreachable, or no instances exist. |
| Login fails with user/password | Only works on `DASH_ENV=dev`. Use an API key in prod. |
| Export is slow / times out | Direct-poll instances are polled **live** on export (the agent's HTTP timeout is 30s). Many direct instances = slow; caching direct status is a follow-up. Push instances are served cheaply from cache. |
| Expected ping service missing | The Phase-2 child has no ping monitor, or the instance is direct-poll (ping is agent-only). Add a monitor, then re-discover. |

---

## Limits & follow-ups

- **Thresholds are hardcoded** (memory/disk 80/90, CPU 95, gateway loss 20/80 —
  `evaluate.py:16-20`). Per-instance/global config is a follow-up.
- **Direct-poll instances** are polled live per export (no cache yet).
- **Full per-role RBAC** for keys is still open (`docs/agent-architecture.md`
  §14). Today the only restriction is read-only.

---

## Reference

- Special agent: `checkmk/agent_styliteorbit.py` (stdlib only) ·
  short note: `checkmk/README.md`
- Export endpoint: `backend/src/app/checks/routes.py` (`GET /api/export/checkmk`)
- Check evaluation + thresholds: `backend/src/app/checks/evaluate.py`
- API keys: `backend/src/app/apikeys/routes.py`
- Test the output transform: `just checkmk-test`
