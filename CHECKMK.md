# Checkmk integration

Monitor every firewall the dashboard knows about as a **Checkmk host** — without
installing a Checkmk agent on the firewall. The dashboard is the single source:
Checkmk pulls evaluated service checks from it and turns each firewall into a
piggyback host with services (memory, CPU, disks, gateways, IPsec service +
tunnels, IPsec ping monitors, firmware).

This is the operator guide. The plugin's own short note lives in
[`checkmk/README.md`](checkmk/README.md).

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
`backend/src/app/checks/evaluate.py`. **Nothing is exported by default** (opt-in);
under **Settings → Checkmk** an admin turns on a whole category globally, then
(optionally) adds or mutes a single service on one instance — include even works
inside an otherwise-off category. Selection is export-only; the dashboard still
shows everything.

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
- Admin access to the dashboard (to open **Settings → Checkmk**).

---

## Setup

### 1. Create the API key (Settings → Checkmk)

In the dashboard, open **Settings → Checkmk** (admin only) and click **Create
key**. Copy the shown `ORBIT_URL` / `ORBIT_API_KEY` snippet — you'll paste it
into the Checkmk wrapper below. The key is **re-viewable** later from the same
page (*Reveal*) and revocable there.

The key is **read-only** (`orbit_…` Bearer, rejected on any non-GET request), so
it's safe to drop into the Checkmk datasource config.

Since 2.7.0 a key can be **bound to instance groups** at creation (group picker in
the same dialog): a bound key only exports its groups' instances — one Checkmk key
per customer/group. Keys without bindings stay **global** (existing keys are
unaffected). The binding is fixed at creation; re-mint the key to change it.

On the same page you also choose **what gets exported**: nothing is on by default
(opt-in) — turn on a whole category globally, then add or mute a single service on
one instance (export-only; the dashboard keeps showing all checks).

### 2. Install the special agent on the Checkmk site

Copy it into the persistent **`local/`** overlay (survives `omd update` — the
plain `~/share/…` version tree does not). Create the directory first; it may not
exist on a fresh site:

```sh
mkdir -p ~/local/share/check_mk/agents/special
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

Install under **`~/local/…`**, never `~/share/…`. The `local/` tree is the
persistent user overlay that survives `omd update`; the plain `~/share/…`
version tree is replaced on every update (that's why files put there
"disappear"). `mkdir -p` first — a fresh site may not have the `special/`
directory yet, and `cat >` into a missing parent silently fails, leaving no
wrapper (→ later `exit code 127`).

```sh
mkdir -p ~/local/share/check_mk/agents/special
cat > ~/local/share/check_mk/agents/special/agent_styliteorbit_run <<'EOF'
#!/bin/sh
export ORBIT_URL=https://dashboard.example.com
export ORBIT_API_KEY=orbit_………
export ORBIT_PIGGYBACK=1
exec ~/local/share/check_mk/agents/special/agent_styliteorbit
EOF
chmod +x ~/local/share/check_mk/agents/special/agent_styliteorbit_run
```

This is two steps in Checkmk — create the host, then attach a **datasource
program rule** that points at the wrapper:

1. **Create the source host.** *Setup → Hosts → Add host* → name e.g.
   `orbit-export`, IP `127.0.0.1`. Leave it as is for now.
2. **Add the datasource rule.** Open the ruleset *Setup → Agents → Datasource
   programs → "Individual program call instead of agent access"* (fastest: type
   *Individual program call* into the Setup search box). *Add rule* → set
   **Command line** to the wrapper path, then under **Conditions → Explicit
   hosts** scope it to `orbit-export` so only that host runs it.

   ```
   ~/local/share/check_mk/agents/special/agent_styliteorbit_run
   or
   $OMD_ROOT/local/share/check_mk/agents/special/agent_styliteorbit_run
   ```

It's a *rule*, not a field on the host — the host page has no "datasource"
input. Without the condition the rule would fire on every host.

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

> **No piggyback?** Set `ORBIT_PIGGYBACK=0` in the wrapper to skip per-firewall
> hosts entirely — every check is then emitted on the **source host** that runs
> the agent, with each service item prefixed by the firewall name (e.g.
> `opnsense-fw01/memory`, summary `[opnsense-fw01] …`). You then run discovery on
> just that one host and skip step 5. Trade-off: all firewalls share one host's
> service list instead of each being its own host.

### 6. Service discovery

Run discovery on each firewall host (or, in `ORBIT_PIGGYBACK=0` mode, on the
single source host), accept the services, and activate changes. The
`memory` / `cpu` / `disk:*` / `gateway:*` / `ipsec.*` / `firmware` checks appear
as **Local checks**.

---

## Authentication & security

- The key is **read-only** — `Authorization: Bearer orbit_…`, accepted only on
  `GET`/`HEAD`/`OPTIONS`, `401` if unknown/revoked. Stored hashed; the
  re-viewable copy (for the Settings *Reveal*) is encrypted at rest and dropped
  on revoke. Keeps the admin password out of WATO.
- Manage keys under **Settings → Checkmk** (create / reveal / revoke).
- Prefer **HTTPS** for `ORBIT_URL` so the key isn't sent in clear text. The agent
  uses the system trust store for `https://` URLs.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Source host works, firewall host has no services | Piggyback host-name mismatch — Checkmk host name must equal the sanitized instance name. Check `~/tmp/check_mk/piggyback/` for the emitted host names. |
| `401 invalid API key` | Wrong/typo'd or revoked key. Reveal it again (or create a new one) under Settings → Checkmk. |
| `403 API key is read-only` | Something issued a non-GET with the key. The export is GET-only; check the wiring. |
| Empty output from the CLI test | `ORBIT_URL` wrong/unreachable, or no instances exist. |
| Export is slow / times out | Direct-poll instances are polled **live** on export (the agent's HTTP timeout is 30s). Many direct instances = slow; caching direct status is a follow-up. Push instances are served cheaply from cache. |
| Expected ping service missing | The Phase-2 child has no ping monitor, or the instance is direct-poll (ping is agent-only). Add a monitor, then re-discover. |

---

## Limits & follow-ups

- **Thresholds are hardcoded** (memory/disk 80/90, CPU 95, gateway loss 20/80 —
  `evaluate.py:16-20`). Per-instance/global config is a follow-up.
- **Direct-poll instances** are polled live per export (no cache yet).
- **Full per-role RBAC** for keys is still open. Today the only restriction is
  read-only.

---

## Reference

- Special agent: `checkmk/agent_styliteorbit.py` (stdlib only) ·
  short note: `checkmk/README.md`
- Export endpoint: `backend/src/app/checks/routes.py` (`GET /api/export/checkmk`)
- Check evaluation + thresholds: `backend/src/app/checks/evaluate.py`
- API keys: `backend/src/app/apikeys/routes.py`
- Test the output transform: `just checkmk-test`
