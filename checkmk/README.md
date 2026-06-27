# STYLiTE Orbit — Checkmk special agent

> Full operator guide (what's exposed, API key, datasource program, piggyback
> hosts, troubleshooting): [`../CHECKMK.md`](../CHECKMK.md). This file is the
> short plugin note.

`agent_styliteorbit.py` pulls `/api/export/checkmk` from the dashboard and emits
Checkmk agent output: **one piggyback host per firewall**, each with a
`<<<local>>>` section of evaluated OK/WARN/CRIT service checks + perfdata
(memory, disks, cpu, gateways, IPsec service + tunnels, firmware).

So every firewall the dashboard knows about becomes a Checkmk host with services
— no agent on the firewall for Checkmk, the dashboard is the single source.

## Install (Checkmk site)

```sh
cp agent_styliteorbit.py ~/local/share/check_mk/agents/special/agent_styliteorbit
chmod +x ~/local/share/check_mk/agents/special/agent_styliteorbit
```

Wire it as a **datasource program** (or test from the CLI):

```sh
# Preferred: a read-only API key (works in prod)
ORBIT_URL=http://dashboard.example.com ORBIT_API_KEY=orbit_xxxxx ./agent_styliteorbit

# Or (dev only): username/password login
ORBIT_URL=http://dashboard.example.com ORBIT_USER=admin ORBIT_PASSWORD=secret ./agent_styliteorbit
```

Mint a key (admin):

```sh
curl -X POST http://dashboard.example.com/api/apikeys \
  -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"name":"checkmk"}'      # returns {"key":"orbit_..."} — shown once
```

Output (excerpt):

```
<<<<opnsense-fw01>>>>
<<<local>>>
0 memory mem_used_pct=19;80;90 Memory 19% used (ok)
2 gateway:WAN - Gateway WAN down
<<<<>>>>
```

Then add the piggyback hosts in Checkmk and run service discovery.

## Auth

Use a **read-only API key** (`ORBIT_API_KEY`) — minted via `POST /api/apikeys`,
stored hashed, rejected on any non-GET request, revocable via
`DELETE /api/apikeys/{id}`. This works in production and keeps the admin
password out of WATO. The username/password fallback only works with
`DASH_ENV=dev` (the dev bearer token). Full per-role RBAC is still a follow-up
(see `docs/agent-architecture.md` §14).

## Dev

Pure-stdlib (Checkmk servers ship Python 3). The output transform
(`render_checkmk`) is tested: `just checkmk-test`.
