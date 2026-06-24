# STYLiTE Orbit — Checkmk special agent

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
ORBIT_URL=http://dashboard.example.com \
ORBIT_USER=admin \
ORBIT_PASSWORD=secret \
  ./agent_styliteorbit
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

## Auth (limitation)

v1 logs in via `/api/auth/login` and uses the returned bearer token, which the
dashboard issues **only when `DASH_ENV=dev`**. A dedicated read-only **API key**
for service accounts is a follow-up (ties into RBAC — see
`docs/agent-architecture.md` §14). Don't put the admin password in production
WATO until then.

## Dev

Pure-stdlib (Checkmk servers ship Python 3). The output transform
(`render_checkmk`) is tested: `just checkmk-test`.
