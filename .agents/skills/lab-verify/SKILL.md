---
name: lab-verify
description: Live E2E verification against the dev stack and the physical lab firewalls (opn1/opn2/pf1/pf2) — connection map, dev-stack drive-through, agent test loop without self-update churn, OPNsense API probing, orphan-process checks, evidence collection. Use whenever a change touches agent behavior, firewall APIs, tunnels/capture/shell, checks, or anything whose real proof is a live box.
---

# /lab-verify

"Tests green" is not "done" for firewall-facing work in this repo — the maintainer
proves changes live and records the evidence in the commit body. This skill is the
complete map so nothing gets rediscovered.

## The lab (shared — others may be using it right now)

| Box | IP | Platform | Notes |
|---|---|---|---|
| opn1 | 10.20.1.198 | OPNsense 2.6.11 | ipsec to opn2+pf1, one deliberately defunct tunnel (for status testing) |
| opn2 | 10.20.1.199 | OPNsense 2.6.11 | ipsec to opn1; `orbit` API user provisioned |
| pf1 | 10.20.1.200 | pfSense CE 2.8.1 | ipsec to opn1; python at `/usr/local/bin/python3.11` |
| pf2 | 10.20.1.217 | pfSense CE 2.7.2 | reusable series-upgrade tester: runs in the `orbit-pre-2.7.2-RELEASE` BE, sibling BE `default` = 2.8.1 (full cycle 2.7.2→2.8.1→rollback proven, docs §26); WAN 10.21.7.105 (DHCP) |

- SSH: `ssh -p 9922 root@10.20.1.19x`. **Root shell is tcsh** — bare `2>&1`, `$( )`
  break. Always run through sh:
  ```bash
  ssh -p 9922 root@10.20.1.199 sh <<'EOF'
  service orbit_agent status 2>&1
  EOF
  ```
- GUI/API on **port 4444** (custom, not 443): `https://10.20.1.19x:4444`.
- Etiquette: other developers/agents use these boxes concurrently. Don't reboot or
  firmware-apply without asking the user. Restore anything you change. **Copy evidence
  off `/tmp` (to `/root/` or your machine) before any reboot** — /tmp is wiped.

## Dev stack

- Start: `just dev-up`. Containers: `dashboard-backend-1`, `dashboard-frontend-1`,
  `dashboard-db-1` (mariadb:11), `dashboard-caddy-1`. Backend bind-mounts
  `backend/src` — code edits hot-reload; frontend has Vite HMR.
- URLs: UI `http://localhost:5173` (proxies /api), backend `http://localhost:8000`.
- Login: `POST /api/auth/login` `{"username":"admin","password":"admin"}` → session
  cookie. Bootstrap admin skips 2FA. For scripted calls, `DASH_ENV=dev` also enables a
  dev Bearer-token path in `current_user`.
  ```bash
  curl -s -c /tmp/orbit.jar -X POST http://localhost:8000/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'
  curl -s -b /tmp/orbit.jar http://localhost:8000/api/agents/connected | python3 -m json.tool
  ```
- Container workdir is `/app` (alembic.ini at `/app/alembic.ini`). New migration →
  restart the backend container (`docker restart dashboard-backend-1`); it applies
  `alembic upgrade head` at boot. Never run alembic from the host.
- **Shared stack, DB overrides win:** `app_settings` rows (e.g. `log_level`) beat env
  vars at lifespan re-apply, and other developers recreate containers in parallel —
  `docker inspect dashboard-backend-1` the env before trusting an experiment, and
  restore any `app_settings` override you touched.
- Known instance ids in the dev DB: 1=opn1(-ish local), 3=opn2 (.199), 4=pf1 (.200) —
  confirm with `GET /api/instances`, ids drift.

## Agent test loop (skip the signed self-update churn)

1. Bump `__version__` **above** the dashboard-served version so self-update won't
   overwrite your test copy.
2. Push and restart:
   ```bash
   scp -P 9922 agent/orbit_agent.py root@10.20.1.199:/usr/local/orbit-agent/orbit_agent.py
   ssh -p 9922 root@10.20.1.199 sh <<'EOF'
   service orbit_agent restart
   sleep 3
   tail -20 /var/log/orbit-agent.log 2>/dev/null || true
   EOF
   ```
3. Confirm reconnect + version: `GET /api/agents/connected` shows the box with your
   version, `last push` fresh.
4. Interpreters: OPNsense = `/usr/local/bin/python3`; pf1 = `/usr/local/bin/python3.11`
   (old pfSense has only versioned binaries — never hardcode `python3`).
5. When done for real: `just sign-agent` works on this machine (key in repo-root
   `.env`); verify with `just sign-agent --verify` before committing the `.sig`.
6. To test the actual self-update path: serve via the dev dashboard,
   `POST /api/instances/{id}/agent/update`, watch for
   `self-update: probation passed (healthy connect)`. A silent rollback after ~60s
   means the new build failed to reconnect.

## Probing firewall APIs directly

OPNsense (keys live on-box at `/usr/local/etc/opnsense-dash-agent.apikey`, or use a
GUI-created key):

```bash
curl -sk -u "KEY:SECRET" https://10.20.1.198:4444/api/core/firmware/status | head -c 400
```

- A response of `{"errorMessage":"Endpoint not found"}` means the MVC path is wrong —
  the backend's `_opnsense_json` swallows exactly this into `{}`, so **always curl the
  path against a lab box before wiring it** (the `filter_base` trap). Correct firewall
  paths: `filter/...`, aliases via `alias/search_item`.
- pfSense has no comparable REST core — agent-side work goes through `php -r` /
  `pfSsh.php`; verify command spellings on pf1, not from memory.

## Standard verification recipes

**New/changed agent data (collector, check, metric):**
- Restart-push loop above → `GET /api/instances/{id}/checks` and the UI tab show the
  new data; force `refresh.full` via the UI "Refresh now" and confirm the section
  actually refreshes (throttle-gate reset).

**Tunnel/stream features (shell, capture, GUI proxy):**
- Open the viewer, then close it, then on the box:
  ```bash
  ssh -p 9922 root@10.20.1.198 sh <<'EOF'
  pgrep -lf tcpdump; pgrep -lf sh.*pty; echo "exit=$?"
  EOF
  ```
  No orphan processes may survive viewer close (the `finally` + close-frame contract).
- Unauthenticated probe: `websocat`/curl the WS endpoint without a cookie — expect
  close 4401/4403 and (server-side) no hub consultation.

**Checks/alerts:** create the condition for real where cheap (stop a service, use
opn1's defunct IPsec tunnel for down-status), confirm the check appears identically on
all four surfaces: instance Checks tab, Alerts page, `/api/export/checkmk`,
`/api/export/prometheus`. Confirm a single blip does NOT alert (debounce) where the
check is per-measurement.

**Scoping:** create/use a user with zero groups → sees nothing; a bound API key →
exports only its groups' instances; out-of-scope by-id → 404 (not 403).

**Firmware/reboot-class actions:** ask the user first (shared lab, real reboots).
Evidence discipline from past runs: copy proofs from `/tmp` to `/root/` before the
box reboots.

## Prod-data calibration (optional, read-only)

A prod-DB copy runs via `docker compose -f compose-db2.yml up -d` on port 3307
(gitignored, plaintext prod passwords — never commit or echo them). Access with TCP:

```bash
docker exec dashboard-db2-1 sh -c 'mariadb -h127.0.0.1 -udash -p"$MYSQL_PASSWORD" dash -e "SELECT ..."'
```

Use it to calibrate thresholds/patterns against real fleet data ("Measured on the prod
DB copy: …" is the house evidence style). Read-only. Socket login fails by design
(grants are `'dash'@'%'`).

## Output

Report per verified claim: what was driven, on which box/stack, and the observed
evidence (exact log line, JSON snippet, pgrep output). These lines belong in the
commit body — "Verified live on .199: <evidence>" is the house convention.
