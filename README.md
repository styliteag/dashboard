# STYLiTE Orbit Dashboard

Central dashboard for monitoring and managing a fleet of **OPNsense, pfSense, and
Securepoint UTM** firewalls from one place — OPNsense/pfSense including sites behind
NAT (reached through an outbound push agent), Securepoint polled directly over its API.

## TL;DR

- **What:** one dashboard for a fleet of **OPNsense**, **pfSense**, and **Securepoint UTM**
  firewalls — live status, IPsec/VPN, gateways, firmware compliance, service checks,
  logs (snapshots, critical-event rollup, AI analysis), audit log, notifications,
  group-based permissions.
- **How boxes connect:** `direct` (dashboard → box API) or `push` (box → outbound
  `wss://`, a stdlib-only FreeBSD agent). Push works behind NAT with no inbound access
  and no stored API key; the agent also tunnels the box's REST API (**relay**) and its
  web GUI (**GUI proxy**). **Securepoint** is direct-poll/agentless (its `spcgi.cgi`
  JSON API, with optional SSH enrichment for richer IPsec data).
- **Agent lifecycle:** dashboard-triggered, signature-verified (Ed25519) **self-update**
  with two-layer rollback, one-time **enrollment**, **uninstall**. Config (e.g. IPsec
  ping monitors) is pushed on every (re)connect — the agent persists nothing, the DB is
  the source of truth.
- **Stack:** FastAPI + async SQLAlchemy on **MariaDB**, React 18 + Vite frontend, pure-
  stdlib agent. Ships as a single combined Docker image; TLS is operator-side.
- **Run it:** `cp .env.example .env`, set the secrets, `just up` (or `docker compose up`).
  Dev: `just dev-up`. See [Quickstart](#quickstart-production).

## What it does

- **Hub** (default landing page) — central operations overview with connected agents,
  push rates, error counters, and **CRIT alerts broken down by section** (checks, IPsec,
  connectivity, firmware, …). Quick access to the full fleet.
- **Instances** — register firewalls, see live status (CPU, memory, disk, uptime,
  interfaces and throughput) and recent history.
- **VPN / IPsec overview** — tunnel state across the fleet, with human-readable
  connection names pulled from each box's `config.xml`; restart a tunnel from the UI.
- **Gateways** — per-gateway up/down and latency.
- **Firmware compliance** — which boxes are up to date, which have updates pending;
  check (and stage) updates in bulk.
- **Service checks** — each box rolled up to OK / WARN / CRIT per service, exported
  for **Checkmk/OMD** (one piggyback host per firewall, no agent on the box) and as a
  **Prometheus** scrape endpoint (`/api/export/prometheus`) for Grafana.
- **Bulk actions + CSV export** — run `firmware_check` / `ipsec_restart` across many
  instances in parallel and export the results.
- **Logs** — the push agent collects the box's important logs hourly (system, filter,
  IPsec, OpenVPN, resolver, gateways, … capped at 250 KB each); the instance page shows
  the raw snapshots, and an optional **AI log analysis** sends an *anonymized* version
  (public IPs, hostnames, secrets scrubbed — with preview) to a configured LLM provider.
  A global **Logs** page rolls the whole fleet up to critical events: lines are rated by
  syslog severity (plus curated patterns for PRI-less logs), noise-filtered, and
  aggregated into one row per message pattern with a count.
- **Remote Packet Capture** — live pcap streaming and one-shot snapshots via the agent
  (no SSH required). Supports arbitrary BPF filters with convenient presets (exclude
  agent traffic automatically, `not vlan`, IPsec on WAN, `ether host`, etc.). Live
  viewer has packet list + hex dump (Ethernet/IP/TCP/UDP). Snapshots support up to
  600 s / 20 MiB. tcpdump is terminated cleanly on viewer close. The Hub page (default
  landing) now surfaces CRIT alerts grouped by section/check key.
- **Groups & permissions** — every instance belongs to exactly one group; users only
  see (and act on) instances of their groups, across every view, bulk action, export
  and the GUI proxy. **SuperAdmins** manage groups, users and memberships — rights
  management only, no instance access implied.
- **Audit log** — who did what, when.
- **Notifications** — Mattermost (webhook), Telegram and email on state changes
  (all optional); each group can override channel targets for its instances, with
  fallback to the global config.
- **Read-only API keys** — service-account auth for Checkmk and other integrations;
  keys can be bound to instance groups (e.g. one Checkmk key per customer).

## How firewalls connect

Transport and device type are decoupled. Two paths are in use today:

| Transport | Who initiates | Use |
|---|---|---|
| `direct` | Dashboard → firewall API | Firewall directly reachable from the dashboard (OPNsense/pfSense REST API, or **Securepoint** `spcgi.cgi`) |
| `push` | Firewall → outbound `wss://…/api/ws/agent` | **Primary for OPNsense/pfSense behind NAT** |

In **push** mode a small stdlib-only Python agent runs on the firewall (FreeBSD),
opens an outbound WebSocket to the dashboard, and pushes metrics on an interval. It
also exposes an optional **relay** — the dashboard tunnels HTTP requests to the box's
own REST API through the agent connection, so the dashboard needs no inbound access
and no stored API key. The same tunnel is reused for **live packet capture** (raw
pcap streaming) and **GUI proxy**. The agent supports dashboard-triggered **self-update**,
one-time **enrollment** (trade a code for a token), and **uninstall**. See
[`docs/agent-architecture.md`](docs/agent-architecture.md) for the full design.

**Securepoint UTM** boxes are **direct-poll only** — no on-box agent. The dashboard
maps the appliance's `spcgi.cgi` JSON API (session-auth) onto the same `DeviceClient`
contract as the others, so VPN/IPsec and service status surface in the same views.
Optionally, enabling **SSH enrichment** lets the dashboard pull IPsec via
`swanctl --raw` for richer detail (SPIs, cookies, byte counters) the `spcgi.cgi` API
doesn't expose. Agent-only features (relay, GUI proxy, on-box ping monitors,
self-update) don't apply to Securepoint.

## Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic, httpx, APScheduler,
  structlog. Managed with [`uv`](https://docs.astral.sh/uv/), `src/`-layout package.
- **Frontend:** React 18 + TypeScript, Vite, Tailwind, TanStack Query, React Router,
  Recharts.
- **Database:** **MariaDB 11** (async via `aiomysql`). Metrics retention and a 5-minute
  rollup are handled by in-process scheduler jobs — no TimescaleDB.
- **Agent:** pure-stdlib Python (no pip dependencies), runs on OPNsense/pfSense (FreeBSD).
- **Container:** single combined image — nginx serves the built frontend on `:80` and
  proxies `/api/` to uvicorn at `127.0.0.1:8000` inside the same container.
- **Deployment:** Docker Compose. TLS is operator-side (host reverse proxy, cloud LB).

## Quickstart (production)

Prerequisites: Docker, Docker Compose, and (optionally) [`just`](https://github.com/casey/just).

```bash
# 1. Configure secrets
cp .env.example .env
just gen-key            # paste output into DASH_MASTER_KEY in .env
# also set DB_PASSWORD, DB_ROOT_PASSWORD, DASH_ADMIN_PASSWORD and DASH_SUPERADMIN_PASSWORD

# 2. Start the stack (MariaDB + combined app image)
just up                 # or: docker compose up -d --build

# 3. Open
# http://localhost  (DASH_PORT in .env to remap)
```

To pull a published image instead of building locally, edit `compose.yml` — swap the
`build:` block under `app` for `image: ghcr.io/styliteag/dashboard:latest`.

## Connecting a firewall via the push agent

On the OPNsense/pfSense box (FreeBSD):

```sh
# Copy the agent/ files to the box, then:
sh install.sh
vi /usr/local/etc/orbit-agent.conf   # set dashboard_url + agent_token (or enroll_code)
sysrc orbit_agent_enable=YES
service orbit_agent start
tail -f /var/log/orbit_agent.log
```

The agent auto-discovers the box's own GUI/API port from `config.xml` (it does not
assume 443/4444). Config reference: [`agent/orbit-agent.conf.example`](agent/orbit-agent.conf.example).

## Firewall GUI proxy (optional)

Reach a NAT'd firewall's **web GUI** through its agent — no inbound access or VPN.
The dashboard tunnels raw TCP to the firewall over the agent's WebSocket; a reverse
proxy in front gives each firewall a **per-instance origin** (so the GUI's absolute
URLs resolve) and a valid TLS cert. The browser speaks TLS end-to-end with the
firewall — nothing is rewritten, so AJAX/forms/live views work. Access is gated by a
one-time handoff from your dashboard session → an origin-scoped cookie checked on
every request (`forwardAuth`), bound to that one firewall.

**Off by default.** It needs the reverse proxy set up, so enable it only then:

```sh
DASH_GUI_PROXY_ENABLED=true
DASH_GUI_BASE_TEMPLATE=https://gui-{slug}.example.com # prod; {slug} = instance slug
DASH_GUI_IDLE_MINUTES=15                               # close idle forwarders
```

With it on, instance pages show an **Open GUI** button (→ new tab). Leave it `false`
and the button is hidden — no wildcard/DNS needed.

- **Dev** (ports, no wildcard): `just dev` runs Caddy ([`docker/Caddyfile.dev`](docker/Caddyfile.dev))
  mapping `https://localhost:900<id>` → instance `<id>`'s forwarder. Already enabled
  in `compose-dev.yml`. Accept Caddy's internal-CA cert once.
- **Prod, behind Traefik** (wildcard subdomain): Orbit ships its own `gui-proxy`
  Caddy (in `compose.yml`, `--profile gui`). Your **external Traefik** terminates TLS
  for `*.gui.example.com` (DNS-01 wildcard cert) and forwards the wildcard to that
  Caddy over HTTP — see [`docker/traefik-gui.example.yml`](docker/traefik-gui.example.yml).
  Caddy host-matches `gui-<slug>`, runs the `forwardAuth` gate, and proxies to that
  firewall's forwarder (`app:14400+id`), so Traefik needs **no per-instance config**.
  Set `ORBIT_GUI_DOMAIN=gui.example.com`, `DASH_GUI_PROXY_ENABLED=true`,
  `DASH_GUI_BASE_TEMPLATE=https://gui-{slug}.gui.example.com`,
  `DASH_GUI_CADDY_ADMIN_URL=http://gui-proxy:2019/load`, attach `gui-proxy` to
  Traefik's network, then `docker compose --profile gui up -d`.

  > **`DASH_GUI_CADDY_ADMIN_URL` is required** — it's how the backend pushes the
  > vhost map to Caddy. The bundled `compose.yml` defaults it for you
  > (`${DASH_GUI_CADDY_ADMIN_URL:-http://gui-proxy:2019/load}`), but a **hand-written
  > compose / Swarm stack has no such default** — you must set it explicitly. If it's
  > unset while the proxy is enabled, the hot-load **silently no-ops**: Caddy stays on
  > the empty bootstrap and every `gui-<slug>` host returns a blank `200`. The backend
  > logs `gui_caddy.admin_url_unset` at startup when this happens.

  Each instance gets a **persistent, URL-safe `slug`** (auto-derived from its name —
  "Firewall Büro Süd" → `firewall-buero-sued`, editable, unique). Because the host is
  now a slug (not arithmetic from the id), the host→port binding lives in the DB: the
  mounted Caddyfile is just a **bootstrap** (admin API + empty wildcard), and the
  backend regenerates the per-slug vhost map and **hot-loads it through Caddy's admin
  API** (`gui-proxy:2019`, internal network only — never publish it) on every instance
  create/slug-change/delete and at startup. No per-instance file editing, no `gui-N`
  cap. Regenerate the bootstrap only if its global block changes:
  `uv --project backend run python scripts/gen-gui-caddyfile.py > docker/Caddyfile.gui-prod`.

  Wire the Traefik router either via the **file provider**
  ([`docker/traefik-gui.example.yml`](docker/traefik-gui.example.yml)) or, if your
  Traefik uses the **Docker/Swarm provider**, via **labels** — see the commented
  `deploy.labels` block on the `gui-proxy` service in `compose.yml`. Either way the
  router is a single wildcard rule → `gui-proxy:80` — `HostRegexp(`{subdomain:gui-[a-z0-9-]+}.<domain>`)`
  in Traefik **v2** (named group, no anchors), or the raw Go regexp
  `HostRegexp(^gui-[a-z0-9-]+\.<domain>$)` in **v3**.
  Traefik needs no per-instance config. Two gotchas: `deploy.labels` is read only by
  Traefik's **Swarm** provider (plain compose → use top-level `labels:`), and `gui-proxy`
  must share a network with Traefik (set `traefik.docker.network` if it's on several).

> Security: each origin fronts a firewall **admin** GUI — the `forwardAuth` gate is
> what keeps it closed. Don't remove it, and keep the forwarder ports off the public
> internet (reachable only by your reverse proxy). See `docs/agent-architecture.md` §18.

## Layout

```
Dockerfile              combined prod image (multi-stage: frontend + backend)
compose.yml             production stack (MariaDB + app)
compose-dev.yml         dev stack (db + backend + frontend, src bind-mounted)
docker/                 nginx.conf + start.sh used by the prod image
backend/                FastAPI app (src/app/), tests, Dockerfile.dev
frontend/               Vite + React + TS app, Dockerfile.dev
agent/                  stdlib push agent for OPNsense/pfSense + install.sh + rc.d
checkmk/                Checkmk special-agent plugin (pulls /api/export/checkmk)
scripts/                sign_agent.py — Ed25519 signing for agent self-update
docs/                   agent-architecture.md (living design doc)
.github/workflows/      release.yml — multi-arch publish on tag push
VERSION                 source of truth, baked into image at build
release.sh              version bump + tag + push helper
```

## Development

Two workflows — pick one:

### A) Local (fast feedback, recommended)

Backend and frontend run on the host. Database can run in Docker (just `db` from the dev compose) or locally.

```bash
just backend-install        # uv sync --all-extras (creates backend/.venv)
just backend-run            # uvicorn --reload on http://localhost:8000
just backend-test           # pytest

just frontend-install       # npm install
just frontend-dev           # vite on http://localhost:5173 (proxies /api → backend)
```

### B) Docker dev compose (everything in containers)

Both backend and frontend run as separate containers with their `src/` bind-mounted, so saving a file triggers `uvicorn --reload` (backend) or Vite HMR (frontend).

```bash
cp .env.example .env        # set DASH_MASTER_KEY at minimum
just dev-up                 # docker compose -f compose-dev.yml up -d --build
just dev-logs

# Browse: http://localhost:5173 (frontend)
# Direct: http://localhost:8000/api/health (backend)
```

### Tests & gates

```bash
just backend-test           # pytest (backend)
just agent-test             # pytest over agent/tests (runs in the backend venv)
just checkmk-test           # pytest over checkmk/tests
just frontend-build         # tsc -b && vite build — the only frontend gate
```

## Releasing

```bash
just release patch          # or: minor / major
```

`release.sh` bumps `VERSION`, inserts a dated section in `CHANGELOG.md`, commits, tags `${VERSION}`, and pushes. The `.github/workflows/release.yml` workflow then builds a multi-arch image (`linux/amd64,linux/arm64`) and publishes it to:

- `docker.io/styliteag/dashboard:${VERSION}` and `:latest`
- `ghcr.io/styliteag/dashboard:${VERSION}` and `:latest`

Required CI secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (GHCR uses the default `GITHUB_TOKEN`).

## Security notes

- Firewall API credentials are stored **encrypted at rest** with Fernet. The master
  key (`DASH_MASTER_KEY`) lives only in `.env`.
- Prefer the **push agent / relay** for boxes behind NAT — the dashboard then needs no
  inbound reachability and stores no per-box API key (the relay forwards to the box's
  loopback API, and on OPNsense the agent auto-provisions a dedicated `orbit` user).
- For **direct** transport, expose each firewall's API only over HTTPS with a source-IP
  allowlist for the dashboard host, pin the per-instance CA bundle, and use a dedicated
  service user with minimal ACLs (Diagnostics read, IPsec start/stop, Firmware update) —
  never root.
- **Checkmk** integration authenticates with a **read-only API key** (`POST /api/apikeys`,
  stored hashed, rejected on any non-GET request) — the admin password stays out of WATO.
- Agent **self-update is signature-verified** (Ed25519). The agent bakes a public key
  (`_UPDATE_PUBKEY` in `agent/orbit_agent.py`); every pushed update must carry a valid
  signature over the code, so a compromised dashboard can't push forged agent code — the
  dashboard only relays the signature, it never holds the key. Setup:
  1. Generate a keypair once, offline: `just sign-agent --gen` → keep `PRIV_B64` offline,
     bake `PUB_HEX` into `_UPDATE_PUBKEY`.
  2. Put the private key where the release machine can read it: `DASH_AGENT_SIGNING_KEY` in
     the environment or the gitignored repo-root `.env`.

  `release.sh` (`just release`) then **signs the agent automatically** before tagging —
  it refreshes `agent/orbit_agent.py.sig` from the current agent bytes, verifies it against
  the baked `_UPDATE_PUBKEY`, and includes it in the release commit (the signature is
  committed because it isn't secret; only the private key is). If `_UPDATE_PUBKEY` is set
  but no signing key is available, the release **aborts** — so only the offline key holder
  can cut a release, and a build that would brick every agent's self-update can't ship.
  To sign by hand outside a release: `DASH_AGENT_SIGNING_KEY=<PRIV_B64> just sign-agent`.

  **Dev escape hatch.** While iterating on the agent you can push an unsigned/stale build
  without re-signing by telling the *agent* (not the dashboard) to skip the check — it's
  off by default and logs a loud warning when active. Two channels, since the agent runs on
  the box, not in compose:
  - **Locally-run agent:** `AGENT_INSECURE_SKIP_SIG=1 python agent/orbit_agent.py`.
  - **Installed agent (rc.d):** add `"insecure_skip_sig": true` to its
    `/usr/local/etc/orbit-agent.conf` and restart it (`service orbit_agent restart`) — the
    env var doesn't reach an rc.d-launched process, so use the config flag there.

  > Never set either in production — it disables the forgery protection. It doesn't flow
  > from `compose-dev`; you set it on the agent itself.

## Further docs

- [`docs/agent-architecture.md`](docs/agent-architecture.md) — agent & connectivity design (transports, self-update, pfSense port, relay, Checkmk).
- [`CHECKMK.md`](CHECKMK.md) — full Checkmk integration guide (what's exposed, API key, datasource program, piggyback hosts, troubleshooting).
- [`checkmk/README.md`](checkmk/README.md) — Checkmk special-agent install and auth.
- [`CLAUDE.md`](CLAUDE.md) — repository conventions and done-criteria.

## License

STYLiTE Orbit Dashboard is **source-available** under the **Business Source
License 1.1 (BSL 1.1)** — see [`LICENSE`](LICENSE) and [`LICENSING.md`](LICENSING.md).

- ✅ Read, build, modify, and run it for your **own** organization.
- ❌ Offering it to third parties as a hosted / managed service, or reselling it,
  needs a **commercial license** — contact `office@stylite.de`.
- Each released version becomes **GPL-3.0-or-later** four years after its release.

BSL is *not* an OSI-approved "Open Source" license; the correct term is
*source-available*.
