#!/usr/bin/env python3
"""Emit the *bootstrap* GUI-proxy Caddyfile (global block + admin API + empty wildcard).

Since the prod proxy moved to per-instance slugs (gui-<slug>.<domain>), the host→port
binding lives in the DB, not in arithmetic. The backend regenerates the real vhost map
and hot-loads it through Caddy's admin API on every instance create/slug-change/delete
and at startup (see app/agent_hub/gui_caddy.py, README "Firewall GUI proxy", §18).

This script only renders the empty bootstrap that Caddy mounts at container start (so
the admin endpoint is up before the backend pushes). It reuses the backend builder, so
run it inside the backend env:

  uv --project backend run python scripts/gen-gui-caddyfile.py > docker/Caddyfile.gui-prod
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend" / "src"))

from app.agent_hub.gui_caddy import bootstrap_caddyfile  # noqa: E402

sys.stdout.write(bootstrap_caddyfile())
