#!/usr/bin/env python3
"""Checkmk special agent for STYLiTE Orbit.

Pulls /api/export/checkmk from the dashboard and emits Checkmk agent output:
one piggyback host per firewall, each with a <<<local>>> section carrying the
evaluated OK/WARN/CRIT service checks + perfdata.

Install: drop this in the Checkmk site's local special-agent path and wire a
datasource program rule:  agent_styliteorbit '$HOSTADDRESS$'  (or via env).
Config via env: ORBIT_URL, ORBIT_USER, ORBIT_PASSWORD.

Auth note: uses the dev bearer token from /api/auth/login (works when the
dashboard runs with DASH_ENV=dev). A dedicated read-only API key for service
accounts is a follow-up (see docs/agent-architecture.md §14, RBAC).

Stdlib only — Checkmk servers ship Python 3.
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request

_VALID_STATES = {0, 1, 2, 3}


def _item(value: object) -> str:
    """Checkmk service item / metric name: no whitespace."""
    return "_".join(str(value).split()) or "unknown"


def _host(value: object) -> str:
    """Piggyback host name: alnum plus . - _ only."""
    s = "".join(ch if (ch.isalnum() or ch in ".-_") else "_" for ch in str(value))
    return s or "unknown"


def _num(value: object) -> str:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return "0"
    return str(int(f)) if f == int(f) else f"{f:.2f}"


def _perfdata(metrics: list) -> str:
    if not metrics:
        return "-"
    parts = []
    for m in metrics:
        warn = "" if m.get("warn") is None else _num(m.get("warn"))
        crit = "" if m.get("crit") is None else _num(m.get("crit"))
        parts.append(f"{_item(m.get('name', 'metric'))}={_num(m.get('value', 0))};{warn};{crit}")
    return "|".join(parts)


def _local_line(check: dict) -> str:
    state = check.get("state", 3)
    if state not in _VALID_STATES:
        state = 3
    text = (check.get("summary") or "-").replace("\n", " ").replace("|", "/").strip() or "-"
    item = _item(check.get("key", "unknown"))
    perf = _perfdata(check.get("metrics") or [])
    return f"{state} {item} {perf} {text}"


def render_checkmk(export: dict) -> str:
    """Transform the export JSON into Checkmk agent output (piggyback + local checks)."""
    out: list[str] = []
    for inst in export.get("instances", []):
        out.append(f"<<<<{_host(inst.get('host') or inst.get('name') or 'unknown')}>>>>")
        out.append("<<<local>>>")
        for check in inst.get("checks", []):
            out.append(_local_line(check))
        out.append("<<<<>>>>")
    return "\n".join(out) + "\n"


# --- HTTP (stdlib) -----------------------------------------------------------


def _ctx(url: str) -> ssl.SSLContext | None:
    return ssl.create_default_context() if url.startswith("https") else None


def _request(url: str, *, data: bytes | None = None, headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        url, data=data, headers=headers or {}, method="POST" if data is not None else "GET"
    )
    with urllib.request.urlopen(req, timeout=30, context=_ctx(url)) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def fetch_export(base_url: str, *, api_key: str = "", username: str = "", password: str = "") -> dict:
    """Fetch the export. Prefer a read-only API key; fall back to login (dev)."""
    if api_key:
        headers = {"Authorization": f"Bearer {api_key}"}
    else:
        login = _request(
            f"{base_url}/api/auth/login",
            data=json.dumps({"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
        )
        token = login.get("session_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
    return _request(f"{base_url}/api/export/checkmk", headers=headers)


def main() -> None:
    base = (os.environ.get("ORBIT_URL") or (sys.argv[1] if len(sys.argv) > 1 else "")).rstrip("/")
    if not base:
        sys.stderr.write("usage: set ORBIT_URL (+ ORBIT_API_KEY, or ORBIT_USER/ORBIT_PASSWORD)\n")
        sys.exit(2)
    export = fetch_export(
        base,
        api_key=os.environ.get("ORBIT_API_KEY", ""),
        username=os.environ.get("ORBIT_USER", "admin"),
        password=os.environ.get("ORBIT_PASSWORD", ""),
    )
    sys.stdout.write(render_checkmk(export))


if __name__ == "__main__":
    main()
