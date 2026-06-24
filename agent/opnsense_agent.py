#!/usr/bin/env python3
"""opnsense-dash agent — runs on OPNsense (FreeBSD), pushes data to the central dashboard.

Collects system metrics locally (no API needed), connects outbound via WebSocket,
and executes commands received from the dashboard.

Dependencies: Python 3.9+ only — no pip packages (stdlib WebSocket client).
Config: /usr/local/etc/opnsense-dash-agent.conf (JSON)
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import platform
import re
import signal
import ssl
import struct
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

# No external dependencies — the WebSocket client below is pure stdlib (see DR-4
# in docs/agent-architecture.md). This keeps the agent installable on locked-down
# boxes (e.g. pfSense CE) and makes self-update a single-file swap.

__version__ = "0.3.3"

# Ensure OPNsense tools are reachable — daemon(8) starts without /usr/local/sbin in PATH
os.environ["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:" + os.environ.get("PATH", "")

CONFIG_PATH = os.environ.get("AGENT_CONFIG", "/usr/local/etc/opnsense-dash-agent.conf")

log = logging.getLogger("opnsense-agent")


# =============================================================================
# Configuration
# =============================================================================

class Config:
    def __init__(self, path: str = CONFIG_PATH):
        self.path = path
        self.dashboard_url: str = ""  # wss://dashboard.example.com/ws/agent
        self.agent_token: str = ""
        self.agent_id: str = platform.node()
        self.push_interval: int = 30
        self.log_level: str = "INFO"
        self.load()

    def load(self) -> None:
        p = Path(self.path)
        if not p.exists():
            log.warning("config file %s not found, using defaults", self.path)
            return
        data = json.loads(p.read_text())
        self.dashboard_url = data.get("dashboard_url", self.dashboard_url)
        self.agent_token = data.get("agent_token", self.agent_token)
        self.agent_id = data.get("agent_id", self.agent_id)
        self.push_interval = int(data.get("push_interval", self.push_interval))
        self.log_level = data.get("log_level", self.log_level)


# =============================================================================
# Collectors — all local, no HTTP API calls needed
# =============================================================================

def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a shell command and return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def detect_platform() -> str:
    """Identify the host firewall: 'opnsense' | 'pfsense' | 'unknown'.

    OPNsense ships /usr/local/opnsense/version/; pfSense marks /etc/platform
    (confirmed on pfSense Plus 26.03). Shared FreeBSD collectors work on both;
    only gateways + firmware diverge (see docs/agent-architecture.md §4).
    """
    for marker in ("/usr/local/opnsense/version/core", "/usr/local/opnsense/version/opnsense"):
        if Path(marker).exists():
            return "opnsense"
    try:
        if "pfsense" in Path("/etc/platform").read_text(errors="replace").lower():
            return "pfsense"
    except OSError:
        pass
    if Path("/usr/local/sbin/pfSense-upgrade").exists():
        return "pfsense"
    return "unknown"


def _read_pfsense_version() -> str:
    """Read the pfSense product version from /etc/version (e.g. '26.03-RELEASE')."""
    try:
        return Path("/etc/version").read_text(errors="replace").strip().splitlines()[0]
    except (OSError, IndexError):
        return ""


def collect_cpu() -> dict:
    """Get CPU usage from sysctl kern.cp_time."""
    out = _run(["sysctl", "-n", "kern.cp_time"])
    if not out.strip():
        return {"total_pct": 0.0}
    # kern.cp_time returns: user nice system interrupt idle (as cumulative ticks)
    # We need two samples to compute delta. Fallback: use top.
    out2 = _run(["top", "-b", "-d1", "-s1"])
    match = re.search(r"([\d.]+)%\s*idle", out2)
    if match:
        idle = float(match.group(1))
        return {"total_pct": round(100.0 - idle, 1)}
    return {"total_pct": 0.0}


def collect_memory() -> dict:
    """Get memory from sysctl."""
    phys = _run(["sysctl", "-n", "hw.physmem"]).strip()
    total_bytes = int(phys) if phys.isdigit() else 0
    total_mb = total_bytes / 1024 / 1024

    # Get used from vm.stats
    pagesize = int(_run(["sysctl", "-n", "hw.pagesize"]).strip() or "4096")
    active = int(_run(["sysctl", "-n", "vm.stats.vm.v_active_count"]).strip() or "0")
    wired = int(_run(["sysctl", "-n", "vm.stats.vm.v_wire_count"]).strip() or "0")
    laundry = int(_run(["sysctl", "-n", "vm.stats.vm.v_laundry_count"]).strip() or "0")
    used_bytes = (active + wired + laundry) * pagesize
    used_mb = used_bytes / 1024 / 1024
    used_pct = (used_mb / total_mb * 100) if total_mb > 0 else 0

    return {
        "total_mb": round(total_mb, 1),
        "used_mb": round(used_mb, 1),
        "used_pct": round(used_pct, 1),
    }


def collect_disk() -> list[dict]:
    """Get disk usage from df."""
    out = _run(["df", "-h"])
    disks = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%"):
            disks.append({
                "device": parts[0],
                "mountpoint": parts[5],
                "used_pct": float(parts[4].rstrip("%")),
            })
    return disks


def collect_interfaces() -> list[dict]:
    """Get interface info: address/status from ifconfig, byte counters from netstat."""
    # Byte counters from netstat -ibn (first row per interface = link-layer row)
    bytes_map: dict[str, dict] = {}
    for line in _run(["netstat", "-ibn"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or parts[0] == "Name":
            continue
        name = parts[0]
        if name not in bytes_map:
            try:
                # netstat -ibn columns (with or without Idrop):
                # ... Ibytes Opkts Oerrs Obytes Coll
                # [-5]  [-4]  [-3]  [-2]  [-1]
                bytes_map[name] = {
                    "bytes_received": int(parts[-5]),
                    "bytes_transmitted": int(parts[-2]),
                }
            except (ValueError, IndexError):
                pass

    # Address and up/down status from ifconfig -a
    result: list[dict] = []
    current: dict | None = None
    for line in _run(["ifconfig", "-a"]).splitlines():
        if line and not line[0].isspace():
            if current is not None:
                result.append(current)
            m = re.match(r'^(\S+?):\s+flags=\S+<([^>]*)>', line)
            if m:
                name = m.group(1)
                flags = m.group(2).upper().split(",")
                current = {
                    "name": name,
                    "status": "up" if ("UP" in flags and "RUNNING" in flags) else "down",
                    "address": None,
                    **bytes_map.get(name, {"bytes_received": 0, "bytes_transmitted": 0}),
                }
            else:
                current = None
        elif current is not None:
            stripped = line.strip()
            if stripped.startswith("inet ") and current["address"] is None:
                parts = stripped.split()
                if len(parts) >= 2:
                    current["address"] = parts[1]
    if current is not None:
        result.append(current)
    return result


_PFSENSE_GW_PHP = (
    'require_once("/etc/inc/gwlb.inc"); '
    "echo json_encode(return_gateways_status(true));"
)


def _collect_gateways_pfsense() -> list[dict]:
    """pfSense gateway status via return_gateways_status() — returns clean JSON.

    Sample: {"WAN":{"monitorip":"1.2.3.4","srcip":"5.6.7.8","name":"WAN",
             "delay":"0ms","stddev":"0ms","loss":"100%","status":"down",
             "substatus":"highloss"}}  (stddev/delay/loss may be empty strings).
    """
    out = _run(["php", "-r", _PFSENSE_GW_PHP], timeout=10)
    start = out.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(out[start:])
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    gateways = []
    for key, info in data.items():
        if not isinstance(info, dict):
            continue
        gateways.append({
            "name": info.get("name", key),
            "address": info.get("monitorip", ""),  # the monitored gateway IP
            "status": info.get("status", ""),
            "delay": info.get("delay", ""),
            "stddev": info.get("stddev", ""),
            "loss": info.get("loss", ""),
            "interface": info.get("interface", ""),
        })
    return gateways


def collect_gateways() -> list[dict]:
    """Get gateway status (platform-specific)."""
    if detect_platform() == "pfsense":
        return _collect_gateways_pfsense()
    # OPNsense: pluginctl returns gateway status as JSON
    out = _run(["pluginctl", "-r", "return_gateways_status"])
    gateways = []
    if not out.strip():
        return gateways
    try:
        data = json.loads(out)
        # Output is wrapped: {"dpinger": {"GW_NAME": {...}, ...}}
        gw_dict = data.get("dpinger", data) if isinstance(data, dict) else {}
        if not isinstance(gw_dict, dict):
            return gateways
        def _tilde(v: object) -> str:
            """Return empty string for tilde sentinel or None, else str(v)."""
            return "" if v in ("~", None) else str(v)

        for name, info in gw_dict.items():
            if not isinstance(info, dict):
                continue
            addr = _tilde(info.get("gateway", ""))
            # Strip IPv6 scope identifier: "fe80::1%em0" → "fe80::1"
            if "%" in addr:
                addr = addr.split("%")[0]
            gateways.append({
                "name": name,
                "address": addr,
                "status": _tilde(info.get("status", "")),
                "delay": _tilde(info.get("delay", "")),
                "stddev": _tilde(info.get("stddev", "")),
                "loss": _tilde(info.get("loss", "")),
                "interface": _tilde(info.get("interface", info.get("friendlyiface", ""))),
            })
    except json.JSONDecodeError:
        pass
    return gateways


def _to_int(v: object) -> int:
    """Best-effort int conversion — swanctl counters are strings, may be missing."""
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


def _vici_parse(tokens: list[str]) -> dict:
    """Build a nested dict from a tokenized vici `--raw` stream.

    Grammar: `name {` opens a section, `name [` a list, `}`/`]` close, `key=value`
    assigns a scalar, `key=` directly before a bracket names that section/list
    (e.g. `local_addrs=[…]`), and a bare token is a section/list name or a list
    item. Tolerant of malformed input — never raises, just stops at end of tokens.
    """
    root: dict = {}
    stack: list[tuple[str, object]] = [("section", root)]
    pending: str | None = None
    for tok in tokens:
        kind, cont = stack[-1]
        if tok == "{" or tok == "[":
            child: object = {} if tok == "{" else []
            key = pending if pending is not None else str(len(cont))  # type: ignore[arg-type]
            if isinstance(cont, dict):
                cont[key] = child
            else:
                cont.append(child)  # type: ignore[union-attr]
            stack.append(("section" if tok == "{" else "list", child))
            pending = None
        elif tok == "}" or tok == "]":
            if len(stack) > 1:
                stack.pop()
            pending = None
        elif "=" in tok:
            k, _, val = tok.partition("=")
            if val == "":
                pending = k  # `key=` glued to a following `[`/`{` → it names that block
            elif isinstance(cont, dict):
                cont[k] = val
                pending = None
            else:
                pending = None
        elif kind == "list":
            cont.append(tok)  # type: ignore[union-attr]
        else:
            pending = tok
    return root


def _tokenize_vici(out: str) -> dict:
    """Pad glued delimiters and parse a `swanctl … --raw` stream into a tree."""
    padded = out
    for delim in "{}[]":
        padded = padded.replace(delim, f" {delim} ")
    return _vici_parse(padded.split())


def _iter_sections(node: object, markers: frozenset[str]):
    """Yield (name, section) for every dict carrying any of `markers`.

    `--raw` wraps payloads in a `… event { <name> { … } }` envelope (plus a
    sibling `… reply {}`), so the records of interest are not at the root.
    Descend until a section carries a marker key, then surface it keyed by its
    name without recursing into it — so nested sub-sections that happen to reuse
    a marker key are not mistaken for top-level records.
    """
    if not isinstance(node, dict):
        return
    for name, val in node.items():
        if not isinstance(val, dict):
            continue
        if markers.intersection(val):
            yield name, val
        else:
            yield from _iter_sections(val, markers)


def _first(v: object) -> str:
    """First element of a vici list (addresses come back as lists), else the value."""
    if isinstance(v, list):
        return str(v[0]) if v else ""
    if isinstance(v, str):
        return v
    return ""


# Marker keys unique to each record type — never present on the raw envelope.
_IKE_SA_MARKERS = frozenset({"uniqueid", "state", "local-host", "remote-host", "child-sas"})
_CONN_MARKERS = frozenset({"local_addrs", "remote_addrs", "children"})


def _parse_swanctl_sas(out: str) -> list[dict]:
    """Parse `swanctl --list-sas --raw` into one record per active IKE_SA.

    Phase-1 state lives at the IKE level; traffic counters and the phase-2 state
    live in the nested `child-sas` sections (summed here).
    """
    if not out.strip():
        return []
    sas = []
    for name, ike in _iter_sections(_tokenize_vici(out), _IKE_SA_MARKERS):
        children = ike.get("child-sas")
        bytes_in = bytes_out = 0
        if isinstance(children, dict):
            for child in children.values():
                if isinstance(child, dict):
                    bytes_in += _to_int(child.get("bytes-in"))
                    bytes_out += _to_int(child.get("bytes-out"))
        sas.append({
            "name": name,  # the SA's connection name — may be stale after a config reload
            "remote": ike.get("remote-host", ""),
            "local": ike.get("local-host", ""),
            "status": ike.get("state", "unknown"),  # IKE-level, not the child's INSTALLED
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "unique_id": str(ike.get("uniqueid", "")),  # stable handle for --terminate --ike-id
        })
    return sas


def _parse_swanctl_conns(out: str) -> list[dict]:
    """Parse `swanctl --list-conns --raw` into one record per configured tunnel.

    These are the *configured* connections (up or down); the connection name is
    what `swanctl --initiate --ike <name>` expects.
    """
    if not out.strip():
        return []
    conns = []
    for name, conn in _iter_sections(_tokenize_vici(out), _CONN_MARKERS):
        conns.append({
            "name": name,
            "local": _first(conn.get("local_addrs")),
            "remote": _first(conn.get("remote_addrs")),
        })
    return conns


def _ipsec_descriptions(config_path: str = "/conf/config.xml") -> dict[str, str]:
    """Map swanctl Connection UUID -> human description from OPNsense config.xml.

    swanctl only knows UUIDs; the user-facing name lives in config.xml under
    <OPNsense><Swanctl><Connections><Connection uuid="…"><description>. Returns
    {} when the file is absent or unparseable (caller then falls back to the UUID).
    """
    try:
        root = ElementTree.parse(config_path).getroot()
    except (OSError, ElementTree.ParseError):
        return {}
    descriptions: dict[str, str] = {}
    for connections in root.iter("Connections"):
        for conn in connections.findall("Connection"):
            uuid = conn.get("uuid")
            desc = (conn.findtext("description") or "").strip()
            if uuid and desc:
                descriptions[uuid] = desc
    return descriptions


def _tunnel(name: str, conn: dict | None, sa: dict | None, descriptions: dict[str, str]) -> dict:
    """Build one dashboard tunnel row, preferring live SA data when present."""
    conn = conn or {}
    base = {
        "id": name,  # connection name → `swanctl --initiate --ike <id>`
        "description": descriptions.get(name) or name,  # human name, else the UUID
    }
    if sa is not None:
        return {
            **base,
            "remote": sa["remote"] or conn.get("remote", ""),
            "local": sa["local"] or conn.get("local", ""),
            "status": sa["status"],
            "bytes_in": sa["bytes_in"],
            "bytes_out": sa["bytes_out"],
            "unique_id": sa["unique_id"],  # → `swanctl --terminate --ike-id <unique_id>`
        }
    return {
        **base,
        "remote": conn.get("remote", ""),
        "local": conn.get("local", ""),
        "status": "down",
        "bytes_in": 0,
        "bytes_out": 0,
        "unique_id": "",
    }


def _merge_ipsec(conns: list[dict], sas: list[dict], descriptions: dict[str, str]) -> list[dict]:
    """Overlay live SA status onto the configured connections.

    Match a configured conn to an active SA by name first, then by endpoint pair
    (the SA name can drift from the conn name after an OPNsense config reload).
    Active SAs with no matching conn are still surfaced so nothing disappears.
    """
    sa_by_name = {s["name"]: s for s in sas}
    sa_by_ep: dict[tuple[str, str], dict] = {}
    for s in sas:
        sa_by_ep.setdefault((s["local"], s["remote"]), s)

    tunnels = []
    matched: set[str] = set()
    for c in conns:
        sa = sa_by_name.get(c["name"]) or sa_by_ep.get((c["local"], c["remote"]))
        if sa is not None:
            matched.add(sa["name"])
        tunnels.append(_tunnel(c["name"], c, sa, descriptions))
    for s in sas:
        if s["name"] not in matched:
            tunnels.append(_tunnel(s["name"], None, s, descriptions))
    return tunnels


def collect_ipsec() -> dict:
    """Get IPsec tunnels: configured connections merged with live SA status."""
    descriptions = _ipsec_descriptions()
    conns = _parse_swanctl_conns(_run(["swanctl", "--list-conns", "--raw"], timeout=10))
    sas = _parse_swanctl_sas(_run(["swanctl", "--list-sas", "--raw"], timeout=10))
    tunnels = _merge_ipsec(conns, sas, descriptions)

    # Fallback: ipsec statusall (older / non-swanctl setups produce nothing above)
    if not tunnels:
        out2 = _run(["ipsec", "statusall"], timeout=10)
        for match in re.finditer(r'(\S+)\{(\d+)\}:\s+(INSTALLED|ESTABLISHED)', out2):
            name = match.group(1)
            tunnels.append({
                "id": name,
                "description": descriptions.get(name) or name,
                "remote": "",
                "local": "",
                "status": match.group(3).lower(),
                "bytes_in": 0,
                "bytes_out": 0,
                "unique_id": match.group(2),
            })

    running = bool(_run(["pgrep", "-x", "charon"]).strip())
    return {"running": running, "tunnels": tunnels}


def _read_opnsense_version() -> str:
    """Read OPNsense version string — tries direct file read first (most reliable in daemon context)."""
    # File read needs no subprocess and no PATH — most reliable approach.
    # Current OPNsense stores these as JSON objects ({"product_version": "25.7.11_9", ...});
    # older builds stored a bare version string. Handle both, else we'd surface "{".
    for vpath in [
        "/usr/local/opnsense/version/core",
        "/usr/local/opnsense/version/opnsense",
    ]:
        try:
            raw = Path(vpath).read_text().strip()
        except OSError:
            continue
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if isinstance(data, dict):
            v = str(data.get("product_version", "")).strip()
            if v:
                return v
            continue
        v = raw.splitlines()[0].strip()
        if v:
            return v
    # Fallback to binary
    out = _run(["/usr/local/sbin/opnsense-version"]).strip()
    if out:
        # "OPNsense 25.7.11_9 (amd64)" → "25.7.11_9"
        m = re.match(r"OPNsense\s+(\S+)", out)
        return m.group(1) if m else out
    return _run(["pkg", "query", "%v", "opnsense"]).strip()


# Track when we last ran a full firmware update check (network call)
_last_fw_check_ts: float = 0.0


def _pfsense_update_available(out: str) -> bool:
    """Decide update availability from `pfSense-upgrade -c` output.

    Confirmed negative on pfSense Plus 26.03: "Your system is up to date".
    The positive wording is inferred and should be re-confirmed against a box
    with a pending update; when unsure we do NOT raise a false alarm.
    """
    low = out.lower()
    if "up to date" in low:
        return False
    return any(
        s in low for s in ("will be upgraded", "new version", "version available", "upgrading")
    )


def collect_firmware() -> dict:
    """Firmware version on every push; update check every 10 minutes (per platform)."""
    global _last_fw_check_ts
    pfsense = detect_platform() == "pfsense"
    version = _read_pfsense_version() if pfsense else _read_opnsense_version()

    now = time.monotonic()
    if now - _last_fw_check_ts < 600:  # 0 on first call → always runs immediately
        return {"product_version": version}
    _last_fw_check_ts = now

    if pfsense:
        out = _run(["/usr/local/sbin/pfSense-upgrade", "-c"], timeout=60)
        upgrade_available = _pfsense_update_available(out)
    else:
        out = _run(["/usr/local/sbin/opnsense-update", "-c"], timeout=30)
        low = out.lower()
        upgrade_available = "can be updated" in low or "updates available" in low

    return {
        "product_version": version,
        "upgrade_available": upgrade_available,
        "update_check_output": out.strip()[:500],
    }


def collect_uptime() -> str:
    """Get uptime."""
    out = _run(["uptime"]).strip()
    match = re.search(r"up\s+(.*?),\s+\d+\s+user", out)
    if match:
        return match.group(1).strip()
    return out


def collect_system_info() -> dict:
    """Basic system identification."""
    return {
        "hostname": platform.node(),
        "os": _run(["uname", "-r"]).strip(),
        "platform": detect_platform(),
        "agent_version": __version__,
    }


def collect_firewall_log(limit: int = 30) -> list[dict]:
    """Read last N lines from /var/log/filter.log."""
    log_path = "/var/log/filter.log"
    if not os.path.exists(log_path):
        return []
    out = _run(["tail", "-n", str(limit), log_path])
    entries = []
    for line in out.splitlines():
        # filterlog format varies; extract what we can
        parts = line.split(",") if "," in line else line.split()
        if len(parts) > 6:
            entries.append({"raw": line.strip()[:300]})
    return entries[-limit:]


def collect_all() -> dict:
    """Full snapshot of this OPNsense instance."""
    return {
        "ts": datetime.now(UTC).isoformat(),
        "system": collect_system_info(),
        "uptime": collect_uptime(),
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disks": collect_disk(),
        "interfaces": collect_interfaces(),
        "gateways": collect_gateways(),
        "ipsec": collect_ipsec(),
        "firmware": collect_firmware(),
        "firewall_log": collect_firewall_log(30),
    }


# =============================================================================
# Command executor
# =============================================================================

def execute_command(action: str, params: dict) -> dict:
    """Execute a command received from the dashboard."""
    log.info("executing command: %s", action)

    if action == "ipsec.connect":
        tunnel_id = params.get("tunnel_id", "")
        out = _run(["swanctl", "--initiate", "--ike", tunnel_id], timeout=15)
        return {"success": "successfully" in out.lower(), "output": out.strip()[:500]}

    elif action == "ipsec.disconnect":
        # tunnel_id is the active IKE_SA's unique id — stable even if the SA's
        # connection name drifted from the configured name after a reload.
        tunnel_id = params.get("tunnel_id", "")
        out = _run(["swanctl", "--terminate", "--ike-id", tunnel_id], timeout=15)
        return {"success": "successfully" in out.lower(), "output": out.strip()[:500]}

    elif action == "ipsec.restart":
        out = _run(["service", "strongswan", "restart"], timeout=30)
        return {"success": True, "output": out.strip()[:500]}

    elif action == "firmware.check":
        out = _run(["/usr/local/sbin/opnsense-update", "-c"], timeout=60)
        return {
            "success": True,
            "output": out.strip()[:500],
            "product_version": _read_opnsense_version(),
        }

    elif action == "firmware.update":
        # Non-blocking: start in background
        subprocess.Popen(
            ["/usr/local/sbin/opnsense-update", "-bkp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {"success": True, "output": "update started in background"}

    elif action == "config.backup":
        config_path = "/conf/config.xml"
        if os.path.exists(config_path):
            content = Path(config_path).read_text(errors="replace")
            return {"success": True, "config_xml": content}
        return {"success": False, "output": "config.xml not found"}

    elif action == "reboot":
        subprocess.Popen(["shutdown", "-r", "+1"], stdout=subprocess.DEVNULL)
        return {"success": True, "output": "reboot scheduled in 1 minute"}

    elif action == "ping":
        return {"success": True, "output": "pong", "agent_version": __version__}

    else:
        return {"success": False, "output": f"unknown action: {action}"}


# =============================================================================
# WebSocket client (stdlib RFC 6455 — no external dependency, see DR-4)
# =============================================================================

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


class WSError(Exception):
    """Raised on handshake failure or when the connection is closed."""


def _ws_accept_key(key: str) -> str:
    """Compute the server's Sec-WebSocket-Accept for a client key (RFC 6455 §1.3)."""
    digest = hashlib.sha1((key + _WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def _encode_frame(opcode: int, payload: bytes) -> bytes:
    """Encode a single client frame: FIN=1, masked (clients MUST mask, §5.3)."""
    header = bytearray([0x80 | (opcode & 0x0F)])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return bytes(header) + masked


async def _read_frame(reader: asyncio.StreamReader) -> tuple[bool, int, bytes]:
    """Read one server frame → (fin, opcode, payload). Server frames are unmasked (§5.1)."""
    b0, b1 = await reader.readexactly(2)
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", await reader.readexactly(2))
    elif length == 127:
        (length,) = struct.unpack("!Q", await reader.readexactly(8))
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked and payload:
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return fin, opcode, payload


class WebSocket:
    """Minimal asyncio WebSocket client: text frames, ping/pong, close, and
    reassembly of fragmented messages. Concurrent senders are serialized so
    frames never interleave."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, max_size: int):
        self._reader = reader
        self._writer = writer
        self._max_size = max_size
        self._send_lock = asyncio.Lock()
        self._closed = False

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        async with self._send_lock:
            self._writer.write(_encode_frame(opcode, payload))
            await self._writer.drain()

    async def send(self, text: str) -> None:
        await self._send_frame(_OP_TEXT, text.encode())

    async def ping(self, payload: bytes = b"") -> None:
        await self._send_frame(_OP_PING, payload)

    async def recv(self) -> str:
        """Return the next text message, transparently answering pings and
        reassembling fragments. Raises WSError when the peer closes."""
        buffer = bytearray()
        msg_opcode: int | None = None
        while True:
            fin, opcode, payload = await _read_frame(self._reader)
            if opcode == _OP_PING:
                await self._send_frame(_OP_PONG, payload)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                self._closed = True
                raise WSError("connection closed by server")
            if opcode != _OP_CONT:
                msg_opcode = opcode
            buffer += payload
            if len(buffer) > self._max_size:
                raise WSError("message exceeds max_size")
            if fin:
                if msg_opcode == _OP_TEXT:
                    return bytes(buffer).decode()
                buffer = bytearray()  # ignore binary; this agent only speaks JSON text
                msg_opcode = None

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(OSError, WSError):
                await self._send_frame(_OP_CLOSE, struct.pack("!H", 1000))
        with contextlib.suppress(OSError):
            self._writer.close()


async def ws_connect(url: str, headers: dict[str, str], max_size: int) -> WebSocket:
    """Open a WebSocket connection (ws:// or wss://) and perform the handshake."""
    parts = urlsplit(url)
    secure = parts.scheme == "wss"
    host = parts.hostname or ""
    port = parts.port or (443 if secure else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    ssl_ctx = ssl.create_default_context() if secure else None
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ssl_ctx, server_hostname=host if secure else None
    )

    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()

    status_line = await reader.readline()
    if b" 101 " not in status_line and not status_line.startswith(b"HTTP/1.1 101"):
        writer.close()
        raise WSError(f"handshake failed: {status_line.decode(errors='replace').strip()}")
    resp_headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode(errors="replace").partition(":")
        resp_headers[k.strip().lower()] = v.strip()
    if resp_headers.get("sec-websocket-accept", "") != _ws_accept_key(key):
        writer.close()
        raise WSError("handshake failed: bad Sec-WebSocket-Accept")
    return WebSocket(reader, writer, max_size)


# =============================================================================
# Self-update (Phase 1) — see docs/agent-architecture.md §5.
#
# The dashboard pushes new agent code over the authenticated WebSocket. We verify
# it (sha256 + syntax), back up the current file, atomically swap it in, set a
# probation marker, and exit 42 to ask the supervisor (run-agent.sh) to respawn
# into the new code. Two rollback layers protect against a bad update:
#   - probation watchdog (this process): no healthy reconnect within
#     _PROBATION_SECS → restore the backup and exit;
#   - supervisor (run-agent.sh): a fast crash with the marker present → restore
#     the backup before respawning.
# =============================================================================

_UPDATE_RESTART_CODE = 42
_PROBATION_SECS = 60
# Set once the dashboard accepts us (welcome received). Created inside the running
# loop in _main_async() so it never binds to the wrong event loop.
_healthy: asyncio.Event | None = None


def _self_path() -> str:
    return os.environ.get("AGENT_SELF_PATH") or os.path.abspath(__file__)


def _marker_path() -> str:
    return _self_path() + ".updating"


def _backup_path() -> str:
    return _self_path() + ".bak"


def _verify_update_code(code: bytes, expected_sha256: str) -> bool:
    """Integrity (sha256) + syntax (compile) check before any swap.

    Note: compile() only catches syntax errors, not runtime failures — the real
    health gate is the probation reconnect below.
    """
    if hashlib.sha256(code).hexdigest() != (expected_sha256 or "").lower():
        return False
    try:
        compile(code, "<agent-update>", "exec")
    except (SyntaxError, ValueError):
        return False
    return True


def _apply_update(code: bytes, version: str) -> None:
    """Back up the running agent, atomically swap in new code, set the marker.

    The temp file is written in the target directory so os.replace stays atomic
    (same filesystem). Errors propagate so a half-write never goes live.
    """
    target = _self_path()
    tmp = target + ".new"
    with open(tmp, "wb") as f:
        f.write(code)
        f.flush()
        os.fsync(f.fileno())
    with contextlib.suppress(OSError):
        os.replace(target, _backup_path())
    os.replace(tmp, target)
    Path(_marker_path()).write_text(version)


def _rollback() -> bool:
    """Restore the backup over the agent file and clear the marker."""
    bak = _backup_path()
    if not os.path.exists(bak):
        return False
    try:
        os.replace(bak, _self_path())
    except OSError:
        return False
    with contextlib.suppress(OSError):
        os.remove(_marker_path())
    return True


def _clear_probation() -> None:
    """Probation passed: drop the marker and the backup."""
    with contextlib.suppress(OSError):
        os.remove(_marker_path())
    with contextlib.suppress(OSError):
        os.remove(_backup_path())


async def _handle_self_update(ws: WebSocket, request_id: str, params: dict) -> None:
    """Verify + stage a pushed update, ack, then exit for the supervisor to respawn."""
    version = params.get("version", "")
    try:
        code = base64.b64decode(params.get("code", ""), validate=True)
    except (ValueError, TypeError):
        await _send_update_result(ws, request_id, False, "invalid base64 code")
        return
    if not _verify_update_code(code, params.get("sha256", "")):
        await _send_update_result(ws, request_id, False, "verification failed (sha256/syntax)")
        return
    try:
        await asyncio.get_event_loop().run_in_executor(None, _apply_update, code, version)
    except OSError as exc:
        await _send_update_result(ws, request_id, False, f"apply failed: {exc}")
        return
    await _send_update_result(ws, request_id, True, f"update staged to {version}, restarting")
    log.info("self-update: staged %s, exiting for supervisor respawn", version)
    await ws.close()
    os._exit(_UPDATE_RESTART_CODE)


async def _send_update_result(ws: WebSocket, request_id: str, success: bool, output: str) -> None:
    await ws.send(json.dumps({
        "type": "command_result",
        "request_id": request_id,
        "action": "agent.update",
        "result": {"success": success, "output": output},
    }))


async def _probation_watchdog(healthy: asyncio.Event) -> None:
    """If we just self-updated, demand a healthy reconnect or roll back."""
    try:
        await asyncio.wait_for(healthy.wait(), _PROBATION_SECS)
    except asyncio.TimeoutError:
        log.error(
            "self-update: probation FAILED (no healthy connect in %ds), rolling back",
            _PROBATION_SECS,
        )
        _rollback()
        os._exit(1)


# =============================================================================
# WebSocket connection loop
# =============================================================================

async def agent_loop(cfg: Config) -> None:
    """Main loop: connect to dashboard, push data, listen for commands."""

    url = cfg.dashboard_url
    if not url:
        log.error("dashboard_url not configured, exiting")
        return

    reconnect_delay = 5

    while True:
        ws: WebSocket | None = None
        try:
            log.info("connecting to %s", url)
            ws = await ws_connect(
                url,
                headers={"Authorization": f"Bearer {cfg.agent_token}"},
                max_size=10 * 1024 * 1024,  # 10MB for config backups
            )
            log.info("connected to dashboard")
            reconnect_delay = 5  # reset on successful connect

            # Send initial handshake
            await ws.send(json.dumps({
                "type": "hello",
                "agent_id": cfg.agent_id,
                "agent_version": __version__,
                "hostname": platform.node(),
                "platform": detect_platform(),
            }))

            # Run push, listen and keepalive concurrently
            tasks = [
                asyncio.create_task(_push_loop(ws, cfg)),
                asyncio.create_task(_listen_loop(ws)),
                asyncio.create_task(_keepalive_loop(ws)),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done:
                if t.exception():
                    log.warning("task ended with error: %s", t.exception())

        except Exception as exc:  # noqa: BLE001 — any failure → reconnect with backoff
            log.warning("connection lost: %s, reconnecting in %ds", exc, reconnect_delay)
        finally:
            if ws is not None:
                await ws.close()

        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, 120)  # exponential backoff, max 2min


async def _keepalive_loop(ws: WebSocket) -> None:
    """Send a WebSocket ping every 20s so NAT mappings stay open."""
    while True:
        await asyncio.sleep(20)
        await ws.ping()


async def _push_loop(ws: WebSocket, cfg: Config) -> None:
    """Push metrics snapshot every N seconds."""
    while True:
        try:
            snapshot = await asyncio.get_event_loop().run_in_executor(None, collect_all)
            await ws.send(json.dumps({"type": "metrics", "data": snapshot}))
            log.debug("pushed metrics snapshot")
        except Exception as exc:
            log.warning("push error: %s", exc)
            raise
        await asyncio.sleep(cfg.push_interval)


async def _listen_loop(ws: WebSocket) -> None:
    """Listen for commands from the dashboard."""
    while True:
        raw = await ws.recv()
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "welcome":
                # Dashboard accepted us. If we just self-updated, probation passes.
                if os.path.exists(_marker_path()):
                    _clear_probation()
                    log.info("self-update: probation passed (healthy connect)")
                if _healthy is not None:
                    _healthy.set()

            elif msg_type == "command":
                action = msg.get("action", "")
                params = msg.get("params", {})
                request_id = msg.get("request_id", "")

                if action == "agent.update":
                    # Stages new code, acks, then exits — does not return here.
                    await _handle_self_update(ws, request_id, params)
                    continue

                # Execute in thread pool to not block the event loop
                result = await asyncio.get_event_loop().run_in_executor(
                    None, execute_command, action, params
                )
                await ws.send(json.dumps({
                    "type": "command_result",
                    "request_id": request_id,
                    "action": action,
                    "result": result,
                }))

            elif msg_type == "config_update":
                # Dashboard can update push interval etc.
                log.info("received config update: %s", msg)

            elif msg_type == "ping":
                await ws.send(json.dumps({"type": "pong"}))

        except json.JSONDecodeError:
            log.warning("received non-JSON message, ignoring")
        except Exception as exc:
            log.warning("error handling message: %s", exc)


# =============================================================================
# Entrypoint
# =============================================================================

async def _main_async(cfg: Config) -> None:
    """Run the connection loop, plus a probation watchdog if we just self-updated."""
    global _healthy
    _healthy = asyncio.Event()
    tasks = [asyncio.create_task(agent_loop(cfg))]
    if os.path.exists(_marker_path()):
        log.info("self-update: on probation — must connect healthy within %ds", _PROBATION_SECS)
        tasks.append(asyncio.create_task(_probation_watchdog(_healthy)))
    await asyncio.gather(*tasks)


def main() -> None:
    cfg = Config()
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log.info("opnsense-dash agent v%s starting (id=%s)", __version__, cfg.agent_id)
    log.info("dashboard: %s", cfg.dashboard_url)
    log.info("push interval: %ds", cfg.push_interval)

    # Graceful shutdown
    loop = asyncio.new_event_loop()

    def shutdown_handler(*_):
        log.info("shutting down")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        loop.run_until_complete(_main_async(cfg))
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()
    log.info("agent stopped")


if __name__ == "__main__":
    main()
