#!/usr/bin/env python3
"""opnsense-dash agent — runs on OPNsense (FreeBSD), pushes data to the central dashboard.

Collects system metrics locally (no API needed), connects outbound via WebSocket,
and executes commands received from the dashboard.

Dependencies: Python 3.9+ (ships with OPNsense), websockets (pip install websockets)
Config: /usr/local/etc/opnsense-dash-agent.conf (JSON)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Only external dependency
try:
    import websockets
    from websockets.asyncio.client import connect as ws_connect
except ImportError:
    print("ERROR: 'websockets' package required. Install with: pip install websockets", file=sys.stderr)
    sys.exit(1)

__version__ = "0.1.0"

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
    """Get interface stats from netstat -ibn."""
    out = _run(["netstat", "-ibn"])
    seen: dict[str, dict] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        name = parts[0]
        if name in seen or name == "Name":
            continue
        # Try to detect if it's a link-layer line (has MAC address)
        try:
            seen[name] = {
                "name": name,
                "mtu": int(parts[1]) if parts[1].isdigit() else 0,
                "bytes_received": int(parts[-3]) if parts[-3].isdigit() else 0,
                "bytes_transmitted": int(parts[-1]) if parts[-1].isdigit() else 0,
            }
        except (ValueError, IndexError):
            pass
    return list(seen.values())


def collect_gateways() -> list[dict]:
    """Get gateway status from dpinger or pluginctl."""
    out = _run(["pluginctl", "-r", "return_gateways_status"])
    gateways = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                for name, info in data.items():
                    gateways.append({
                        "name": name,
                        "address": info.get("address", info.get("gateway", "")),
                        "status": info.get("status", ""),
                        "delay": info.get("delay", ""),
                        "loss": info.get("loss", ""),
                    })
        except json.JSONDecodeError:
            pass
    return gateways


def collect_ipsec() -> dict:
    """Get IPsec tunnel status from swanctl."""
    out = _run(["swanctl", "--list-sas", "--raw"], timeout=10)
    tunnels = []
    # Parse swanctl raw output — simplified
    if out.strip():
        for line in out.strip().split("\n"):
            # Each line is a SA; parse key fields
            parts = dict(re.findall(r'(\w[\w-]*)=([^,}\]]+)', line))
            if parts:
                tunnels.append({
                    "id": parts.get("uniqueid", parts.get("name", "")),
                    "description": parts.get("name", ""),
                    "remote": parts.get("remote-host", ""),
                    "local": parts.get("local-host", ""),
                    "status": parts.get("state", "unknown"),
                    "bytes_in": int(parts.get("bytes-in", 0) or 0),
                    "bytes_out": int(parts.get("bytes-out", 0) or 0),
                })

    # Fallback: use ipsec statusall
    if not tunnels:
        out2 = _run(["ipsec", "statusall"], timeout=10)
        # Minimal parse — just detect tunnel names and status
        for match in re.finditer(r'(\S+)\{(\d+)\}:\s+(INSTALLED|ESTABLISHED)', out2):
            tunnels.append({
                "id": match.group(2),
                "description": match.group(1),
                "remote": "",
                "local": "",
                "status": match.group(3).lower(),
                "bytes_in": 0,
                "bytes_out": 0,
            })

    running = bool(_run(["pgrep", "-x", "charon"]).strip())
    return {"running": running, "tunnels": tunnels}


def collect_firmware() -> dict:
    """Get firmware version and update status."""
    version = _run(["opnsense-version"]).strip()
    # Check for updates
    update_out = _run(["opnsense-update", "-c"], timeout=30)
    updates_available = "can be updated" in update_out.lower() or "updates available" in update_out.lower()
    return {
        "product_version": version,
        "upgrade_available": updates_available,
        "update_check_output": update_out.strip()[:500],
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
        "ts": datetime.now(timezone.utc).isoformat(),
        "system": collect_system_info(),
        "uptime": collect_uptime(),
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disks": collect_disk(),
        "interfaces": collect_interfaces(),
        "gateways": collect_gateways(),
        "ipsec": collect_ipsec(),
        "firmware": collect_firmware(),
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
        tunnel_id = params.get("tunnel_id", "")
        out = _run(["swanctl", "--terminate", "--ike", tunnel_id], timeout=15)
        return {"success": True, "output": out.strip()[:500]}

    elif action == "ipsec.restart":
        out = _run(["service", "strongswan", "restart"], timeout=30)
        return {"success": True, "output": out.strip()[:500]}

    elif action == "firmware.check":
        out = _run(["opnsense-update", "-c"], timeout=60)
        return {"success": True, "output": out.strip()[:500]}

    elif action == "firmware.update":
        # Non-blocking: start in background
        subprocess.Popen(
            ["opnsense-update", "-bkp"],
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
        try:
            log.info("connecting to %s", url)
            async with ws_connect(
                url,
                additional_headers={"Authorization": f"Bearer {cfg.agent_token}"},
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5,
                max_size=10 * 1024 * 1024,  # 10MB for config backups
            ) as ws:
                log.info("connected to dashboard")
                reconnect_delay = 5  # reset on successful connect

                # Send initial handshake
                await ws.send(json.dumps({
                    "type": "hello",
                    "agent_id": cfg.agent_id,
                    "agent_version": __version__,
                    "hostname": platform.node(),
                }))

                # Run push and listen concurrently
                push_task = asyncio.create_task(_push_loop(ws, cfg))
                listen_task = asyncio.create_task(_listen_loop(ws))

                # Wait for either to finish (usually because connection dropped)
                done, pending = await asyncio.wait(
                    [push_task, listen_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
                for t in done:
                    if t.exception():
                        log.warning("task ended with error: %s", t.exception())

        except (websockets.exceptions.ConnectionClosed, OSError, Exception) as exc:
            log.warning("connection lost: %s, reconnecting in %ds", exc, reconnect_delay)

        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, 120)  # exponential backoff, max 2min


async def _push_loop(ws, cfg: Config) -> None:
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


async def _listen_loop(ws) -> None:
    """Listen for commands from the dashboard."""
    async for raw in ws:
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "command":
                action = msg.get("action", "")
                params = msg.get("params", {})
                request_id = msg.get("request_id", "")

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
        loop.run_until_complete(agent_loop(cfg))
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()
    log.info("agent stopped")


if __name__ == "__main__":
    main()
