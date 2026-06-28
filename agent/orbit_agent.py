#!/usr/bin/env python3
"""orbit agent — runs on OPNsense (FreeBSD), pushes data to the central dashboard.

Collects system metrics locally (no API needed), connects outbound via WebSocket,
and executes commands received from the dashboard.

Dependencies: Python 3.9+ only — no pip packages (stdlib WebSocket client).
Config: /usr/local/etc/orbit-agent.conf (JSON)
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import platform
import re
import signal
import ssl
import struct
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from xml.etree import ElementTree

# datetime.UTC landed in Python 3.11; alias timezone.utc so the agent also runs on
# the older Pythons FreeBSD/pfSense may ship (3.8+). Same object on 3.11+.
UTC = timezone.utc

# No external dependencies — the WebSocket client below is pure stdlib (see DR-4
# in docs/agent-architecture.md). This keeps the agent installable on locked-down
# boxes (e.g. pfSense CE) and makes self-update a single-file swap.

__version__ = "1.8.1"

# Ensure OPNsense tools are reachable — daemon(8) starts without /usr/local/sbin in PATH
os.environ["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:" + os.environ.get("PATH", "")

def _path_with_legacy(new: str, legacy: str) -> str:
    """Prefer the new path; fall back to the legacy name so an agent that
    self-updates in place (config/cache files keep their old names) keeps
    working after the opnsense-dash -> orbit rename."""
    if not os.path.exists(new) and os.path.exists(legacy):
        return legacy
    return new


CONFIG_PATH = os.environ.get("AGENT_CONFIG") or _path_with_legacy(
    "/usr/local/etc/orbit-agent.conf", "/usr/local/etc/opnsense-dash-agent.conf"
)

log = logging.getLogger("orbit-agent")

# Active config — set in main(). The HTTP relay (execute_command runs without a
# cfg arg) reads the local OPNsense API settings from here.
_CONFIG: Config | None = None

# IPsec Phase-2 ping monitors, pushed by the dashboard via a `config_update` frame
# (see _listen_loop_inner). Each entry: {tunnel_id, child_name, local_ts, remote_ts,
# source, destination, enabled, ping_count}. collect_ipsec pings each enabled match.
_PING_MONITORS: list[dict] = []


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
        # Local API relay (see §15): where the box's own REST API listens, plus
        # optional admin-pasted credentials. Empty creds → the agent provisions
        # its own key on OPNsense (when relay_provision is on).
        self.local_api_url: str = "https://127.0.0.1:4444"
        self.local_api_key: str = ""
        self.local_api_secret: str = ""
        self.relay_provision: bool = True
        # DEV ONLY: skip self-update signature verification. Lets a dev dashboard push
        # an agent with a stale/missing .sig without re-signing. Also settable via the
        # AGENT_INSECURE_SKIP_SIG=1 env var (for a locally-run agent). NEVER in prod.
        self.insecure_skip_sig: bool = False
        # True once the config file pins local_api_url — then port-discovery
        # (the box's GUI port is admin-configurable) must not override it.
        self.local_api_url_explicit: bool = False
        # Enrollment: a one-time code exchanged for an agent_token at first start
        # (so the admin needn't paste the token). enroll_url overrides the URL
        # derived from dashboard_url.
        self.enroll_code: str = ""
        self.enroll_url: str = ""
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
        # Relay creds were renamed opnsense_api_* -> local_api_*; read the old
        # key names as a fallback so pre-rename config files keep working.
        self.local_api_url = data.get("local_api_url", data.get("opnsense_api_url", self.local_api_url))
        self.local_api_key = data.get("local_api_key", data.get("opnsense_api_key", self.local_api_key))
        self.local_api_secret = data.get(
            "local_api_secret", data.get("opnsense_api_secret", self.local_api_secret)
        )
        self.relay_provision = bool(data.get("relay_provision", self.relay_provision))
        self.insecure_skip_sig = bool(data.get("insecure_skip_sig", self.insecure_skip_sig))
        self.local_api_url_explicit = "local_api_url" in data or "opnsense_api_url" in data
        self.enroll_code = data.get("enroll_code", self.enroll_code)
        self.enroll_url = data.get("enroll_url", self.enroll_url)


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


# pfSense repo dirs vary by release: new CE/Plus use /usr/local/etc, very old
# (2.6/2.7) use /usr/local/share. The active repo is the pfSense.conf symlink.
_PFSENSE_REPO_DIRS = (
    "/usr/local/etc/pfSense/pkg/repos",
    "/usr/local/share/pfSense/pkg/repos",
)
_PFSENSE_REPO_LINK = "/usr/local/etc/pkg/repos/pfSense.conf"


def _pfsense_active_conf() -> str:
    """Absolute path to the active pfSense repo .conf (the pfSense.conf symlink).

    Universal across layouts; falls back to an absolute ``pkg_repo_conf_path`` in
    config.xml. Empty on failure.
    """
    try:
        return os.readlink(_PFSENSE_REPO_LINK)
    except (OSError, AttributeError):
        pass
    try:
        if os.path.exists("/cf/conf/config.xml"):
            raw = Path("/cf/conf/config.xml").read_text(errors="replace")
            m = re.search(r"<pkg_repo_conf_path>([^<]+)</pkg_repo_conf_path>", raw)
            if m and m.group(1).strip().startswith("/"):
                return m.group(1).strip()
    except Exception:
        pass
    return ""


def _pfsense_branch_from_conf(conf_path: str) -> str:
    """Software-train id for a repo .conf, parsed from the package URL.

    The repo filename is unreliable — new boxes name it ``pfSense-repo-NNNN.conf``
    where ``NNNN`` is a meaningless index slot, old boxes use a bare
    ``pfSense-repo.conf``. The package URL inside the .conf always carries the
    train, identically to the ``.name`` descriptor::

        pkg+https://pkg.pfsense.org/pfSense_v2_8_1_amd64-core            -> 2_8_1
        pkg+https://pfsense-plus-pkg.netgate.com/pfSense_plus-v26_03_... -> 26_03

    Falls back to the ``.name`` / ``.descr`` sibling, then the filename token.
    """
    if not conf_path:
        return ""
    try:
        raw = Path(conf_path).read_text(errors="replace")
        m = re.search(r"[-_]v([0-9]+(?:_[0-9]+)+)_", raw)
        if m:
            return m.group(1)
    except OSError:
        pass
    base = re.sub(r"\.conf$", "", conf_path, flags=re.I)
    for ext in (".name", ".descr"):
        try:
            txt = Path(base + ext).read_text(errors="replace").strip()
            if txt:
                return txt
        except OSError:
            continue
    tok = re.sub(r"^pfSense-repo-?", "", conf_path.rsplit("/", 1)[-1])
    return re.sub(r"\.conf$", "", tok, flags=re.I)


def _read_pfsense_branch() -> str:
    """Active pfSense update branch / software train.

    `pfSense-upgrade -c` only ever reports updates *within the current train*; to
    reach a newer major train the branch must be switched first. Empty on failure.
    """
    return _pfsense_branch_from_conf(_pfsense_active_conf())


def _list_pfsense_branches() -> list[str]:
    """Best-effort list of train ids from the local repo .conf definitions.

    Only ``pfSense-repo*.conf`` files are real repos — the sibling ``.abi`` /
    ``.altabi`` / ``.descr`` metadata files are NOT branches (the old glob leaked
    them as junk like "0000.abi"). Each .conf resolves to its train via the URL.
    """
    try:
        for d in _PFSENSE_REPO_DIRS:
            confs = sorted(Path(d).glob("pfSense-repo*.conf"))
            if not confs:
                continue
            names: list[str] = []
            for conf in confs:
                label = _pfsense_branch_from_conf(str(conf))
                if label and label not in names:
                    names.append(label)
            return names[:12]
        return []
    except Exception:
        return []


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
        **_collect_swap(),
    }


def _collect_swap() -> dict:
    """Swap usage from ``swapinfo -k`` (summed across devices). Empty when no swap."""
    total_kb = used_kb = 0
    for line in _run(["swapinfo", "-k"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            total_kb += int(parts[1])
            used_kb += int(parts[2])
    total_mb = total_kb / 1024
    used_mb = used_kb / 1024
    pct = (used_mb / total_mb * 100) if total_mb > 0 else 0.0
    return {
        "swap_total_mb": round(total_mb, 1),
        "swap_used_mb": round(used_mb, 1),
        "swap_used_pct": round(pct, 1),
    }


# Pseudo filesystems report no meaningful capacity (or mirror another mount via
# nullfs) — they only inflate the metrics row count, so we drop them.
_PSEUDO_FSTYPES = frozenset({"devfs", "fdescfs", "procfs", "nullfs", "linprocfs", "linsysfs"})


def _zfs_pool(device: str) -> str:
    """Pool name of a ZFS dataset device (``zroot/ROOT/default`` -> ``zroot``)."""
    return device.split("/", 1)[0]


def _disk_pref(row: dict) -> tuple[int, int]:
    """Representative-pick order within a pool: the ``/`` mount wins, then shortest path."""
    mp = row["mountpoint"]
    return (0 if mp == "/" else 1, len(mp))


def _collapse_zfs_pools(rows: list[dict]) -> list[dict]:
    """Collapse each ZFS pool's datasets to one entry. Datasets share the pool's
    free space, so one row per pool suffices — but each dataset's capacity% is its
    own usage over that shared free, so they diverge (a filling ``/var/log`` reads
    high while root reads low). We keep a stable label (the ``/`` mount, else the
    shortest path) but report the pool's *worst* dataset fill, so a separate
    dataset filling up is never masked by a near-empty root. Non-ZFS rows pass
    through unchanged (order preserved; collapsed pools land at the end)."""
    passthrough = [r for r in rows if r["fstype"] != "zfs"]
    rep: dict[str, dict] = {}  # pool -> representative row (drives the label)
    worst: dict[str, float] = {}  # pool -> max used_pct across the pool
    for row in rows:
        if row["fstype"] != "zfs":
            continue
        pool = _zfs_pool(row["device"])
        worst[pool] = max(worst.get(pool, 0.0), row["used_pct"])
        if pool not in rep or _disk_pref(row) < _disk_pref(rep[pool]):
            rep = {**rep, pool: row}
    collapsed = [{**rep[pool], "used_pct": worst[pool]} for pool in rep]
    return passthrough + collapsed


def collect_disk() -> list[dict]:
    """Disk usage from ``df -T``, minus pseudo filesystems and with each ZFS pool
    collapsed to a single entry (datasets in a pool share free space)."""
    rows: list[dict] = []
    for line in _run(["df", "-T", "-h"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7 or not parts[5].endswith("%"):
            continue
        if parts[1] in _PSEUDO_FSTYPES:
            continue
        rows.append({
            "device": parts[0],
            "fstype": parts[1],
            "mountpoint": parts[6],
            "used_pct": float(parts[5].rstrip("%")),
        })
    return [
        {"device": r["device"], "mountpoint": r["mountpoint"], "used_pct": r["used_pct"]}
        for r in _collapse_zfs_pools(rows)
    ]


def _netstat_int(token: str) -> int:
    """netstat error/coll columns are '-' when the driver exposes no counter → 0."""
    try:
        return int(token)
    except (ValueError, TypeError):
        return 0


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
                # netstat -ibn columns (Idrop is optional, shifting the input side):
                #   Name Mtu Network Address Ipkts Ierrs [Idrop] Ibytes Opkts Oerrs Obytes Coll
                # Input side is stable from the LEFT (Ierrs = [5], before optional Idrop);
                # output side is stable from the RIGHT (Coll [-1], Obytes [-2], Oerrs [-3]).
                bytes_map[name] = {
                    "bytes_received": int(parts[-5]),
                    "bytes_transmitted": int(parts[-2]),
                    "in_errors": _netstat_int(parts[5]),
                    "out_errors": _netstat_int(parts[-3]),
                    "collisions": _netstat_int(parts[-1]),
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
                    **bytes_map.get(
                        name,
                        {
                            "bytes_received": 0,
                            "bytes_transmitted": 0,
                            "in_errors": 0,
                            "out_errors": 0,
                            "collisions": 0,
                        },
                    ),
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
            key = pending if pending is not None else str(len(cont))  # type: ignore[arg-type]
            child: object
            if isinstance(cont, dict):
                # swanctl --raw emits one `… event { <record> }` envelope per
                # record, every one keyed `event` at the same level — and a
                # connection name can even repeat (a passive `%any` half-open
                # responder SA alongside the established one). Disambiguate a
                # colliding section key (`key\x00N`) instead of merging, so every
                # record survives as its own section; merging collapsed the two
                # same-named SAs and let the `%any`/CREATED half-open overwrite the
                # live ESTABLISHED record's host + IKE-cookie fields.
                if key in cont:
                    n = 1
                    while f"{key}\x00{n}" in cont:
                        n += 1
                    key = f"{key}\x00{n}"
                child = {} if tok == "{" else []
                cont[key] = child
            else:
                child = {} if tok == "{" else []
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
            # strip the \x00N disambiguation suffix (see _vici_parse) from the name
            yield name.split("\x00", 1)[0], val
        else:
            yield from _iter_sections(val, markers)


def _first(v: object) -> str:
    """First element of a vici list (addresses come back as lists), else the value."""
    if isinstance(v, list):
        return str(v[0]) if v else ""
    if isinstance(v, str):
        return v
    return ""


def _clean_ts(ts: str) -> str:
    """Normalize a strongSwan traffic selector to just the subnet.

    pfSense's strongSwan appends a protocol/port part ("10.3.3.0/24|/0"); OPNsense
    omits it ("10.3.3.0/24"). Classic strongSwan uses bracket form
    ("10.3.3.0/24[tcp/80]"). The dashboard only wants the network — for display,
    and so ``ipaddress.ip_network`` (suggested ping source) doesn't choke on the
    suffix. Strip any "|proto/port" or "[proto/port]" tail.
    """
    if not ts:
        return ts
    return ts.split("|", 1)[0].split("[", 1)[0].strip()


# Marker keys unique to each record type — never present on the raw envelope.
_IKE_SA_MARKERS = frozenset({"uniqueid", "state", "local-host", "remote-host", "child-sas"})
_CONN_MARKERS = frozenset({"local_addrs", "remote_addrs", "children"})

# Real child-SA modes carry traffic; PASS/DROP are policy shunts, not tunnels.
_TUNNEL_CHILD_MODES = frozenset({"TUNNEL", "TRANSPORT", "BEET"})


def _is_shunt_conn(children: object) -> bool:
    """True when a connection is a pure policy shunt, not a real tunnel.

    pfSense auto-generates a `bypass` connection whose `bypasslan` child is
    `mode=PASS` (exclude local nets from IPsec). It creates no IKE_SA, never
    establishes, and would otherwise sit in the UI as a permanently-down row.
    A shunt has children but none in a traffic-carrying mode.
    """
    if not isinstance(children, dict):
        return False
    modes = [
        str(c.get("mode", "")).upper() for c in children.values() if isinstance(c, dict)
    ]
    return bool(modes) and not any(m in _TUNNEL_CHILD_MODES for m in modes)


def _child_rank(c: dict) -> tuple:
    """Order child SAs sharing a selector pair so the live one wins (INSTALLED, then traffic)."""
    return (c.get("state") == "INSTALLED", c.get("bytes_in", 0) + c.get("bytes_out", 0))


def _dedupe_children(children: list[dict]) -> list[dict]:
    """Collapse make-before-break child-SA rekey dups: one row per Phase-2.

    A child SA rekey briefly lists two SAs for the SAME traffic-selector pair
    (old INSTALLED + new), which would otherwise double the phase-2 count and
    bytes (e.g. "4/2"). Keep the best (INSTALLED, then most traffic) per selector
    pair. Children with no selectors can't be told apart, so they pass through.
    """
    best: dict = {}
    order: list = []
    passthrough: list[dict] = []
    for c in children:
        sel = (c.get("local_ts"), c.get("remote_ts"))
        if not (sel[0] or sel[1]):
            passthrough.append(c)
            continue
        if sel not in best:
            order.append(sel)
        cur = best.get(sel)
        if cur is None or _child_rank(c) > _child_rank(cur):
            best[sel] = c
    return [best[k] for k in order] + passthrough


def _parse_swanctl_sas(out: str) -> list[dict]:
    """Parse `swanctl --list-sas --raw` into one record per active IKE_SA.

    Phase-1 state lives at the IKE level; traffic counters and the phase-2 state
    live in the nested `child-sas` sections (deduped per selector pair, then
    summed) — see _dedupe_children for the rekey-dup collapse.
    """
    if not out.strip():
        return []
    sas = []
    for name, ike in _iter_sections(_tokenize_vici(out), _IKE_SA_MARKERS):
        children = ike.get("child-sas")
        child_rows: list[dict] = []
        if isinstance(children, dict):
            for ckey, child in children.items():
                if not isinstance(child, dict):
                    continue
                child_rows.append({
                    # The child carries its own `name` (bare UUID on OPNsense); the
                    # section key appends a "-N" instance suffix — strip it as fallback.
                    "name": _first(child.get("name")) or re.sub(r"-\d+$", "", ckey),
                    "local_ts": _clean_ts(_first(child.get("local-ts"))),
                    "remote_ts": _clean_ts(_first(child.get("remote-ts"))),
                    "state": str(child.get("state", "")).upper(),
                    "bytes_in": _to_int(child.get("bytes-in")),
                    "bytes_out": _to_int(child.get("bytes-out")),
                    # ESP SPIs — shared across both tunnel ends (A.spi_out == B.spi_in),
                    # NAT-proof identifiers for cross-instance tunnel pairing.
                    "spi_in": str(child.get("spi-in", "")),
                    "spi_out": str(child.get("spi-out", "")),
                })
        child_rows = _dedupe_children(child_rows)
        phase2_total = len(child_rows)  # distinct phase-2 (selector pairs)
        phase2_up = sum(1 for c in child_rows if c["state"] == "INSTALLED")
        bytes_in = sum(c["bytes_in"] for c in child_rows)
        bytes_out = sum(c["bytes_out"] for c in child_rows)
        sas.append({
            "name": name,  # the SA's connection name — may be stale after a config reload
            "remote": ike.get("remote-host", ""),
            "local": ike.get("local-host", ""),
            "status": ike.get("state", "unknown"),  # IKE-level, not the child's INSTALLED
            "phase2_up": phase2_up,  # installed child SAs
            "phase2_total": phase2_total,  # live child SAs (fallback "n" when no conn match)
            "seconds_established": _to_int(ike.get("established")),  # phase-1 uptime, seconds
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "unique_id": str(ike.get("uniqueid", "")),  # stable handle for --terminate --ike-id
            # IKE cookie pair — IDENTICAL on both tunnel ends (one IKE_SA, two peers),
            # NAT-proof key for cross-instance tunnel pairing.
            "ike_init_spi": str(ike.get("initiator-spi", "")),
            "ike_resp_spi": str(ike.get("responder-spi", "")),
            "children": child_rows,  # per-Phase-2 detail for the dashboard
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
        children = conn.get("children")
        if _is_shunt_conn(children):
            continue  # pfSense `bypass` passthrough policy — not a real tunnel
        child_rows: list[dict] = []
        if isinstance(children, dict):
            for ckey, child in children.items():
                if not isinstance(child, dict):
                    continue
                child_rows.append({
                    "name": ckey,  # configured child key = the Phase-2 id (UUID on OPNsense)
                    "local_ts": _clean_ts(_first(child.get("local-ts"))),
                    "remote_ts": _clean_ts(_first(child.get("remote-ts"))),
                })
        conns.append({
            "name": name,
            "local": _first(conn.get("local_addrs")),
            "remote": _first(conn.get("remote_addrs")),
            # configured phase-2 children → the "n" in "x/n up"
            "phase2_total": len(children) if isinstance(children, dict) else 0,
            "children": child_rows,  # configured Phase-2 selectors (up or down)
        })
    return conns


def _ipsec_descriptions(config_path: str = "/conf/config.xml") -> dict[str, str]:
    """Map swanctl connection name -> human description from config.xml.

    swanctl only knows opaque connection names; the user-facing name lives in
    config.xml. Returns {} when the file is absent or unparseable (caller then
    falls back to the connection name).
    """
    try:
        root = ElementTree.parse(config_path).getroot()
    except (OSError, ElementTree.ParseError):
        return {}
    descriptions: dict[str, str] = {}
    # OPNsense: <Swanctl><Connections><Connection uuid="…"><description>; the
    # swanctl connection name is the UUID.
    for connections in root.iter("Connections"):
        for conn in connections.findall("Connection"):
            uuid = conn.get("uuid")
            desc = (conn.findtext("description") or "").strip()
            if uuid and desc:
                descriptions[uuid] = desc
    # pfSense: <ipsec><phase1><ikeid>N</ikeid><descr>name</descr>; the swanctl
    # connection is named "conN". iter("phase1") only — phase2 entries also carry
    # an <ikeid> + <descr> ("name-p2") and would otherwise clobber the tunnel name.
    for phase1 in root.iter("phase1"):
        ikeid = (phase1.findtext("ikeid") or "").strip()
        desc = (phase1.findtext("descr") or "").strip()
        if ikeid and desc:
            descriptions[f"con{ikeid}"] = desc
    return descriptions


def _child_row(cc: dict | None, sc: dict | None) -> dict:
    """One merged Phase-2 row: configured selectors annotated with live SA state."""
    cc = cc or {}
    sc = sc or {}
    return {
        "name": cc.get("name") or sc.get("name") or "",
        "local_ts": cc.get("local_ts") or sc.get("local_ts") or "",
        "remote_ts": cc.get("remote_ts") or sc.get("remote_ts") or "",
        "state": sc.get("state", ""),  # "" = configured but no live child SA (down)
        "bytes_in": sc.get("bytes_in", 0),
        "bytes_out": sc.get("bytes_out", 0),
        "spi_in": sc.get("spi_in", ""),  # live ESP SPIs (empty when down) — for pairing
        "spi_out": sc.get("spi_out", ""),
    }


def _merge_children(conn_children: list[dict], sa_children: list[dict]) -> list[dict]:
    """Overlay live child SAs onto configured Phase-2 entries.

    Match by name first, then by traffic-selector pair (the child name drifts when
    OPNsense regenerates UUIDs on apply). Live children with no configured match
    are still surfaced so nothing disappears.
    """
    sa_by_name = {c["name"]: c for c in sa_children if c.get("name")}
    sa_by_sel = {(c.get("local_ts"), c.get("remote_ts")): c for c in sa_children}
    out: list[dict] = []
    used: set[int] = set()
    for cc in conn_children:
        sc = sa_by_name.get(cc.get("name")) or sa_by_sel.get(
            (cc.get("local_ts"), cc.get("remote_ts"))
        )
        if sc is not None:
            used.add(id(sc))
        out.append(_child_row(cc, sc))
    for sc in sa_children:
        if id(sc) not in used:
            out.append(_child_row(None, sc))
    return out


def _tunnel(name: str, conn: dict | None, sa: dict | None, descriptions: dict[str, str]) -> dict:
    """Build one dashboard tunnel row, preferring live SA data when present."""
    conn = conn or {}
    children = _merge_children(conn.get("children", []), (sa or {}).get("children", []))
    base = {
        "id": name,  # connection name → `swanctl --initiate --ike <id>`
        "description": descriptions.get(name) or name,  # human name, else the UUID
        "children": children,  # per-Phase-2 detail (selectors + live state)
    }
    if sa is not None:
        return {
            **base,
            "remote": sa["remote"] or conn.get("remote", ""),
            "local": sa["local"] or conn.get("local", ""),
            "status": sa["status"],
            "phase2_up": sa.get("phase2_up", 0),
            # prefer the configured child count from the conn; fall back to live SAs
            "phase2_total": conn.get("phase2_total") or sa.get("phase2_total", 0),
            "seconds_established": sa.get("seconds_established", 0),
            "bytes_in": sa["bytes_in"],
            "bytes_out": sa["bytes_out"],
            "unique_id": sa["unique_id"],  # → `swanctl --terminate --ike-id <unique_id>`
            "ike_init_spi": sa.get("ike_init_spi", ""),  # shared IKE cookie pair (pairing)
            "ike_resp_spi": sa.get("ike_resp_spi", ""),
        }
    return {
        **base,
        "remote": conn.get("remote", ""),
        "local": conn.get("local", ""),
        "status": "down",
        "phase2_up": 0,
        "phase2_total": conn.get("phase2_total", 0),
        "seconds_established": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "unique_id": "",
        "ike_init_spi": "",  # down: no live IKE_SA → no SPI (pair via IP fallback)
        "ike_resp_spi": "",
    }


def _sa_rank(sa: dict) -> tuple:
    """Order SAs that share a name/endpoint so the live one wins a tie.

    During an IKE rekey (make-before-break) strongSwan briefly lists two SAs for
    one connection: the old ESTABLISHED SA still holding the INSTALLED child (and
    its traffic) and a new CONNECTING SA mid-handshake. Indexing last-wins would
    surface the transient CONNECTING SA — the dashboard then shows a red tunnel
    that is actually up and passing bytes. Prefer ESTABLISHED, then an installed
    child, then the one carrying traffic.
    """
    return (
        str(sa.get("status", "")).upper() == "ESTABLISHED",
        sa.get("phase2_up", 0),
        sa.get("bytes_in", 0) + sa.get("bytes_out", 0),
    )


def _index_best(sas: list[dict], key) -> dict:
    """Build a {key: sa} index keeping the highest-ranked SA per key."""
    best: dict = {}
    for s in sas:
        k = key(s)
        cur = best.get(k)
        if cur is None or _sa_rank(s) > _sa_rank(cur):
            best[k] = s
    return best


def _merge_ipsec(conns: list[dict], sas: list[dict], descriptions: dict[str, str]) -> list[dict]:
    """Overlay live SA status onto the configured connections.

    Match a configured conn to an active SA by name first, then by endpoint pair
    (the SA name can drift from the conn name after an OPNsense config reload).
    Active SAs with no matching conn are still surfaced so nothing disappears.
    """
    sa_by_name = _index_best(sas, lambda s: s["name"])
    sa_by_ep = _index_best(sas, lambda s: (s["local"], s["remote"]))

    tunnels = []
    used_names: set[str] = set()
    used_eps: set[tuple[str, str]] = set()
    for c in conns:
        sa = sa_by_name.get(c["name"]) or sa_by_ep.get((c["local"], c["remote"]))
        if sa is not None:
            used_names.add(sa["name"])
            used_eps.add((sa["local"], sa["remote"]))
        tunnels.append(_tunnel(c["name"], c, sa, descriptions))
    # Surface orphan SAs (no matching conn) so nothing disappears — but only the
    # best SA per name/endpoint, and never one already consumed above (a rekey
    # dup shares the matched SA's endpoint even when its name drifted).
    for s in sas:
        ep = (s["local"], s["remote"])
        if s["name"] in used_names or ep in used_eps:
            continue
        used_names.add(s["name"])
        used_eps.add(ep)
        best = sa_by_name.get(s["name"], s)
        tunnels.append(_tunnel(best["name"], None, best, descriptions))
    return tunnels


def _box_inet_addrs() -> list[str]:
    """IPv4 addresses this box owns (from ifconfig) — used to suggest a ping source."""
    return re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", _run(["ifconfig"]))


def _suggest_source(local_ts: str, box_ips: list[str]) -> str:
    """A box-owned IP inside the Phase-2 local selector, or "" if none.

    ``ping -S`` requires a source the box actually owns *and* that falls in the
    local selector for the packet to enter the tunnel — surface a valid default.
    """
    if not local_ts:
        return ""
    try:
        net = ipaddress.ip_network(local_ts, strict=False)
    except ValueError:
        return ""
    for ip in box_ips:
        try:
            if ipaddress.ip_address(ip) in net:
                return ip
        except ValueError:
            continue
    return ""


def _ping_once(source: str, dest: str, count: int) -> dict:
    """Ping ``dest`` from ``source`` (FreeBSD ping). Classify ok / fail / error.

    fail = no reply (the tunnel-not-passing signal); error = the probe could not
    run (bad/unassignable source, unresolvable host) — a misconfiguration, not an
    outage. ``-S`` binds the source; an unowned source fails immediately with no
    loss summary, which we read as error.
    """
    if not dest:
        return {"ping_state": "error", "ping_loss_pct": None, "ping_rtt_ms": None}
    # Pace packets 0.3s apart (sub-second interval needs root, which the agent has)
    # so a healthy tunnel answers in well under a second instead of the default
    # 1s/packet. ``-t`` caps the run: all probes are sent within (count-1)*0.3s, so
    # max(count, 2) still leaves >1s of reply slack while a dead tunnel waits out a
    # shorter deadline than the old max(count+1, 3).
    timeout = max(count, 2)
    cmd = ["ping", "-n", "-i", "0.3", "-c", str(count), "-t", str(timeout)]
    if source:
        cmd += ["-S", source]
    cmd.append(dest)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except (subprocess.TimeoutExpired, OSError):
        return {"ping_state": "error", "ping_loss_pct": None, "ping_rtt_ms": None}
    out = (r.stdout or "") + (r.stderr or "")
    m = re.search(r"([\d.]+)%\s*packet loss", out)
    if m is None:
        # No summary line → the probe never ran (e.g. "bind: Can't assign requested
        # address", "cannot resolve") → misconfiguration.
        return {"ping_state": "error", "ping_loss_pct": None, "ping_rtt_ms": None}
    loss = float(m.group(1))
    rtt: float | None = None
    rm = re.search(r"=\s*[\d.]+/([\d.]+)/", out)  # min/avg/max/stddev → avg
    if rm:
        rtt = float(rm.group(1))
    return {
        "ping_state": "ok" if loss < 100 else "fail",
        "ping_loss_pct": loss,
        "ping_rtt_ms": rtt,
    }


def _match_monitor(tunnel: dict, child: dict, monitors: list[dict]) -> dict | None:
    """Find an enabled monitor for this child: by name, selector pair, or whole-tunnel."""
    for m in monitors:
        if not m.get("enabled", True) or m.get("tunnel_id") != tunnel.get("id"):
            continue
        child_name = m.get("child_name") or ""
        if not child_name:  # "" applies to the whole tunnel
            return m
        if child_name == child.get("name"):
            return m
        if (
            m.get("local_ts")
            and m.get("local_ts") == child.get("local_ts")
            and m.get("remote_ts") == child.get("remote_ts")
        ):
            return m
    return None


def run_ping_checks(tunnels: list[dict], monitors: list[dict], now_iso: str) -> None:
    """Run each configured Phase-2 ping concurrently; annotate the matching child."""
    jobs: list[tuple[dict, str, str, int]] = []
    for t in tunnels:
        for ch in t.get("children", []):
            m = _match_monitor(t, ch, monitors)
            if m is None:
                continue
            jobs.append((ch, m.get("source", ""), m.get("destination", ""), int(m.get("ping_count") or 3)))
    if not jobs:
        return
    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as pool:
        futures = {pool.submit(_ping_once, src, dst, cnt): ch for ch, src, dst, cnt in jobs}
        for future, ch in futures.items():
            try:
                ch.update(future.result())
            except Exception:  # noqa: BLE001 — one bad ping must not sink the push
                ch.update({"ping_state": "error", "ping_loss_pct": None, "ping_rtt_ms": None})
            ch["ping_ts"] = now_iso


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
                "phase2_up": 1 if match.group(3) == "INSTALLED" else 0,
                "phase2_total": 1,
                "seconds_established": 0,  # statusall format carries no uptime here
                "bytes_in": 0,
                "bytes_out": 0,
                "unique_id": match.group(2),
            })

    # Annotate each Phase-2 with a suggested ping source, then run configured pings.
    box_ips = _box_inet_addrs()
    for t in tunnels:
        for ch in t.get("children", []):
            ch.setdefault("ping_state", "none")
            ch["suggested_source"] = _suggest_source(ch.get("local_ts", ""), box_ips)
    run_ping_checks(tunnels, _PING_MONITORS, datetime.now(UTC).isoformat())

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


# Track when we last ran a full firmware update check (network call). The verdict
# is cached because pushes happen every ~30s but the network check only every 10
# min — without the cache the cheap interim pushes would blank a detected update.
_last_fw_check_ts: float = 0.0
_last_fw_verdict: dict = {}


def _opnsense_series() -> str:
    """OPNsense major series (e.g. '26.1'), reported to the dashboard as branch/train."""
    try:
        data = json.loads(_run(["opnsense-version"]))
        return data.get("product_series") or data.get("CORE_SERIES", "")
    except Exception:
        return ""


def _opnsense_update_check(installed: str) -> tuple[bool, str, str]:
    """Detect an OPNsense update. Returns ``(upgrade_available, latest, output)``.

    ``opnsense-update -c`` only reports base-set (release) upgrades, so it MISSES
    pkg point releases — e.g. 26.1.9 -> 26.1.10, which ship as the ``opnsense``
    package. Refresh the repo catalogue, then compare the installed vs the remote
    ``opnsense`` package version: that is the authoritative point-release signal
    and matches what the GUI firmware check shows. ``pkg rquery`` reads the local
    catalogue cache, so the ``pkg update`` refresh is what makes this work — a
    stale cache otherwise returns an empty remote version (false "up to date").
    """
    out = _run(["/usr/local/sbin/opnsense-update", "-c"], timeout=30)
    low = out.lower()
    upgrade_available = "can be updated" in low or "updates available" in low
    latest = installed
    try:
        _run(["pkg", "update", "-q"], timeout=60)  # refresh catalogue (lock-busy → next cycle)
        cur = _run(["pkg", "query", "%v", "opnsense"]).strip()
        remote = _run(["pkg", "rquery", "%v", "opnsense"]).strip()
        if remote:
            latest = remote
        if cur and remote and cur != remote:
            upgrade_available = True
            if not out or "up to date" in low:
                out = f"{cur} can be updated to {remote}"
    except Exception:
        pass
    return upgrade_available, latest, out


def _store_fw_verdict(
    branch: str, known_branches: list, upgrade_available: bool, latest: str, out: str
) -> dict:
    """Cache the firmware verdict + restart the 10-min throttle window.

    Both the periodic push and the manual ``firmware.check`` go through here so a
    just-run check is reflected by the cheap interim pushes (otherwise a throttled
    push would overwrite a fresh manual check with the stale cached verdict).
    """
    global _last_fw_check_ts, _last_fw_verdict
    _last_fw_verdict = {
        "branch": branch,
        "known_branches": known_branches,
        "upgrade_available": upgrade_available,
        "product_latest": latest,
        "update_check_output": out.strip()[:500],
    }
    _last_fw_check_ts = time.monotonic()
    return _last_fw_verdict


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
    """Firmware version on every push; update check every 10 minutes (per platform).

    Only ``product_version`` is recomputed every push (a cheap local file read); the
    branch + upgrade verdict come from the cached last network check so the frequent
    interim pushes never blank a detected update (see ``_last_fw_verdict``).
    """
    pfsense = detect_platform() == "pfsense"
    version = _read_pfsense_version() if pfsense else _read_opnsense_version()

    now = time.monotonic()
    if _last_fw_verdict and now - _last_fw_check_ts < 600:
        return {"product_version": version, **_last_fw_verdict}

    if pfsense:
        branch = _read_pfsense_branch()
        known_branches = _list_pfsense_branches()
        out = _run(["/usr/local/sbin/pfSense-upgrade", "-c"], timeout=60)
        upgrade_available = _pfsense_update_available(out)
        latest = version  # pfSense-upgrade reports no target version
    else:
        branch = _opnsense_series()
        known_branches = []
        upgrade_available, latest, out = _opnsense_update_check(version)

    verdict = _store_fw_verdict(branch, known_branches, upgrade_available, latest, out)
    return {"product_version": version, **verdict}


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


def collect_loadavg() -> dict:
    """1/5/15-minute load average from ``sysctl vm.loadavg`` ('{ 0.37 0.29 0.26 }'),
    plus the CPU core count (``hw.ncpu``) so the dashboard can normalise load per
    core. ``cores`` is 0 when the count can't be read (then the load check skips)."""
    try:
        cores = int(_run(["sysctl", "-n", "hw.ncpu"]).strip())
    except (ValueError, IndexError):
        cores = 0
    nums = _run(["sysctl", "-n", "vm.loadavg"]).strip().strip("{}").split()
    try:
        return {
            "one": float(nums[0]),
            "five": float(nums[1]),
            "fifteen": float(nums[2]),
            "cores": cores,
        }
    except (ValueError, IndexError):
        return {"one": 0.0, "five": 0.0, "fifteen": 0.0, "cores": cores}


def collect_pf() -> dict:
    """pf state-table usage: current states vs the hard limit (``pfctl``, needs root).

    Both OPNsense and pfSense run pf, so the same parse works on each. State-table
    exhaustion is a real outage mode that is otherwise invisible.
    """
    current = 0
    for line in _run(["pfctl", "-si"]).splitlines():
        m = re.search(r"current entries\s+(\d+)", line)
        if m:
            current = int(m.group(1))
            break
    limit = 0
    for line in _run(["pfctl", "-sm"]).splitlines():
        m = re.search(r"states\s+hard limit\s+(\d+)", line)
        if m:
            limit = int(m.group(1))
            break
    pct = (current / limit * 100) if limit > 0 else 0.0
    return {"states_current": current, "states_limit": limit, "states_pct": round(pct, 1)}


def collect_ntp() -> dict:
    """NTP sync state via ``ntpq``. ``synced`` is True only once a clock is usable
    (stratum < 16); a freshly-booted box reporting stratum 16 is NOT an error — the
    dashboard check treats unsynced as a soft state, never CRIT.

    Reading association 0 (``rv 0``) is more robust than parsing peer-table tally
    codes. ntpd ships by default on both platforms.
    """
    rv = _run(["ntpq", "-c", "rv 0"], timeout=8)
    stratum = -1
    offset_ms = 0.0
    jitter_ms = 0.0
    m = re.search(r"stratum=(\d+)", rv)
    if m:
        stratum = int(m.group(1))
    m = re.search(r"offset=([-\d.]+)", rv)
    if m:
        offset_ms = float(m.group(1))
    m = re.search(r"sys_jitter=([-\d.]+)", rv)
    if m:
        jitter_ms = float(m.group(1))
    peer = ""
    for line in _run(["ntpq", "-pn"], timeout=8).splitlines():
        if line.startswith("*"):  # '*' tally = the currently selected sys.peer
            fields = line[1:].split()
            peer = fields[0] if fields else ""
            break
    return {
        "synced": 0 <= stratum < 16,
        "stratum": stratum,
        "offset_ms": round(offset_ms, 3),
        "jitter_ms": round(jitter_ms, 3),
        "peer": peer,
    }


def collect_config() -> dict:
    """Last config-change metadata from ``/conf/config.xml`` <revision> (both platforms).

    pfSense wraps description/username in CDATA; ElementTree reads that transparently.
    """
    try:
        root = ElementTree.parse(_CONFIG_XML).getroot()
    except (OSError, ElementTree.ParseError):
        return {}
    rev = root.find("./revision")
    if rev is None:
        return {}
    raw_time = (rev.findtext("time") or "").strip()
    iso = ""
    try:
        if raw_time:
            iso = datetime.fromtimestamp(float(raw_time), UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        iso = ""
    return {
        "revision_time": iso,
        "revision_description": (rev.findtext("description") or "").strip()[:300],
        "revision_user": (rev.findtext("username") or "").strip()[:128],
    }


def collect_services() -> list[dict]:
    """Per-service running state. OPNsense: ``configctl service list``;
    pfSense: ``get_services()`` via PHP (no configctl there)."""
    if detect_platform() == "pfsense":
        return _collect_services_pfsense()
    return _collect_services_opnsense()


def _collect_services_opnsense() -> list[dict]:
    out = _run(["configctl", "service", "list"], timeout=15)
    start = out.find("[")
    if start < 0:
        return []
    try:
        data = json.loads(out[start:])
    except json.JSONDecodeError:
        return []
    services = []
    for s in data:
        if not isinstance(s, dict) or not s.get("name"):
            continue
        # ``status`` is a human string: "<name> is running as pid N." / "... is not running."
        low = str(s.get("status", "")).lower()
        running = "running" in low and "not running" not in low
        services.append({
            "name": s.get("name", ""),
            "description": s.get("description", ""),
            "running": running,
        })
    return services


_PFSENSE_SVC_PHP = (
    'require_once("globals.inc"); require_once("service-utils.inc"); '
    "$out=array(); foreach (get_services() as $s) { $n=isset($s['name'])?$s['name']:''; "
    "if(!$n) continue; "
    "$out[]=array('name'=>$n,'description'=>isset($s['description'])?$s['description']:'',"
    "'running'=>is_service_running($n,$s)?true:false); } echo json_encode($out);"
)


def _collect_services_pfsense() -> list[dict]:
    out = _run(["php", "-r", _PFSENSE_SVC_PHP], timeout=15)
    start = out.find("[")
    if start < 0:
        return []
    try:
        data = json.loads(out[start:])
    except json.JSONDecodeError:
        return []
    return [
        {
            "name": s.get("name", ""),
            "description": s.get("description", ""),
            "running": bool(s.get("running", False)),
        }
        for s in data
        if isinstance(s, dict) and s.get("name")
    ]


def collect_certificates() -> list[dict]:
    """Certificate expiry from ``/conf/config.xml`` <cert>/<ca>. The agent is
    stdlib-only (no x509 parser), so each PEM is piped through ``openssl x509``.
    Works on both platforms; the GUI cert is flagged via <system><webgui><ssl-certref>.
    """
    try:
        root = ElementTree.parse(_CONFIG_XML).getroot()
    except (OSError, ElementTree.ParseError):
        return []
    gui_ref = (root.findtext("./system/webgui/ssl-certref") or "").strip()
    out: list[dict] = []
    elements = [("cert", e) for e in root.findall("./cert")]
    elements += [("ca", e) for e in root.findall("./ca")]
    for kind, el in elements:
        crt_b64 = (el.findtext("crt") or "").strip()
        if not crt_b64:
            continue
        try:
            pem = base64.b64decode(crt_b64)
        except ValueError:  # binascii.Error is a ValueError subclass
            continue
        info = _openssl_cert_info(pem)
        if info is None:
            continue
        refid = (el.findtext("refid") or "").strip()
        out.append({
            "refid": refid,
            "name": (el.findtext("descr") or "").strip() or refid or "(unnamed)",
            "type": kind,
            "is_gui": bool(gui_ref) and refid == gui_ref,
            **info,
        })
    return out


def _openssl_cert_info(pem: bytes) -> dict | None:
    """Parse one PEM cert via ``openssl x509`` → expiry + subject/issuer, or None."""
    try:
        r = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-subject", "-issuer"],
            input=pem,
            capture_output=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None
    txt = r.stdout.decode(errors="replace")
    m = re.search(r"notAfter=(.+)", txt)
    if not m:
        return None
    # openssl -enddate is always GMT, e.g. "Jun 28 14:36:28 2027 GMT".
    raw = m.group(1).strip().removesuffix(" GMT").strip()
    try:
        not_after = datetime.strptime(raw, "%b %d %H:%M:%S %Y").replace(tzinfo=UTC)
    except ValueError:
        return None
    days = (not_after - datetime.now(UTC)).days
    subj = re.search(r"subject=(.+)", txt)
    issuer = re.search(r"issuer=(.+)", txt)
    return {
        "not_after": not_after.isoformat(),
        "days_remaining": days,
        "subject": (subj.group(1).strip() if subj else "")[:200],
        "issuer": (issuer.group(1).strip() if issuer else "")[:200],
    }


def collect_all() -> dict:
    """Full snapshot of this OPNsense instance."""
    return {
        "ts": datetime.now(UTC).isoformat(),
        "system": collect_system_info(),
        "uptime": collect_uptime(),
        "loadavg": collect_loadavg(),
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disks": collect_disk(),
        "pf": collect_pf(),
        "ntp": collect_ntp(),
        "interfaces": collect_interfaces(),
        "gateways": collect_gateways(),
        "ipsec": collect_ipsec(),
        "firmware": collect_firmware(),
        "firewall_log": collect_firewall_log(30),
        "config": collect_config(),
        "services": collect_services(),
        "certificates": collect_certificates(),
    }


# =============================================================================
# Local API relay (see docs/agent-architecture.md §15)
#
# The dashboard reaches a NAT'd firewall's REST API by tunneling HTTP over the
# existing agent WebSocket: it sends an `http.relay` command, the agent forwards
# the request to the box's own API (https://127.0.0.1:4444 by default) and returns
# the response. The dashboard holds NO firewall credentials — the agent, already
# root on the box, injects HTTP Basic auth locally. On OPNsense it self-provisions
# that key (OPNsense's own User model mints it, computing the bcrypt secret), so
# the admin pastes nothing. The relay user gets page-all; the trust boundary is
# the dashboard (the relay route requires an admin session).
# =============================================================================

_APIKEY_CACHE = os.environ.get("AGENT_APIKEY_CACHE") or _path_with_legacy(
    "/usr/local/etc/orbit-agent.apikey", "/usr/local/etc/opnsense-dash-agent.apikey"
)

# Hop-by-hop headers (RFC 7230 §6.1) plus auth/host/cookie — never forwarded.
_RELAY_DROP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "authorization", "cookie",
})

# OPNsense's own User model mints the key (and the crypt-SHA512 secret) — we never
# hash anything ourselves. Idempotent: reuses the `orbit` user, and DROPS every
# existing key before adding exactly one, so a lost agent cache (which re-triggers
# provisioning) can't leave orphaned keys piling up on the user.
_PROVISION_PHP = r"""<?php
require_once('legacy_bindings.inc');
use OPNsense\Core\Config;
use OPNsense\Auth\User;
$username = 'orbit';
Config::getInstance()->lock();
$mdl = new User();
$user = $mdl->getUserByName($username);
if (!$user) {
    $user = $mdl->user->Add();
    $user->name = $username;
    $user->scope = 'automation';
    $user->descr = 'STYLiTE Orbit relay (auto-provisioned)';
    $pw = random_bytes(50);
    while (($i = strpos($pw, "\0")) !== false) { $pw[$i] = random_bytes(1); }
    $hash = $mdl->generatePasswordHash($pw);
    if ($hash !== false && strpos($hash, '$') === 0) { $user->password = $hash; }
}
$user->priv = 'page-all';
foreach ($user->apikeys->all() as $row) { $user->apikeys->del($row['key']); }
$pair = $user->apikeys->add();
$mdl->serializeToConfig(false, true);
Config::getInstance()->save();
echo json_encode($pair);
"""


_CONFIG_XML = "/conf/config.xml"


def _discover_local_api_url() -> str | None:
    """Derive the box's own GUI/API URL from config.xml `<system><webgui>`.

    The GUI port is admin-configurable (commonly moved off 443 — e.g. 4444 on the
    test boxes), so the relay must not hardcode it (see TODO.md). Returns None when
    the file/section is unreadable, so the caller keeps its configured default.
    """
    try:
        root = ElementTree.parse(_CONFIG_XML).getroot()
    except (OSError, ElementTree.ParseError):
        return None
    webgui = root.find("./system/webgui")
    if webgui is None:
        return None
    protocol = (webgui.findtext("protocol") or "https").strip().lower() or "https"
    port = (webgui.findtext("port") or "").strip()
    if not port:
        port = "443" if protocol == "https" else "80"
    return f"{protocol}://127.0.0.1:{port}"


def _apply_port_discovery(cfg: Config) -> None:
    """Point cfg.local_api_url at the box's real GUI port, unless config pins it."""
    if cfg.local_api_url_explicit:
        return
    discovered = _discover_local_api_url()
    if discovered and discovered != cfg.local_api_url:
        log.info("relay: discovered local API at %s", discovered)
        cfg.local_api_url = discovered


def _write_private(path: Path, data: str) -> None:
    """Write a secret file mode 0600 from creation — no world-readable window.

    `Path.write_text` creates with the process umask (0644 under root's default),
    leaving a window before any chmod where a local non-root process could read an
    admin credential. Open O_CREAT with 0600 and fchmod to enforce it on a
    pre-existing file too; a failure to lock perms must raise, not be swallowed.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data.encode())
    finally:
        os.close(fd)


def _write_root_script(content: str, suffix: str) -> str:
    """Write a root-executed helper script to a fresh, unpredictable /tmp file.

    Returns the path. ``mkstemp`` creates with O_CREAT|O_EXCL and a random name
    (mode 0600), so a local unprivileged user cannot pre-plant a symlink at a
    predictable path and redirect the root write/exec — FreeBSD has no
    ``fs.protected_symlinks`` equivalent, so a fixed /tmp name would be vulnerable.
    """
    fd, path = tempfile.mkstemp(prefix="orbit-", suffix=suffix, dir="/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    return path


def _load_cached_credentials() -> tuple[str, str] | None:
    """Return the (key, secret) the agent provisioned earlier, or None."""
    try:
        data = json.loads(Path(_APIKEY_CACHE).read_text())
    except (OSError, ValueError):
        return None
    key, secret = data.get("key"), data.get("secret")
    return (key, secret) if key and secret else None


def _cache_credentials(key: str, secret: str) -> None:
    """Persist the provisioned key:secret (mode 600 — it is an admin credential)."""
    _write_private(Path(_APIKEY_CACHE), json.dumps({"user": "orbit", "key": key, "secret": secret}))


# pfSense has no native REST API — the dashboard-triggered relay.enable installs the
# community pfRest package (pfrest/pfSense-pkg-RESTAPI), whose default auth is
# BasicAuth against the pfSense local user DB. So here we just create a dedicated
# `orbit` pfSense user with page-all and a known bcrypt password, and return it as
# the (key, secret) = (username, password) pair — the relay injects the SAME HTTP
# Basic auth as for OPNsense, only the credential differs. Idempotent: resets the
# password if the user already exists. (local_user_set_password expects an
# ['item'=>…] wrapper and silently no-ops otherwise, so we set bcrypt-hash directly.)
_PROVISION_PF_PHP = r"""<?php
require_once("config.inc");
require_once("auth.inc");
$pw = base64_encode(random_bytes(24));
$hash = password_hash($pw, PASSWORD_BCRYPT);
$users = config_get_path("system/user", []);
$found = false;
foreach ($users as $i => $u) {
    if (($u['name'] ?? '') === 'orbit') {
        $users[$i]['bcrypt-hash'] = $hash;
        $users[$i]['priv'] = ['page-all'];
        local_user_set($users[$i]);
        $found = true;
        break;
    }
}
if (!$found) {
    $uid = (int) config_get_path("system/nextuid");
    $user = ['name'=>'orbit','descr'=>'STYLiTE Orbit relay (auto-provisioned)',
             'scope'=>'user','uid'=>(string)$uid,'priv'=>['page-all'],
             'expires'=>'','ipsecpsk'=>'','bcrypt-hash'=>$hash];
    $users[] = $user;
    config_set_path("system/nextuid", (string)($uid + 1));
    local_user_set($user);
}
config_set_path("system/user", $users);
write_config("orbit relay user");
echo json_encode(["key"=>"orbit","secret"=>$pw]);
"""

# pfRest release assets are per-pfSense-version (pfSense-<ver>-pkg-RESTAPI.pkg). We
# track `latest` — the project ships an asset per supported version; pin instead if
# reproducibility matters (it then needs bumping per pfSense release).
_PFREST_RELEASE_BASE = "https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download"
_PFREST_CLI = "/usr/local/bin/pfsense-restapi"


def _pfrest_installed() -> bool:
    """True when the pfRest REST API package is installed (its CLI is present)."""
    return Path(_PFREST_CLI).exists()


def _install_pfrest() -> bool:
    """Install the pfRest package from its GitHub release (pfSense only, needs egress)."""
    if _pfrest_installed():
        return True
    version = _read_pfsense_version().split("-")[0]  # "2.8.1-RELEASE" -> "2.8.1"
    if not version:
        return False
    url = f"{_PFREST_RELEASE_BASE}/pfSense-{version}-pkg-RESTAPI.pkg"
    log.warning("relay: installing pfRest package from %s", url)
    _run(["pkg-static", "add", url], timeout=180)
    return _pfrest_installed()


def _run_provision_php(php: str) -> tuple[str, str] | None:
    """Run a provisioning PHP that prints {"key","secret"}, cache + return the pair."""
    tmp = f"{_APIKEY_CACHE}.provision.php"
    try:
        Path(tmp).write_text(php)
        out = _run(["/usr/local/bin/php", tmp], timeout=30)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp)
    try:
        pair = json.loads(out.strip())
    except ValueError:
        log.error("relay: provisioning produced no valid key pair")
        return None
    key, secret = pair.get("key"), pair.get("secret")
    if not key or not secret:
        return None
    _cache_credentials(key, secret)
    return key, secret


# pfSense (unlike OPNsense / stock FreeBSD) does NOT auto-start rcvar services from
# /usr/local/etc/rc.d/ at boot — they are started by its PHP boot framework. So the
# installed rc.d script + ``orbit_agent_enable=YES`` never fires after a reboot and
# the agent stays down. Register pfSense's native ``afterbootupshellcmd`` boot hook
# (run at the end of rc.bootup, network up) to start us. Idempotent + non-destructive.
_PF_BOOT_CMD = "/usr/local/etc/rc.d/orbit_agent onestart"
_PF_PERSIST_PHP = r"""<?php
require_once("config.inc");
$cmd = "__CMD__";
$cur = (string) config_get_path("system/afterbootupshellcmd", "");
if (strpos($cur, "orbit_agent") !== false) { echo "unchanged"; exit; }
$new = ($cur === "") ? $cmd : ($cur . "; " . $cmd);
config_set_path("system/afterbootupshellcmd", $new);
write_config("orbit: persist agent autostart across reboot");
echo "set";
"""


def _ensure_pfsense_boot_persistence() -> None:
    """Make the agent survive a pfSense reboot (idempotent, pfSense only, best-effort).

    Already-deployed agents self-heal on the next deploy: the self-updated code
    runs this at startup and registers the boot hook. Skips when already present
    and appends rather than clobbering any existing afterbootupshellcmd.
    """
    if detect_platform() != "pfsense":
        return
    try:
        tmp = _write_root_script(_PF_PERSIST_PHP.replace("__CMD__", _PF_BOOT_CMD), ".php")
    except OSError as exc:
        log.warning("pfsense: could not write boot persistence script: %s", exc)
        return
    try:
        out = _run(["/usr/local/bin/php", tmp], timeout=30).strip()
        if out == "set":
            log.warning("pfsense: registered afterbootupshellcmd for reboot persistence")
        elif out == "unchanged":
            log.debug("pfsense: boot persistence already registered")
        else:
            log.warning("pfsense: boot persistence php returned unexpected: %r", out[:120])
    except OSError as exc:
        log.warning("pfsense: could not set boot persistence: %s", exc)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def _provision_api_credentials() -> tuple[str, str] | None:
    """Mint relay credentials for the local platform, cache them, return the pair.

    OPNsense: an API key via its own User model (key+secret). pfSense: a dedicated
    `orbit` local user for the pfRest package's BasicAuth (username+password) — but
    ONLY if pfRest is already installed (the install is an explicit relay.enable
    step, never an automatic side-effect). Returns None on unknown platform/failure.
    """
    platform_name = detect_platform()
    if platform_name == "opnsense":
        pair = _run_provision_php(_PROVISION_PHP)
        if pair:
            log.warning("relay: provisioned OPNsense API key for user 'orbit' (page-all)")
        return pair
    if platform_name == "pfsense":
        if not _pfrest_installed():
            return None  # relay not enabled yet — don't install here
        pair = _run_provision_php(_PROVISION_PF_PHP)
        if pair:
            log.warning("relay: provisioned pfSense relay user 'orbit' (page-all)")
        return pair
    return None


def _relay_enable() -> dict:
    """Dashboard-triggered: make the relay usable on this box, return a result dict.

    pfSense: install the pfRest package (egress) THEN provision. OPNsense: just
    provision (no package, no egress). Idempotent.
    """
    platform_name = detect_platform()
    if platform_name == "pfsense" and not _install_pfrest():
        return {"success": False, "output": "pfRest package install failed"}
    creds = _provision_api_credentials()
    if creds is None:
        return {"success": False, "output": "relay credential provisioning failed"}
    return {"success": True, "output": f"relay enabled ({platform_name})"}


def _ensure_api_credentials(cfg: Config) -> tuple[str, str] | None:
    """Resolve relay credentials.

    Precedence: admin-pasted config creds > cached provisioned pair > fresh
    auto-provision (OPNsense, when relay_provision is on). None → relay can't auth.
    """
    if cfg.local_api_key and cfg.local_api_secret:
        return cfg.local_api_key, cfg.local_api_secret
    cached = _load_cached_credentials()
    if cached:
        return cached
    if cfg.relay_provision:
        return _provision_api_credentials()
    return None


def _http_request(
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    timeout: int,
    *,
    verify: bool = True,
) -> tuple[int, list[tuple[str, str]], bytes]:
    """One HTTP(S) request.

    HTTPS verifies the server certificate by default. ``verify=False`` is ONLY for
    the box's own self-signed loopback API (127.0.0.1) where there is no CA to check
    against — never for a remote endpoint, whose secrets would then be exposed to an
    on-path attacker (cf. the verified WebSocket in ``ws_connect``).
    """
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    if parts.scheme == "http":
        conn: http.client.HTTPConnection = http.client.HTTPConnection(
            host, parts.port or 80, timeout=timeout
        )
    else:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, parts.port or 443, timeout=timeout, context=ctx)
    try:
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        conn.request(method, path or "/", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data
    finally:
        conn.close()


def _relay_http(params: dict, cfg: Config | None) -> dict:
    """Forward a dashboard HTTP request to the local OPNsense API with injected auth.

    params: {method, path, headers, body(base64)} → {success, status, headers,
    body(base64)}. status 0 marks a transport/credential failure (the request
    never reached the API), distinct from an API HTTP error status.
    """
    if cfg is None:
        return {"success": False, "status": 0, "output": "agent config unavailable"}
    creds = _ensure_api_credentials(cfg)
    if creds is None:
        return {"success": False, "status": 0, "output": "no OPNsense API credentials"}
    key, secret = creds

    method = str(params.get("method", "GET")).upper()
    path = str(params.get("path", "")).lstrip("/")
    url = f"{cfg.local_api_url.rstrip('/')}/{path}"
    try:
        body = base64.b64decode(params.get("body") or "", validate=True)
    except (ValueError, TypeError):
        body = b""

    headers = {
        k: v
        for k, v in (params.get("headers") or {}).items()
        if k.lower() not in _RELAY_DROP_HEADERS
    }
    cred = base64.b64encode(f"{key}:{secret}".encode()).decode()
    headers["Authorization"] = f"Basic {cred}"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        status, resp_headers, data = _http_request(
            url, method, headers, body or None, timeout=25, verify=False
        )  # local self-signed API
    except (OSError, http.client.HTTPException) as exc:
        return {"success": False, "status": 0, "output": f"relay request failed: {exc}"}

    out_headers = {k: v for k, v in resp_headers if k.lower() not in _RELAY_DROP_HEADERS}
    return {
        "success": 200 <= status < 400,
        "status": status,
        "headers": out_headers,
        "body": base64.b64encode(data).decode(),
    }


# =============================================================================
# GUI auto-login (see docs/agent-architecture.md §18)
# =============================================================================
#
# The dashboard's GUI proxy lands the operator on the firewall's own WebUI, which
# still shows its login page. To skip it, the agent replays the form login locally
# and hands the resulting session cookie back to the dashboard, which sets it on
# the per-instance proxy origin so the browser arrives already authenticated.
#
# Credentials reuse the relay's `orbit` user (page-all). On pfSense its password IS
# the cached relay secret (pfRest BasicAuth == WebUI password), so we reuse it. On
# OPNsense the relay user's password is a random unknown (API-key auth is separate),
# so we mint + cache a dedicated WebUI password here.

_GUIPW_CACHE = os.environ.get("AGENT_GUIPW_CACHE") or _path_with_legacy(
    "/usr/local/etc/orbit-agent.guipw", "/usr/local/etc/opnsense-dash-agent.guipw"
)

_GUI_UA = f"orbit-agent/{__version__}"

# A transient cookie OPNsense sets to probe cookie support — not the auth session,
# never worth forwarding to the browser.
_GUI_TRANSIENT_COOKIES = frozenset({"cookie_test"})

# Set a known WebUI password on the existing `orbit` user (OPNsense). The User model
# hashes it; the relay's API key (separate apikeys auth) is left untouched.
_GUI_PROVISION_PHP = r"""<?php
require_once('legacy_bindings.inc');
use OPNsense\Core\Config;
use OPNsense\Auth\User;
$username = 'orbit';
$pw = base64_encode(random_bytes(24));
Config::getInstance()->lock();
$mdl = new User();
$user = $mdl->getUserByName($username);
if (!$user) { echo json_encode(["error" => "no orbit user"]); exit; }
$hash = $mdl->generatePasswordHash($pw);
if ($hash === false || strpos($hash, '$') !== 0) { echo json_encode(["error" => "hash failed"]); exit; }
$user->password = $hash;
$mdl->serializeToConfig(false, true);
Config::getInstance()->save();
echo json_encode(["user" => $username, "password" => $pw]);
"""


def _load_cached_gui_password() -> str | None:
    """Return the WebUI password the agent provisioned earlier, or None."""
    try:
        data = json.loads(Path(_GUIPW_CACHE).read_text())
    except (OSError, ValueError):
        return None
    pw = data.get("password")
    return pw if pw else None


def _cache_gui_password(user: str, password: str) -> None:
    """Persist the provisioned WebUI password (mode 600 — admin credential)."""
    _write_private(Path(_GUIPW_CACHE), json.dumps({"user": user, "password": password}))


def _provision_gui_password() -> tuple[str, str] | None:
    """OPNsense: set + cache a known WebUI password on the orbit user."""
    tmp = f"{_GUIPW_CACHE}.provision.php"
    try:
        Path(tmp).write_text(_GUI_PROVISION_PHP)
        out = _run(["/usr/local/bin/php", tmp], timeout=30)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp)
    try:
        data = json.loads(out.strip())
    except ValueError:
        log.error("gui: provisioning produced no valid password")
        return None
    user, pw = data.get("user"), data.get("password")
    if not user or not pw:
        log.error("gui: provisioning failed (%s)", data.get("error", "unknown"))
        return None
    _cache_gui_password(user, pw)
    return user, pw


def _ensure_gui_credentials(cfg: Config) -> tuple[str, str] | None:
    """(username, password) for replaying the firewall WebUI login.

    pfSense reuses the cached relay secret (it IS the user's password). OPNsense
    mints + caches a dedicated WebUI password (the relay user's own password is a
    random unknown — its API auth uses a separate key pair).
    """
    if detect_platform() == "pfsense":
        cached = _load_cached_credentials()
        return (cached[0], cached[1]) if cached else None
    cached_pw = _load_cached_gui_password()
    if cached_pw:
        return ("orbit", cached_pw)
    return _provision_gui_password()


class _LoginForm(HTMLParser):
    """Collect <input> fields (esp. hidden CSRF tokens) and the form action."""

    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[dict[str, str]] = []
        self.action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "form" and self.action is None:
            self.action = a.get("action")
        if tag == "input":
            self.inputs.append(a)


def _parse_login_form(body: bytes) -> tuple[dict[str, str], str | None]:
    """Return (hidden field name->value, form action) from a login page."""
    parser = _LoginForm()
    parser.feed(body.decode("utf-8", "replace"))
    hidden = {
        i["name"]: i.get("value", "")
        for i in parser.inputs
        if i.get("type") == "hidden" and i.get("name")
    }
    return hidden, parser.action


def _parse_set_cookies(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Extract cookie name->value pairs from every Set-Cookie response header."""
    jar: dict[str, str] = {}
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        if "=" in pair:
            k, v = pair.split("=", 1)
            jar[k.strip()] = v.strip()
    return jar


def _gui_login(cfg: Config | None) -> dict:
    """Replay the firewall WebUI login; return its session cookie(s) for the browser.

    params: none. → {success, cookies:[{name,value}], output?}. The session cookie
    is the secret — returned to the dashboard over the (TLS) WebSocket, never logged.
    Works on OPNsense and pfSense: both use usernamefld/passwordfld; their CSRF token
    is a hidden field of a random/platform-specific name, captured generically.
    """
    if cfg is None:
        return {"success": False, "output": "agent config unavailable"}
    creds = _ensure_gui_credentials(cfg)
    if creds is None:
        return {"success": False, "output": "no GUI credentials"}
    user, password = creds
    base = cfg.local_api_url.rstrip("/")

    # 1. GET the login page → pre-session cookie + CSRF hidden fields.
    try:
        _, headers, body = _http_request(
            f"{base}/", "GET", {"User-Agent": _GUI_UA}, None, 15, verify=False
        )  # local self-signed GUI
    except (OSError, http.client.HTTPException) as exc:
        return {"success": False, "output": f"gui login GET failed: {exc}"}
    pre_jar = _parse_set_cookies(headers)
    hidden, action = _parse_login_form(body)

    # 2. POST credentials + every hidden field (the CSRF token name is not fixed).
    fields = dict(hidden)
    fields["usernamefld"] = user
    fields["passwordfld"] = password
    fields["login"] = "1"
    post_body = urlencode(fields).encode()
    post_headers = {
        "User-Agent": _GUI_UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(post_body)),
        "Cookie": "; ".join(f"{k}={v}" for k, v in pre_jar.items()),
    }
    login_url = f"{base}/{(action or '').lstrip('/')}"
    try:
        status, headers, _ = _http_request(
            login_url, "POST", post_headers, post_body, 15, verify=False
        )  # local self-signed GUI
    except (OSError, http.client.HTTPException) as exc:
        return {"success": False, "output": f"gui login POST failed: {exc}"}

    # A successful login redirects (302 → dashboard) AND rotates the session id.
    # Keep only cookies the POST freshly set or changed vs the pre-login jar (drop
    # transients): a redirect that re-renders the login page on failure leaves the
    # session cookie unchanged, yielding no rotated cookie -> treated as failure.
    new_jar = _parse_set_cookies(headers)
    session_cookies = [
        {"name": k, "value": v}
        for k, v in new_jar.items()
        if k not in _GUI_TRANSIENT_COOKIES and pre_jar.get(k) != v
    ]
    if not (300 <= status < 400) or not session_cookies:
        return {"success": False, "output": "gui login rejected (bad credentials?)"}
    return {"success": True, "cookies": session_cookies}


# =============================================================================
# Command executor
# =============================================================================


def _ipsec_log_raw(lines: int = 3000) -> str:
    """Recent strongSwan log text. OPNsense = plain dated files (latest.log
    symlink); pfSense = a clog circular log."""
    if detect_platform() == "pfsense":
        return _run(["clog", "/var/log/ipsec.log"], timeout=10)
    for path in ("/var/log/ipsec/latest.log", "/var/log/ipsec.log"):
        if os.path.exists(path):
            return _run(["tail", "-n", str(lines), path], timeout=10)
    return ""


def _diagnose_ipsec(name: str) -> list[dict]:
    """Readable per-tunnel diagnostic sections gathered on-box (matches the
    Securepoint SSH bundle): config, live SAs, recent log, peer ping."""
    sections = [
        {
            "title": "Connection config (swanctl --list-conns)",
            "content": _run(["swanctl", "--list-conns"], timeout=10).strip(),
        },
        {
            "title": "Live IKE / CHILD SAs (swanctl --list-sas)",
            "content": _run(["swanctl", "--list-sas", "--ike", name], timeout=10).strip(),
        },
    ]
    # Resolve the peer IP from the conn config (reused for log-filtering + ping).
    remote = ""
    try:
        conns = _parse_swanctl_conns(_run(["swanctl", "--list-conns", "--raw"], timeout=10))
        remote = next(
            (c["remote"] for c in conns if c.get("name") == name and "%" not in c.get("remote", "%")),
            "",
        )
    except Exception:  # best-effort — never fail the bundle on a parse error
        remote = ""

    # Match this tunnel's log lines by conn name OR peer IP (a never-negotiating
    # tunnel may carry neither, and the failure of a *retrying* one is often tagged
    # by peer IP, not conn name). Fall back to a recent tail with a clear note so
    # the reader isn't misled by another tunnel's chatter.
    raw_lines = _ipsec_log_raw().splitlines()
    terms = [f"<{name}|"] + ([remote] if remote else [])
    tagged = [ln for ln in raw_lines if any(t in ln for t in terms)]
    if tagged:
        log_content = "\n".join(tagged[-300:]).strip()
    else:
        note = "(no recent charon lines reference this tunnel — last general charon lines:)"
        log_content = note + "\n" + "\n".join(raw_lines[-120:]).strip()
    sections.append({"title": "Recent IPsec log (charon)", "content": log_content})
    if remote:
        sections.append(
            {
                "title": "Peer reachability",
                "content": _run(["ping", "-c", "2", "-t", "4", remote], timeout=8).strip(),
            }
        )
    else:
        sections.append(
            {
                "title": "Peer reachability",
                "content": "no concrete peer IP (remote=%any / responder-only) — nothing to ping",
            }
        )
    return sections


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

    elif action == "ipsec.diagnose":
        return {"success": True, "sections": _diagnose_ipsec(params.get("tunnel_id", ""))}

    elif action == "ipsec.ping_test":
        # One-shot ping the dashboard runs from the config dialog BEFORE saving a
        # Phase-2 monitor, so the user can see whether the source/destination work.
        source = params.get("source", "")
        dest = params.get("destination", "")
        count = int(params.get("ping_count", 3) or 3)
        res = _ping_once(source, dest, count)
        state = res.get("ping_state")
        if state == "ok":
            msg = f"reply from {dest}: {res.get('ping_rtt_ms')} ms avg, {res.get('ping_loss_pct')}% loss"
        elif state == "fail":
            msg = f"no reply from {dest} (100% loss) — Phase 2 not passing traffic?"
        else:
            msg = "ping could not run — check the source IP (must be owned by this box) and routing"
        return {
            "success": state == "ok",
            "ping_state": state,
            "ping_rtt_ms": res.get("ping_rtt_ms"),
            "ping_loss_pct": res.get("ping_loss_pct"),
            "output": msg,
        }

    elif action == "ipsec.restart":
        # Reload IPsec via each platform's own config layer. NEITHER OPNsense nor
        # pfSense populates /usr/local/etc/swanctl/conf.d — both load swanctl via
        # a custom layer (verified on real boxes: conf.d empty, tunnels still up).
        # So `service strongswan restart` restarts charon with ZERO connections and
        # drops every tunnel on BOTH. Use the native reload instead (regenerates +
        # reloads in place, non-destructive). Fire-and-forget: the dashboard sees
        # the result via its IPsec status polling.
        if detect_platform() == "pfsense":
            cmd = [
                "php", "-r",
                'require_once("/etc/inc/config.inc"); '
                'require_once("/etc/inc/ipsec.inc"); ipsec_configure();',
            ]
        else:
            cmd = ["configctl", "ipsec", "reload"]  # OPNsense → pluginctl -c ipsec
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"success": True, "output": "ipsec reload started in background"}

    elif action == "firmware.check":
        plat = detect_platform()
        if plat == "pfsense":
            out = _run(["/usr/local/sbin/pfSense-upgrade", "-c"], timeout=60)
            version = _read_pfsense_version()
            branch = _read_pfsense_branch()
            known = _list_pfsense_branches()
            upgrade_available = _pfsense_update_available(out)
            latest = version  # pfSense-upgrade reports no target version
        else:
            version = _read_opnsense_version()
            branch = _opnsense_series()
            known = []
            upgrade_available, latest, out = _opnsense_update_check(version)
        # Refresh the push-loop cache so a throttled interim push doesn't revert
        # this fresh manual check back to the previous verdict.
        verdict = _store_fw_verdict(branch, known, upgrade_available, latest, out)
        return {
            "success": True,
            "output": verdict["update_check_output"],
            "product_version": version,
            "product_latest": verdict["product_latest"],
            "upgrade_available": verdict["upgrade_available"],
            "branch": verdict["branch"],
            "known_branches": verdict["known_branches"],
        }

    elif action == "firmware.update":
        # Non-blocking: start in background. -R keeps pfSense-upgrade from
        # rebooting automatically (admin reboots manually), matching the
        # stage-without-reboot behaviour of opnsense-update -bkp.
        if detect_platform() == "pfsense":
            cmd = ["/usr/local/sbin/pfSense-upgrade", "-y", "-R"]
        else:
            cmd = ["/usr/local/sbin/opnsense-update", "-bkp"]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    elif action == "relay.enable":
        # Explicit, idempotent: install the local REST API (pfSense) + provision the
        # relay credential. Kept off the startup path on purpose (§16 #3) — on
        # pfSense it pulls a package from the internet.
        return _relay_enable()

    elif action == "gui.login":
        return _gui_login(_CONFIG)

    elif action == "http.relay":
        # Tunnel a dashboard HTTP request to the local OPNsense API (see §15).
        return _relay_http(params, _CONFIG)

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

# Dead-peer detection: send a ping every _PING_INTERVAL; if nothing at all has
# arrived (not even a pong) for _RECV_TIMEOUT, the peer is gone (e.g. backend
# restart / half-open TCP) — treat the connection as dead and reconnect. Without
# this the agent can hang forever on a silently-dead socket.
_PING_INTERVAL = 20
_RECV_TIMEOUT = 60


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
        self._last_recv = time.monotonic()  # for dead-peer detection

    def stale_seconds(self) -> float:
        """Seconds since the last frame of any kind arrived from the peer."""
        return time.monotonic() - self._last_recv

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
            self._last_recv = time.monotonic()
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


# --- Update signing (Ed25519, pure stdlib verify) ----------------------------
# Set → every self-update must carry a valid Ed25519 signature over the code, so a
# compromised dashboard cannot push forged code (the private key is offline, never
# on the dashboard). Sign each release with scripts/sign_agent.py (just sign-agent),
# which writes orbit_agent.py.sig; the dashboard relays it. Empty disables enforcement.
# IMPORTANT: never release a build with this set but no matching .sig served — the
# agent would reject every subsequent update.
_UPDATE_PUBKEY = "082a588e9b9e4aec7eb3799f18ff545878be235b3158a07562db335a006cdedd"

_ED_P = 2**255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_B = (_ed_recover_x(_ED_BY) % _ED_P, _ED_BY % _ED_P)


def _ed_add(pt1: tuple[int, int], pt2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = pt1
    x2, y2 = pt2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _ED_D * x1 * x2 * y1 * y2, _ED_P - 2, _ED_P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _ED_D * x1 * x2 * y1 * y2, _ED_P - 2, _ED_P)
    return (x3 % _ED_P, y3 % _ED_P)


def _ed_mul(pt: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _ed_mul(pt, e // 2)
    q = _ed_add(q, q)
    if e & 1:
        q = _ed_add(q, pt)
    return q


def _ed_bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _ed_decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2**i * _ed_bit(s, i) for i in range(255))
    x = _ed_recover_x(y)
    if x & 1 != _ed_bit(s, 255):
        x = _ED_P - x
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P != 0:
        raise ValueError("point not on curve")
    return (x, y)


def _ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """RFC 8032 Ed25519 verify — pure Python (slow ref; run once per update)."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r = _ed_decodepoint(signature[:32])
        a = _ed_decodepoint(public_key)
    except (ValueError, IndexError):
        return False
    s = sum(2**i * _ed_bit(signature[32:], i) for i in range(256))
    h = hashlib.sha512(signature[:32] + public_key + message).digest()
    hh = sum(2**i * _ed_bit(h, i) for i in range(512))
    return _ed_mul(_ED_B, s) == _ed_add(r, _ed_mul(a, hh))


def _signature_ok(code: bytes, signature_b64: str) -> bool:
    """True if signing is disabled, or the Ed25519 signature over ``code`` is valid."""
    if not _UPDATE_PUBKEY:
        return True  # signing not enforced (dev / no baked key)
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = bytes.fromhex(_UPDATE_PUBKEY)
    except (ValueError, TypeError):
        return False
    return _ed25519_verify(sig, code, pub)


def _skip_sig_check() -> bool:
    """DEV ONLY: True if signature enforcement is explicitly disabled.

    Honors the AGENT_INSECURE_SKIP_SIG=1 env var (locally-run agent) and the
    ``insecure_skip_sig`` config flag (installed agent). Logs loudly so an accidental
    prod use is obvious. Never returns True on its own — both channels are opt-in.
    """
    env_on = os.environ.get("AGENT_INSECURE_SKIP_SIG") == "1"
    # Read the active config global (_CONFIG). The old globals().get("cfg") always
    # returned None (no module-level `cfg`), so the config flag was dead.
    cfg_on = bool(getattr(_CONFIG, "insecure_skip_sig", False))
    if env_on or cfg_on:
        log.warning(
            "INSECURE: self-update signature verification DISABLED "
            "(%s) — dev only, never use in production",
            "env AGENT_INSECURE_SKIP_SIG" if env_on else "config insecure_skip_sig",
        )
        return True
    return False


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


_CODE_VERSION_RE = re.compile(rb"""__version__\s*=\s*["']([0-9][0-9.]*)["']""")


def _version_tuple(version: str) -> tuple[int, ...]:
    """Numeric SemVer-ish tuple; leading digits of each dotted part (rest ignored)."""
    out: list[int] = []
    for part in version.split("."):
        m = re.match(r"\d+", part)
        out.append(int(m.group()) if m else 0)
    return tuple(out)


def _code_version(code: bytes) -> str | None:
    """The ``__version__`` embedded in pushed agent source — the version that will
    actually run after the swap. The signature covers ``code``, so reading the
    version from it binds the anti-rollback check to authenticated content; the
    unsigned ``version`` push param could otherwise be forged over old signed code."""
    m = _CODE_VERSION_RE.search(code)
    return m.group(1).decode() if m else None


def _is_forward_update(code: bytes) -> bool:
    """True only if the pushed code's embedded version is strictly newer than ours.

    Anti-rollback: every prior release is validly signed, so signature checks alone
    don't stop a compromised dashboard from replaying an old (vulnerable) build as an
    "update". Refuse anything not strictly forward, and refuse code with no version."""
    pushed = _code_version(code)
    if pushed is None:
        return False
    return _version_tuple(pushed) > _version_tuple(__version__)


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
    """Verify + stage a pushed update, ack, then exit for the supervisor to respawn.

    The unsigned ``version`` param is intentionally ignored — anti-rollback gates on
    the version embedded in the signature-covered code (see ``_is_forward_update``).
    """
    try:
        code = base64.b64decode(params.get("code", ""), validate=True)
    except (ValueError, TypeError):
        await _send_update_result(ws, request_id, False, "invalid base64 code")
        return
    if not _verify_update_code(code, params.get("sha256", "")):
        await _send_update_result(ws, request_id, False, "verification failed (sha256/syntax)")
        return
    if not _skip_sig_check() and not _signature_ok(code, params.get("signature", "")):
        await _send_update_result(ws, request_id, False, "signature verification failed")
        return
    # Anti-rollback: gate on the version embedded in the (signature-covered) code,
    # not the unsigned `version` param — refuse a replay of an older signed build.
    if not _is_forward_update(code):
        pushed = _code_version(code) or "unknown"
        await _send_update_result(
            ws, request_id, False, f"downgrade refused: pushed {pushed} not newer than {__version__}"
        )
        return
    staged = _code_version(code)  # validated forward above
    try:
        await asyncio.get_event_loop().run_in_executor(None, _apply_update, code, staged)
    except OSError as exc:
        await _send_update_result(ws, request_id, False, f"apply failed: {exc}")
        return
    await _send_update_result(ws, request_id, True, f"update staged to {staged}, restarting")
    log.info("self-update: staged %s, exiting for supervisor respawn", staged)
    await ws.close()
    os._exit(_UPDATE_RESTART_CODE)


async def _send_update_result(ws: WebSocket, request_id: str, success: bool, output: str) -> None:
    await ws.send(json.dumps({
        "type": "command_result",
        "request_id": request_id,
        "action": "agent.update",
        "result": {"success": success, "output": output},
    }))


# =============================================================================
# Uninstall (dashboard-triggered) — remove the agent's own footprint.
#
# The agent can't cleanly remove itself while running: the supervisor respawns it
# on any exit. So we ack the command, then a DETACHED script (own session, see
# start_new_session) does the teardown AFTER we're gone — killing the supervisor
# FIRST so nothing respawns, then the agent, then files + rc.d + the OPNsense
# orbit user. We deliberately do NOT exit here (an exit would just flap a respawn).
# =============================================================================

# Remove the auto-provisioned `orbit` OPNsense user (reverse of provisioning).
_DEPROVISION_PHP = r"""<?php
require_once('legacy_bindings.inc');
use OPNsense\Core\Config;
use OPNsense\Auth\User;
Config::getInstance()->lock();
$mdl = new User();
$removed = 0;
foreach ($mdl->user->iterateItems() as $uuid => $node) {
    if ((string)$node->name === 'orbit') { $mdl->user->del($uuid); $removed++; }
}
if ($removed > 0) { $mdl->serializeToConfig(false, true); Config::getInstance()->save(); }
echo "removed=$removed";
"""

# Remove the auto-provisioned `orbit` pfSense user (reverse of the pfSense provision).
_DEPROVISION_PF_PHP = r"""<?php
require_once("config.inc");
require_once("auth.inc");
$users = config_get_path("system/user", []);
$kept = [];
foreach ($users as $u) {
    if (($u['name'] ?? '') === 'orbit') { local_user_del($u); }
    else { $kept[] = $u; }
}
config_set_path("system/user", $kept);
write_config("remove orbit relay user");
echo "removed";
"""


def _build_uninstall_script(
    install_dir: str,
    rc_script: str,
    php_path: str,
    deprovision: bool,
    extra_cleanup: str = "",
) -> str:
    """Build the detached teardown script. Order matters: supervisor dies first.

    extra_cleanup is a platform-specific shell line (e.g. removing the pfRest package
    on pfSense) run after the orbit user is deprovisioned.
    """
    deprovision_line = (
        f"[ -x /usr/local/bin/php ] && /usr/local/bin/php {php_path} >/dev/null 2>&1\n"
        if deprovision and php_path
        else ""
    )
    return (
        "#!/bin/sh\n"
        "sleep 3\n"  # let the ack flush over the WS before we kill the agent
        # SIGKILL the whole tree: the daemon(8) wrapper (respawns the supervisor),
        # the supervisor (run-agent.sh, respawns the agent), and the agent. SIGTERM
        # is unreliable (asyncio handler + executor threads linger). Retry in a loop
        # — a single pass can race a respawn, and detached execution proved flaky on
        # FreeBSD (kill the wrapper first each pass so nothing comes back).
        "i=0\n"
        "while [ $i -lt 6 ]; do\n"
        '  pids="$(pgrep -f \'daemon.*orbit_agent\' 2>/dev/null) '
        "$(pgrep -f run-agent.sh 2>/dev/null) $(pgrep -f orbit_agent.py 2>/dev/null)\"\n"
        '  [ -z "$(echo $pids | tr -d \' \')" ] && break\n'
        '  for p in $pids; do kill -9 "$p" 2>/dev/null; done\n'
        "  sleep 1\n"
        "  i=$((i + 1))\n"
        "done\n"
        "sysrc -x orbit_agent_enable >/dev/null 2>&1\n"  # don't revive on reboot
        f"rm -f {rc_script}\n"
        + deprovision_line
        + extra_cleanup
        + f"rm -rf {install_dir}\n"
        f"rm -f {CONFIG_PATH} /usr/local/etc/opnsense-dash-agent.conf\n"
        f"rm -f {_APIKEY_CACHE} /usr/local/etc/opnsense-dash-agent.apikey\n"
        f"rm -f {php_path}\n"
    )


async def _handle_uninstall(ws: WebSocket, request_id: str, params: dict) -> None:
    """Ack, then a detached script removes the agent (supervisor first) + cleans up."""
    install_dir = os.path.dirname(_self_path())
    rc_script = "/usr/local/etc/rc.d/orbit_agent"
    deprovision = bool(params.get("deprovision", True))

    # Platform-specific teardown: remove the right `orbit` user, and on pfSense also
    # remove the pfRest package the relay installed (else uninstall leaves a dangling,
    # internet-reachable REST API behind).
    if detect_platform() == "pfsense":
        deprovision_php, extra_cleanup = _DEPROVISION_PF_PHP, (
            f"[ -x {_PFREST_CLI} ] && pkg-static delete -y pfSense-pkg-RESTAPI >/dev/null 2>&1\n"
        )
    else:
        deprovision_php, extra_cleanup = _DEPROVISION_PHP, ""

    try:
        php_path = _write_root_script(deprovision_php, ".php")
    except OSError:
        php_path = ""

    try:
        sh_path = _write_root_script(
            _build_uninstall_script(install_dir, rc_script, php_path, deprovision, extra_cleanup),
            ".sh",
        )
        subprocess.Popen(
            ["/bin/sh", sh_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # detach so it survives the agent's death
        )
        ok, output = True, "uninstall started; agent removing itself"
    except OSError as exc:
        ok, output = False, f"uninstall failed to start: {exc}"

    await ws.send(json.dumps({
        "type": "command_result",
        "request_id": request_id,
        "action": "agent.uninstall",
        "result": {"success": ok, "output": output},
    }))
    log.warning("agent.uninstall: %s", output)

    if ok:
        # Exit NOW so the detached script reparents to init — a still-running
        # descendant can't reliably SIGKILL its own ancestors on FreeBSD (the kill
        # silently no-ops), but once we exit, the script is outside the tree and
        # the kill works (the supervisor respawns us once; the script's retry loop
        # reaps that). The script sleeps briefly to let this exit land first.
        with contextlib.suppress(Exception):
            await ws.close()
        os._exit(0)


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
    """Ping periodically (NAT keepalive) and detect a dead peer.

    If nothing has arrived from the server for _RECV_TIMEOUT (no pong, no data),
    the connection is dead (backend restart / half-open TCP) — raise so the main
    loop tears down and reconnects instead of hanging on a silent socket.
    """
    while True:
        await asyncio.sleep(_PING_INTERVAL)
        if ws.stale_seconds() > _RECV_TIMEOUT:
            raise WSError(f"no data from server in {_RECV_TIMEOUT}s — dead connection")
        await ws.ping()


def _apply_push_interval(value: object) -> None:
    """Apply a dashboard-pinned push cadence to the live config.

    The push loop reads ``cfg.push_interval`` each cycle, so mutating the shared
    ``_CONFIG`` takes effect on the next push. Ignores junk and guards against a
    0/negative value that would turn the push loop into a hot loop.
    """
    if value is None or _CONFIG is None:
        return
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return
    if seconds < 1 or seconds == _CONFIG.push_interval:
        return
    _CONFIG.push_interval = seconds
    log.info("push interval set to %ds (dashboard)", seconds)


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


# =============================================================================
# GUI proxy — raw TCP tunnel over the agent WS (see docs/agent-architecture.md §18)
#
# The dashboard can't path-proxy the firewall's web GUI (absolute URLs escape any
# path prefix). Instead the dashboard exposes a local endpoint that tunnels raw TCP
# to the box's GUI port through this agent: the browser speaks TLS end-to-end with
# the firewall (self-signed cert), so AJAX/forms/live views just work — no HTML
# rewriting. Streams are multiplexed by id over the one agent WS; bytes are base64
# in JSON `tunnel` frames (the stdlib WS client is text-only).
# =============================================================================

class _TunnelManager:
    """Per-connection multiplexed TCP tunnels to the local GUI port."""

    def __init__(self, ws: WebSocket, host: str, port: int):
        self._ws = ws
        self._host = host
        self._port = port
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    async def handle(self, msg: dict) -> None:
        op = msg.get("op")
        stream = str(msg.get("stream", ""))
        if not stream:
            return
        if op == "open":
            # Pin the destination to the configured local GUI target; ignore any
            # server-supplied host/port so a malicious dashboard cannot turn the
            # agent (root) into a TCP pivot into the box's networks. Mirrors how
            # _relay_http pins its target to cfg.local_api_url.
            await self._open(stream)
        elif op == "data":
            await self._data(stream, msg.get("data", ""))
        elif op == "close":
            self._close(stream)

    async def _open(self, stream: str) -> None:
        host, port = self._host, self._port
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            log.warning("tunnel %s: connect %s:%s failed: %s", stream, host, port, exc)
            await self._send(stream, "close")
            return
        self._writers[stream] = writer
        self._tasks[stream] = asyncio.create_task(self._pump(stream, reader))

    async def _pump(self, stream: str, reader: asyncio.StreamReader) -> None:
        """Forward bytes from the local socket back to the dashboard until EOF."""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await self._send(stream, "data", base64.b64encode(chunk).decode())
        except (OSError, WSError):
            pass
        finally:
            await self._send(stream, "close")
            self._close(stream, cancel_task=False)

    async def _data(self, stream: str, data_b64: str) -> None:
        writer = self._writers.get(stream)
        if writer is None:
            return
        try:
            writer.write(base64.b64decode(data_b64))
            await writer.drain()
        except (OSError, ValueError):
            self._close(stream)

    def _close(self, stream: str, cancel_task: bool = True) -> None:
        writer = self._writers.pop(stream, None)
        if writer is not None:
            with contextlib.suppress(OSError):
                writer.close()
        task = self._tasks.pop(stream, None)
        if cancel_task and task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _send(self, stream: str, op: str, data: str | None = None) -> None:
        frame: dict = {"type": "tunnel", "op": op, "stream": stream}
        if data is not None:
            frame["data"] = data
        with contextlib.suppress(WSError, OSError):
            await self._ws.send(json.dumps(frame))

    def shutdown(self) -> None:
        for task in list(self._tasks.values()):
            task.cancel()
        for writer in list(self._writers.values()):
            with contextlib.suppress(OSError):
                writer.close()
        self._tasks.clear()
        self._writers.clear()


async def _listen_loop(ws: WebSocket) -> None:
    """Listen for commands from the dashboard."""
    gui = urlsplit(_CONFIG.local_api_url if _CONFIG else "https://127.0.0.1:4444")
    tunnels = _TunnelManager(ws, gui.hostname or "127.0.0.1", gui.port or 443)
    try:
        await _listen_loop_inner(ws, tunnels)
    finally:
        tunnels.shutdown()


async def _listen_loop_inner(ws: WebSocket, tunnels: _TunnelManager) -> None:
    while True:
        raw = await ws.recv()
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "tunnel":
                await tunnels.handle(msg)
                continue

            if msg_type == "welcome":
                # Dashboard may pin our push cadence (per-instance override or the
                # global default); the push loop reads cfg each cycle, so it sticks.
                _apply_push_interval(msg.get("push_interval"))
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

                if action == "agent.uninstall":
                    # Acks, then a detached script removes the agent — no return.
                    await _handle_uninstall(ws, request_id, params)
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
                # Dashboard pushes config: IPsec Phase-2 ping monitors + push cadence.
                data = msg.get("data", {})
                monitors = data.get("ipsec_ping_monitors")
                if monitors is not None:
                    global _PING_MONITORS
                    _PING_MONITORS = monitors if isinstance(monitors, list) else []
                    log.info("applied %d ipsec ping monitor(s)", len(_PING_MONITORS))
                _apply_push_interval(data.get("push_interval"))

            elif msg_type == "ping":
                await ws.send(json.dumps({"type": "pong"}))

        except json.JSONDecodeError:
            log.warning("received non-JSON message, ignoring")
        except Exception as exc:
            log.warning("error handling message: %s", exc)


# =============================================================================
# Enrollment — exchange a one-time code for an agent token (see §16 chunk C2)
# =============================================================================

def _derive_enroll_url(dashboard_url: str) -> str:
    """Turn the WS dashboard_url into the HTTP(S) enroll endpoint, or '' if unknown."""
    parts = urlsplit(dashboard_url)
    if not parts.netloc:
        return ""
    scheme = {"wss": "https", "ws": "http"}.get(parts.scheme, parts.scheme or "https")
    path = parts.path
    if path.endswith("/ws/agent"):
        path = path[: -len("/ws/agent")] + "/agent/enroll"
    else:
        path = "/api/agent/enroll"
    return f"{scheme}://{parts.netloc}{path}"


def _persist_token(cfg: Config, token: str) -> None:
    """Write the obtained token into the config file and drop the spent code.

    Critical: the enrollment code is single-use, so the token MUST survive a
    restart — otherwise the next boot re-enrolls with a consumed code and the
    agent can never reconnect.
    """
    try:
        p = Path(cfg.path)
        data = json.loads(p.read_text()) if p.exists() else {}
        data["agent_token"] = token
        data.pop("enroll_code", None)
        # Config holds agent_token + local_api_secret — write 0600 (no world-readable
        # window). write_text would create with root's umask (0644).
        _write_private(p, json.dumps(data, indent=4))
    except (OSError, ValueError) as exc:
        log.warning("enroll: could not persist token to %s: %s", cfg.path, exc)


def _enroll(cfg: Config) -> bool:
    """Exchange enroll_code for an agent_token before connecting, then persist it.

    Skips when an agent_token already exists (prefer it — a stored token must never
    be replaced by a re-enroll) or no code is configured. Returns True on success.
    """
    if cfg.agent_token or not cfg.enroll_code:
        return False
    url = cfg.enroll_url or _derive_enroll_url(cfg.dashboard_url)
    if not url:
        log.error("enroll: cannot derive enroll URL from dashboard_url")
        return False
    body = json.dumps({"code": cfg.enroll_code}).encode()
    try:
        # Remote dashboard: MUST verify TLS — this exchanges the one-time enroll
        # code (bootstrap secret) for the long-lived agent token.
        status, _, data = _http_request(
            url, "POST", {"Content-Type": "application/json"}, body, timeout=15, verify=True
        )
    except (OSError, http.client.HTTPException) as exc:
        log.error("enroll: request to %s failed: %s", url, exc)
        return False
    if status != 200:
        log.error("enroll: server rejected code (HTTP %s)", status)
        return False
    try:
        token = json.loads(data).get("agent_token", "")
    except ValueError:
        token = ""
    if not token:
        log.error("enroll: no token in response")
        return False
    cfg.agent_token = token
    _persist_token(cfg, token)
    log.info("enroll: obtained and persisted agent token")
    return True


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
    global _CONFIG
    cfg = Config()
    _CONFIG = cfg  # the HTTP relay reads local API settings from here
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log.info("orbit agent v%s starting (id=%s)", __version__, cfg.agent_id)
    log.info("dashboard: %s", cfg.dashboard_url)
    log.info("push interval: %ds", cfg.push_interval)

    # Enrollment: if bootstrapped with a one-time code instead of a token, trade it
    # for an agent_token and persist it before we try to connect (§16 chunk C2).
    if not cfg.agent_token and cfg.enroll_code:
        _enroll(cfg)

    # Relay startup: discover the box's real GUI/API port, then (on OPNsense) make
    # sure a key already exists — so the first relay request isn't a cold provision
    # racing the command timeout (§15 #5). Idempotent: a valid cache is reused, no
    # config write. Never fatal — the agent must start even if this fails.
    _apply_port_discovery(cfg)
    if cfg.relay_provision:
        try:
            if _ensure_api_credentials(cfg):
                log.info("relay: local API credentials ready (%s)", cfg.local_api_url)
        except Exception as exc:  # noqa: BLE001 — provisioning must never block startup
            log.warning("relay: credential provisioning at startup failed: %s", exc)

    # Self-heal pfSense boot persistence (no-op elsewhere / when already set). Runs
    # at every startup so already-connected agents fix themselves on the next deploy.
    try:
        _ensure_pfsense_boot_persistence()
    except Exception as exc:  # noqa: BLE001 — must never block startup
        log.warning("pfsense: boot persistence check failed: %s", exc)

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
