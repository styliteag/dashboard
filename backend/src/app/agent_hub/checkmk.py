"""Checkmk-agent output → snapshot enrichment (generic Linux nodes, §25/DR-10).

The linux agent pushes the raw output of the vendored ``check_mk_agent.linux``
as a ``checkmk_raw`` section (gzip+base64, see agent collect_checkmk). This
module parses the envelope plus a small, growing set of sections and rewrites
the push payload so the regular converters/checks see exactly the shapes the
FreeBSD collectors produce — downstream (SystemStatus, checks, metrics
history, UI) needs no linux branch, and evaluating a new Checkmk section is a
backend-only change (no agent rollout).

The parsers are own-built from the documented section formats. Do NOT copy
parse code from the GPLv2 Checkmk sources — we distribute container images,
and a derived work would drag the whole image under GPL (the vendored shell
script itself is attributed in THIRD-PARTY-NOTICES).

Everything here is pure and total: absent/broken data never raises, a section
that fails to parse simply leaves the original payload untouched (no data
must never alarm downstream).
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re

# Decompressed cap. The agent caps raw output at 2 MB before gzip; anything
# larger here means a tampered/broken payload — drop it, don't parse it.
_MAX_RAW = 8_000_000

_HEADER_RE = re.compile(r"^<<<([a-zA-Z0-9_.-]+)((?::[a-zA-Z_]+\([^)]*\))*)>>>$")

# Cumulative (total, idle) jiffies from <<<kernel>>> — CPU% needs the delta
# between two pushes, so the hub keeps the previous tuple per instance.
CpuTicks = tuple[int, int]


def decode_raw(data: dict) -> str | None:
    """The decompressed checkmk_raw text of a push payload, or None."""
    section = data.get("checkmk_raw") or {}
    blob = section.get("output_gz_b64") if isinstance(section, dict) else None
    if not blob:
        return None
    try:
        raw = gzip.decompress(base64.b64decode(blob))
    except (ValueError, OSError, binascii.Error):
        return None
    if len(raw) > _MAX_RAW:
        return None
    return raw.decode("utf-8", "replace")


def parse_sections(text: str) -> dict[str, list[str]]:
    """Split Checkmk agent output into ``{section_name: lines}``.

    Piggyback blocks (``<<<<host>>>>`` … ``<<<<>>>>``) belong to other hosts
    and are skipped entirely. A repeated section name *concatenates* — the
    stock agent legitimately emits some sections twice (``lnx_if`` = ip-link
    block + counter/ethtool variant, ``df_v2`` = data + inode block), and the
    parsers are defensive enough that appended plugin output degrades to
    ignored lines rather than clobbering anything. Header options
    (``:sep(..)``, ``:cached(..)``) are dropped; the parsers below split
    whitespace-separated columns.
    """
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    piggyback = False
    for line in text.splitlines():
        if line.startswith("<<<<") and line.endswith(">>>>"):
            piggyback = line != "<<<<>>>>"
            current = None
            continue
        if piggyback:
            continue
        m = _HEADER_RE.match(line)
        if m:
            current = sections.setdefault(m.group(1), [])
            continue
        if current is not None:
            current.append(line)
    return sections


def _parse_cpu(lines: list[str]) -> dict | None:
    """``<<<cpu>>>`` → the agent's loadavg shape.

    One line: ``load1 load5 load15 running/total lastpid [ncores]``.
    """
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 3:
        return None
    try:
        one, five, fifteen = (float(parts[i]) for i in range(3))
    except ValueError:
        return None
    cores = int(parts[5]) if len(parts) >= 6 and parts[5].isdigit() else 0
    return {"one": one, "five": five, "fifteen": fifteen, "cores": cores}


def _parse_kernel_ticks(lines: list[str]) -> CpuTicks | None:
    """Cumulative (total, idle) jiffies from the ``cpu`` summary row of
    ``<<<kernel>>>`` (/proc/stat format). iowait counts as idle — the CPU is
    not doing work while waiting on disk."""
    for line in lines:
        parts = line.split()
        if parts and parts[0] == "cpu" and len(parts) >= 5:
            try:
                vals = [int(x) for x in parts[1:]]
            except ValueError:
                return None
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return (sum(vals), idle)
    return None


def cpu_pct_from_ticks(prev: CpuTicks | None, cur: CpuTicks | None) -> float | None:
    """Busy-CPU percent across two tick samples; None when not computable."""
    if prev is None or cur is None:
        return None
    d_total = cur[0] - prev[0]
    d_idle = cur[1] - prev[1]
    if d_total <= 0:
        return None
    pct = (d_total - d_idle) / d_total * 100.0
    return round(min(100.0, max(0.0, pct)), 1)


_MEM_RE = re.compile(r"^(\w+):\s+(\d+)")


def _parse_mem(lines: list[str]) -> dict | None:
    """``<<<mem>>>`` (/proc/meminfo, kB) → the agent's memory shape.

    Used = MemTotal - MemAvailable (the kernel's own reclaimable estimate);
    the Buffers+Cached fallback covers pre-3.14 kernels without MemAvailable.
    """
    kv: dict[str, int] = {}
    for line in lines:
        m = _MEM_RE.match(line)
        if m:
            kv[m.group(1)] = int(m.group(2))
    total_kb = kv.get("MemTotal", 0)
    if total_kb <= 0:
        return None
    avail_kb = kv.get("MemAvailable")
    if avail_kb is None:
        avail_kb = kv.get("MemFree", 0) + kv.get("Buffers", 0) + kv.get("Cached", 0)
    used_kb = max(0, total_kb - avail_kb)
    swap_total_kb = kv.get("SwapTotal", 0)
    swap_used_kb = max(0, swap_total_kb - kv.get("SwapFree", 0))
    total_mb = total_kb / 1024
    used_mb = used_kb / 1024
    swap_total_mb = swap_total_kb / 1024
    swap_used_mb = swap_used_kb / 1024
    return {
        "total_mb": round(total_mb, 1),
        "used_mb": round(used_mb, 1),
        "used_pct": round(used_mb / total_mb * 100, 1),
        "swap_total_mb": round(swap_total_mb, 1),
        "swap_used_mb": round(swap_used_mb, 1),
        "swap_used_pct": round(swap_used_mb / swap_total_mb * 100, 1) if swap_total_kb else 0.0,
    }


def _parse_df(lines: list[str]) -> list[dict] | None:
    """``<<<df_v2>>>`` (Checkmk ≥2.4; ``<<<df>>>`` before) → the agent's disks shape.

    Columns: device fstype size_kb used_kb avail_kb used% mountpoint. The
    section embeds an inode sub-block ([df_inodes_start]…[df_inodes_end]) —
    skipped. Only real block devices (/dev/…) or copy-on-write filesystems
    are kept: tmpfs/overlay/squashfs rows would flood a server's disk list.
    """
    rows: list[dict] = []
    in_inodes = False
    for line in lines:
        if line.startswith("[df_"):
            in_inodes = line.startswith("[df_inodes_start")
            continue
        if in_inodes:
            continue
        parts = line.split()
        if len(parts) < 7 or not parts[5].endswith("%"):
            continue
        device, fstype = parts[0], parts[1]
        if not device.startswith("/dev/") and fstype not in ("zfs", "btrfs", "xfs"):
            continue
        try:
            used_pct = float(parts[5].rstrip("%"))
        except ValueError:
            continue
        rows.append(
            {
                "device": device,
                # df escapes nothing — a mountpoint with spaces spans columns.
                "mountpoint": " ".join(parts[6:]),
                "used_pct": used_pct,
            }
        )
    return rows or None


# /proc/net/dev row inside <<<lnx_if>>>: "  eth0: 53756418 85747 0 5000 …"
# (16 counter columns; MAC/Speed lines from the ethtool blocks don't match
# because their values aren't digits-only).
_IF_COUNTER_RE = re.compile(r"^\s*([^\s:\[\]]+):\s*(\d[\d ]*)$")
_IF_IPLINK_RE = re.compile(r"^\d+:\s+([^:@\s]+)(?:@\S+)?:\s+<([^>]*)>")


def _parse_lnx_if(lines: list[str]) -> list[dict] | None:
    """``<<<lnx_if>>>`` (both variants concatenated) → the agent's interfaces
    shape.

    The ip-link block ([start_iplink]…[end_iplink]) provides flags/state and
    the primary IPv4; the counter rows (/proc/net/dev format) provide byte and
    error counters: rx bytes/packets/errs/… then tx bytes/packets/errs/…/colls.
    Loopback is dropped (noise on every host). Only interfaces with a counter
    row are reported — the counters drive the error-rate annotation downstream.
    """
    counters: dict[str, list[int]] = {}
    states: dict[str, str] = {}
    addrs: dict[str, str] = {}
    in_iplink = False
    current: str | None = None
    for line in lines:
        if line.startswith("[start_iplink]"):
            in_iplink = True
            continue
        if line.startswith("[end_iplink]"):
            in_iplink = False
            current = None
            continue
        if in_iplink:
            m = _IF_IPLINK_RE.match(line)
            if m:
                current = m.group(1)
                flags = m.group(2).split(",")
                states[current] = "up" if "UP" in flags else "down"
                continue
            am = re.match(r"\s+inet\s+([\d.]+)/", line)
            if am and current is not None:
                addrs.setdefault(current, am.group(1))
            continue
        m = _IF_COUNTER_RE.match(line)
        if m:
            fields = m.group(2).split()
            if len(fields) >= 14:
                counters[m.group(1)] = [int(x) for x in fields]
    rows = [
        {
            "name": name,
            "status": states.get(name, "up"),
            "address": addrs.get(name),
            "bytes_received": c[0],
            "bytes_transmitted": c[8],
            "in_errors": c[2],
            "out_errors": c[10],
            "collisions": c[13],
        }
        for name, c in counters.items()
        if name != "lo"
    ]
    return rows or None


def _parse_chrony(lines: list[str]) -> dict | None:
    """``<<<chrony>>>`` (chronyc tracking output) → the agent's ntp shape.

    "System time … fast/slow of NTP time" is the live offset (sign follows
    fast/slow); "RMS offset" stands in for jitter. An unsynchronised chrony
    reports stratum 0 / "Not synchronised" → synced False, and the ntp check's
    no-data sentinel (stratum < 0) stays reserved for "no chrony at all".
    """
    kv: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            kv[key.strip()] = value.strip()
    if "Stratum" not in kv:
        return None
    try:
        stratum = int(kv["Stratum"])
    except ValueError:
        return None
    offset_ms = 0.0
    m = re.match(r"([\d.]+)\s+seconds\s+(fast|slow)", kv.get("System time", ""))
    if m:
        offset_ms = round(float(m.group(1)) * 1000 * (1 if m.group(2) == "fast" else -1), 3)
    jitter_ms = 0.0
    jm = re.match(r"([\d.]+)\s+seconds", kv.get("RMS offset", ""))
    if jm:
        jitter_ms = round(float(jm.group(1)) * 1000, 3)
    peer = ""
    pm = re.search(r"\(([^)]+)\)", kv.get("Reference ID", ""))
    if pm:
        peer = pm.group(1)
    synced = stratum > 0 and "not synchronised" not in kv.get("Leap status", "").lower()
    return {
        "synced": synced,
        "stratum": stratum,
        "offset_ms": offset_ms,
        "jitter_ms": jitter_ms,
        "peer": peer,
    }


def _parse_systemd_units(lines: list[str]) -> list[dict] | None:
    """``<<<systemd_units>>>`` ([all] block) → the agent's services shape.

    Reported: running services (display + vital-service checks) and *failed*
    units (running False + failed marker → WARN check downstream). The
    hundreds of inactive/static units are deliberately dropped — an inactive
    oneshot is normal life, not a service list.
    """
    rows: list[dict] = []
    in_all = False
    for line in lines:
        if line.startswith("["):
            in_all = line.strip() == "[all]"
            continue
        if not in_all:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        unit, _load, active, sub = parts[:4]
        name = unit[: -len(".service")]
        description = parts[4] if len(parts) > 4 else ""
        if active == "failed":
            rows.append(
                {"name": name, "description": description, "running": False, "failed": True}
            )
        elif active == "active" and sub == "running":
            rows.append({"name": name, "description": description, "running": True})
    return rows or None


def _parse_uptime(lines: list[str]) -> str | None:
    """``<<<uptime>>>`` (seconds since boot) → the human string the FreeBSD
    collector ships (uptime(1) style: "12 days, 3:07" / "3:07" / "42 mins")."""
    if not lines:
        return None
    try:
        secs = float(lines[0].split()[0])
    except (ValueError, IndexError):
        return None
    if secs < 0:
        return None
    mins = int(secs // 60)
    days, rem = divmod(mins, 1440)
    hours, minutes = divmod(rem, 60)
    if days:
        return f"{days} days, {hours}:{minutes:02d}"
    if hours:
        return f"{hours}:{minutes:02d}"
    return f"{minutes} mins"


def enrich_snapshot(
    data: dict, sections: dict[str, list[str]], prev_cpu_ticks: CpuTicks | None
) -> tuple[dict, CpuTicks | None]:
    """Rewrite a push payload with sections parsed from Checkmk output.

    Returns ``(new payload, current cpu ticks)`` — the input dict is never
    mutated. Only sections that parsed replace their orbit counterparts; on
    linux those hold zeros/junk (sysctl/pfctl don't exist there), so parsed
    Checkmk data wins. A parser returning None leaves the original key —
    partial Checkmk output degrades per-section, never wholesale.
    """
    out = dict(data)
    load = _parse_cpu(sections.get("cpu", []))
    if load is not None:
        out["loadavg"] = load
    mem = _parse_mem(sections.get("mem", []))
    if mem is not None:
        out["memory"] = mem
    # Live ubn1 (Checkmk 2.5.0p8) emits df_v2; older agent builds emit df.
    disks = _parse_df(sections.get("df_v2") or sections.get("df", []))
    if disks is not None:
        out["disks"] = disks
    uptime = _parse_uptime(sections.get("uptime", []))
    if uptime is not None:
        out["uptime"] = uptime
    interfaces = _parse_lnx_if(sections.get("lnx_if", []))
    if interfaces is not None:
        out["interfaces"] = interfaces
    ntp = _parse_chrony(sections.get("chrony", []))
    if ntp is not None:
        out["ntp"] = ntp
    services = _parse_systemd_units(sections.get("systemd_units", []))
    if services is not None:
        out["services"] = services
    ticks = _parse_kernel_ticks(sections.get("kernel", []))
    pct = cpu_pct_from_ticks(prev_cpu_ticks, ticks)
    if pct is not None:
        out["cpu"] = {"total_pct": pct}
    return out, ticks
