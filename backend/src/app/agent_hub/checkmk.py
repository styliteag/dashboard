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
    and are skipped entirely. A repeated section name keeps the *first*
    occurrence — the stock agent emits each core section once, and a local
    plugin appending the same name again must not clobber the core data.
    Header options (``:sep(..)``, ``:cached(..)``) are dropped; the parsers
    below split whitespace-separated columns.
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
            name = m.group(1)
            if name in sections:
                current = None
            else:
                sections[name] = []
                current = sections[name]
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
    """``<<<df>>>`` → the agent's disks shape.

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
    disks = _parse_df(sections.get("df", []))
    if disks is not None:
        out["disks"] = disks
    uptime = _parse_uptime(sections.get("uptime", []))
    if uptime is not None:
        out["uptime"] = uptime
    ticks = _parse_kernel_ticks(sections.get("kernel", []))
    pct = cpu_pct_from_ticks(prev_cpu_ticks, ticks)
    if pct is not None:
        out["cpu"] = {"total_pct": pct}
    return out, ticks
