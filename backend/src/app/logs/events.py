"""Extract aggregated "critical" events from agent log snapshots.

Two syslog shapes exist in the wild (verified against a prod DB copy):
RFC5424 with a ``<PRI>`` prefix (OPNsense, most pfSense logs) where severity
is ``PRI % 8``, and PRI-less BSD lines (dpinger, older pfSense) where a curated
pattern list assigns a severity. Lines are normalized (IPs, numbers, quoted
strings → placeholders) so repeats collapse into one event with a count —
prod data showed 3900+ identical ``syslogd sendto`` lines on a single box.

Known-noise patterns are dropped entirely: ``dpinger sendto error`` appeared on
37 of 68 prod instances and ``filterdns failed to resolve`` on 47 — both are
steady-state, not signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Highest syslog severity number worth storing (4 = warning). The UI defaults
# to showing <= 2 (crit/alert/emerg) and lets the user widen to 3 or 4.
MAX_SEVERITY = 4

_PATTERN_MAX = 200
_SAMPLE_MAX = 500

# RFC5424: <PRI>VER TS HOST APP PROCID MSGID/[SD] MSG
_RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>\d+\s+(?P<ts>\S+)\s+\S+\s+(?P<app>\S+)\s+\S+\s+\S+\s+"
    r"(?:\[[^\]]*\]\s*)?(?P<msg>.*)$"
)
# BSD: Mon DD HH:MM:SS host prog[pid]: msg  (optional <PRI> prefix, RFC3164)
_BSD = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+"
    r"(?P<prog>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

# Steady-state noise — dropped before any severity logic (see module docstring).
_NOISE = (
    re.compile(r"dpinger.*sendto error", re.IGNORECASE),
    re.compile(r"filterdns.*failed to resolve", re.IGNORECASE),
)

# Severity for PRI-less lines. First match wins; anything unmatched is dropped.
_CURATED: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"\bpanic\b|Fatal trap|out of swap", re.IGNORECASE), 2),
    (re.compile(r"authentication (?:error|failed)|Failed password|login failed", re.IGNORECASE), 3),
    (re.compile(r"\berror\b|\bcritical\b|\bcorrupt", re.IGNORECASE), 3),
    (re.compile(r"\bfail(?:ed|ure)?\b|\btimeout\b|link state changed to DOWN", re.IGNORECASE), 4),
)


@dataclass
class ExtractedEvent:
    severity: int
    program: str
    pattern: str
    sample: str = ""
    count: int = 0
    last_ts: str = field(default="")


def normalize(msg: str) -> str:
    """Mask the variable parts of a log message so repeats collapse."""
    msg = re.sub(r'"[^"]*"', '"…"', msg)
    msg = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "IP", msg)
    msg = re.sub(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", "MAC", msg)
    msg = re.sub(r"\b[0-9a-fA-F:]*:[0-9a-fA-F:%a-z0-9]{4,}\b", "IP6", msg)
    msg = re.sub(r"\b\d+\b", "N", msg)
    return msg[:_PATTERN_MAX]


def _classify(line: str) -> tuple[int, str, str, str] | None:
    """(severity, program, message, ts) for one raw line, or None to drop it."""
    m = _RFC5424.match(line)
    if m:
        return int(m["pri"]) % 8, m["app"], m["msg"], m["ts"]
    m = _BSD.match(line)
    if m:
        if m["pri"] is not None:
            return int(m["pri"]) % 8, m["prog"], m["msg"], m["ts"]
        for pattern, severity in _CURATED:
            if pattern.search(line):
                return severity, m["prog"], m["msg"], m["ts"]
    return None


def extract_events(log_name: str, content: str) -> list[ExtractedEvent]:
    """Aggregate a snapshot's critical lines into normalized events.

    ``log_name`` is unused for now but part of the contract — per-log rules
    (e.g. treating filter logs differently) belong here, not in callers.
    """
    by_key: dict[tuple[int, str, str], ExtractedEvent] = {}
    for line in content.splitlines():
        if not line or any(noise.search(line) for noise in _NOISE):
            continue
        classified = _classify(line)
        if classified is None:
            continue
        severity, program, msg, ts = classified
        if severity > MAX_SEVERITY:
            continue
        key = (severity, program, normalize(msg))
        event = by_key.get(key)
        if event is None:
            event = ExtractedEvent(severity=severity, program=program[:64], pattern=key[2])
            by_key[key] = event
        event.count += 1
        event.sample = line[:_SAMPLE_MAX]
        event.last_ts = ts
    return sorted(by_key.values(), key=lambda e: (e.severity, -e.count))
