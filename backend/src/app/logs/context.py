"""Render an instance's structured telemetry into a compact text block for AI
analysis — interfaces, IPsec tunnels, gateways, services, pf and certificates,
the same data the dashboard already holds in ``Instance.status_snapshot``. Sent
alongside the raw logs so the model reasons over state *and* log lines. Pure.
"""

from __future__ import annotations

from typing import Any

# Token economy: dense state first, then a recent tail of each verbose log, all
# capped. Context (interfaces/tunnels/…) is tiny and always kept in full.
PER_LOG_CHARS = 5_000  # tail of each verbose log (system/filter/ipsec/…)
STATE_CHARS = 4_500  # head of a state snapshot (pf/mbufs/neighbors/ifconfig/…)
RULES_CHARS = 12_000  # the ruleset is bigger but high-signal — keep more of its head
MAX_PAYLOAD_CHARS = 48_000  # hard cap (~12 k tokens; was ~173 k of raw logs)

# Names that are time-ordered logs → keep the recent TAIL. Everything else is a
# current-state snapshot → keep the HEAD.
_TAIL_LOGS = frozenset(
    {"system", "filter", "ipsec", "gateways", "resolver", "openvpn", "dhcp", "dmesg"}
)


def _iface_problem_flags(i: dict[str, Any]) -> list[str]:
    flags = []
    if i.get("status") != "up":
        flags.append(str(i.get("status") or "down"))
    if i.get("in_errors") or i.get("out_errors"):
        flags.append(f"errs in={i.get('in_errors')} out={i.get('out_errors')}")
    if i.get("err_rate"):
        flags.append(f"err_rate={i.get('err_rate')}/s")
    return flags


def _interfaces(status: dict[str, Any]) -> list[str]:
    """All interfaces, compact: name, status, address and any error flags. Cheap
    (~one short line each) and the inventory + addresses help the model."""
    rows = status.get("interfaces") or []
    if not rows:
        return []
    issues = 0
    lines: list[str] = []
    for i in rows:
        flags = _iface_problem_flags(i)
        if flags:
            issues += 1
        tag = f" [{', '.join(flags)}]" if flags else ""
        lines.append(f"  {i.get('name')} {i.get('status')} {i.get('address') or ''}{tag}".rstrip())
    return [f"  ({len(rows)} interfaces, {issues} with issues)", *lines]


def _ipsec(ipsec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for t in ipsec.get("tunnels") or []:
        label = t.get("description") or t.get("id") or "?"
        out.append(
            f"  tunnel {label}: P1={t.get('phase1_status')} "
            f"P2 {t.get('phase2_up')}/{t.get('phase2_total')} up, "
            f"bytes in={t.get('bytes_in')} out={t.get('bytes_out')}"
        )
        for c in t.get("children") or []:
            ping = c.get("ping_state")
            ping_txt = f" ping={ping}" if ping and ping != "none" else ""
            out.append(
                f"    {c.get('local_ts')} -> {c.get('remote_ts')}: {c.get('state')} "
                f"in={c.get('bytes_in')}B out={c.get('bytes_out')}B{ping_txt}"
            )
    return out


def _gateways(gateways: list[dict[str, Any]]) -> list[str]:
    return [
        f"  {g.get('name')} {g.get('status')} loss={g.get('loss')} delay={g.get('delay')}"
        for g in gateways
    ]


def _services_down(services: list[dict[str, Any]]) -> list[str]:
    return [f"  {s.get('name')} STOPPED" for s in services if not s.get("running")]


def _certs_soon(certs: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for c in certs:
        days = c.get("days_remaining")
        if isinstance(days, int) and days < 30:
            out.append(f"  {c.get('name')} expires in {days}d")
    return out


def build_context_text(snapshot: dict[str, Any] | None) -> str:
    """Compact structured summary from a status snapshot ('' if no snapshot)."""
    if not snapshot:
        return ""
    status = snapshot.get("status") or {}
    parts: list[str] = ["===== SYSTEM CONTEXT (structured telemetry) ====="]

    ifaces = _interfaces(status)
    if ifaces:
        parts.append("Interfaces:")
        parts.extend(ifaces)

    pf = status.get("pf") or {}
    if pf:
        parts.append(
            f"pf states: {pf.get('states_current')}/{pf.get('states_limit')} "
            f"({pf.get('states_pct')}%)"
        )

    tunnels = _ipsec(snapshot.get("ipsec") or {})
    if tunnels:
        parts.append("IPsec tunnels:")
        parts.extend(tunnels)

    gateways = _gateways(snapshot.get("gateways") or [])
    if gateways:
        parts.append("Gateways:")
        parts.extend(gateways)

    down = _services_down(snapshot.get("services") or [])
    if down:
        parts.append("Services (stopped):")
        parts.extend(down)

    certs = _certs_soon(snapshot.get("certificates") or [])
    if certs:
        parts.append("Certificates (<30d):")
        parts.extend(certs)

    return "\n".join(parts) if len(parts) > 1 else ""


def _slice_for(row: Any) -> str:
    """Head of a state snapshot (whole-ish) vs recent tail of a verbose log."""
    content = row.content or ""
    if row.name in _TAIL_LOGS:
        return content[-PER_LOG_CHARS:]
    cap = RULES_CHARS if row.name == "rules" else STATE_CHARS
    return content[:cap]


def build_analysis_text(snapshot: dict[str, Any] | None, logs: list[Any]) -> str:
    """Bounded analysis payload (``logs`` are ORM rows with ``.name``/``.content``).

    Order by signal density: structured context, then state snapshots (ruleset,
    pf, neighbors, ifconfig, listeners, mbufs), then the recent tail of each
    verbose log — capped so the dense, high-signal data always survives."""
    parts: list[str] = []
    context = build_context_text(snapshot)
    if context:
        parts.append(context)
    state = [r for r in logs if r.name not in _TAIL_LOGS]
    tails = [r for r in logs if r.name in _TAIL_LOGS]
    for row in (*state, *tails):
        slice_ = _slice_for(row)
        if slice_:
            kind = "recent" if row.name in _TAIL_LOGS else "state"
            parts.append(f"===== {row.name} ({kind}, {len(slice_)} chars) =====\n{slice_}")
    return "\n\n".join(parts)[:MAX_PAYLOAD_CHARS]
