"""Parse ``swanctl --list-sas/--list-conns --raw`` into Orbit IPsec DTOs.

Ported (stdlib-only text processing) from ``agent/orbit_agent.py`` — the agent
already parses the identical strongSwan ``--raw`` vici stream on OPNsense/pfSense.
The backend can't import the agent (separate app), so this is a copy.

DIVERGENCE FROM THE AGENT (mirror back, then bump agent __version__ + re-sign):
``_vici_parse`` here DISAMBIGUATES colliding ``{``-section keys instead of merging
them. swanctl emits one ``… event { <conn> { <sa> } }`` envelope per SA and can
repeat a connection name (a passive ``%any`` half-open responder SA alongside the
established one). The agent's merge-by-key collapses those two into one record —
the later ``CREATED``/``%any`` half-open overwrites the live ESTABLISHED SA's host
+ IKE-cookie fields, producing a Frankenstein tunnel (CREATED/%any, zeroed
responder SPI, but INSTALLED children). Disambiguation keeps both; the ``%any``
half-open is then dropped in ``_parse_swanctl_sas``.
"""

from __future__ import annotations

import re
from typing import Any

from app.xsense.schemas import IPsecChild, IPsecServiceStatus, IPsecTunnel

# Marker keys unique to each record type — never present on the raw envelope.
_IKE_SA_MARKERS = frozenset({"uniqueid", "state", "local-host", "remote-host", "child-sas"})
_CONN_MARKERS = frozenset({"local_addrs", "remote_addrs", "children"})
# Real child-SA modes carry traffic; PASS/DROP are policy shunts, not tunnels.
_TUNNEL_CHILD_MODES = frozenset({"TUNNEL", "TRANSPORT", "BEET"})


def _to_int(v: object) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


def _vici_parse(tokens: list[str]) -> dict:
    """Build a nested dict from a tokenized vici ``--raw`` stream.

    Colliding ``{``-section keys are disambiguated (``key\\x00N``) rather than
    merged, so repeated ``event``/connection envelopes each survive as their own
    record (see module docstring).
    """
    root: dict = {}
    stack: list[tuple[str, object]] = [("section", root)]
    pending: str | None = None
    for tok in tokens:
        kind, cont = stack[-1]
        if tok in ("{", "["):
            key = pending if pending is not None else str(len(cont))  # type: ignore[arg-type]
            child: object
            if isinstance(cont, dict):
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
        elif tok in ("}", "]"):
            if len(stack) > 1:
                stack.pop()
            pending = None
        elif "=" in tok:
            k, _, val = tok.partition("=")
            if val == "":
                pending = k
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
    padded = out
    for delim in "{}[]":
        padded = padded.replace(delim, f" {delim} ")
    return _vici_parse(padded.split())


def _iter_sections(node: object, markers: frozenset[str]):
    """Yield (name, section) for every dict carrying any of ``markers``."""
    if not isinstance(node, dict):
        return
    for name, val in node.items():
        if not isinstance(val, dict):
            continue
        if markers.intersection(val):
            # strip the \x00N disambiguation suffix from the surfaced name
            yield name.split("\x00", 1)[0], val
        else:
            yield from _iter_sections(val, markers)


def _first(v: object) -> str:
    if isinstance(v, list):
        return str(v[0]) if v else ""
    if isinstance(v, str):
        return v
    return ""


def _clean_ts(ts: str) -> str:
    """Normalize a strongSwan traffic selector to just the subnet."""
    if not ts:
        return ts
    return ts.split("|", 1)[0].split("[", 1)[0].strip()


def _is_shunt_conn(children: object) -> bool:
    if not isinstance(children, dict):
        return False
    modes = [str(c.get("mode", "")).upper() for c in children.values() if isinstance(c, dict)]
    return bool(modes) and not any(m in _TUNNEL_CHILD_MODES for m in modes)


def _child_rank(c: dict) -> tuple:
    return (c.get("state") == "INSTALLED", c.get("bytes_in", 0) + c.get("bytes_out", 0))


def _dedupe_children(children: list[dict]) -> list[dict]:
    """Collapse make-before-break child-SA rekey dups: one row per Phase-2."""
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
    """Parse ``swanctl --list-sas --raw`` into one record per active IKE_SA.

    Passive ``%any`` / ``CREATED`` half-open responder SAs are skipped — they carry
    no usable host or cookie; down tunnels come from ``--list-conns`` instead.
    """
    if not out.strip():
        return []
    sas = []
    for name, ike in _iter_sections(_tokenize_vici(out), _IKE_SA_MARKERS):
        if ike.get("local-host") == "%any" or str(ike.get("state", "")).upper() == "CREATED":
            continue
        children = ike.get("child-sas")
        child_rows: list[dict] = []
        if isinstance(children, dict):
            for ckey, child in children.items():
                if not isinstance(child, dict):
                    continue
                child_rows.append(
                    {
                        "name": _first(child.get("name")) or re.sub(r"-\d+$", "", ckey),
                        "local_ts": _clean_ts(_first(child.get("local-ts"))),
                        "remote_ts": _clean_ts(_first(child.get("remote-ts"))),
                        "state": str(child.get("state", "")).upper(),
                        "bytes_in": _to_int(child.get("bytes-in")),
                        "bytes_out": _to_int(child.get("bytes-out")),
                        "spi_in": str(child.get("spi-in", "")),
                        "spi_out": str(child.get("spi-out", "")),
                    }
                )
        child_rows = _dedupe_children(child_rows)
        sas.append(
            {
                "name": name,
                "remote": ike.get("remote-host", ""),
                "local": ike.get("local-host", ""),
                "status": ike.get("state", "unknown"),
                "phase2_up": sum(1 for c in child_rows if c["state"] == "INSTALLED"),
                "phase2_total": len(child_rows),
                "seconds_established": _to_int(ike.get("established")),
                "bytes_in": sum(c["bytes_in"] for c in child_rows),
                "bytes_out": sum(c["bytes_out"] for c in child_rows),
                "unique_id": str(ike.get("uniqueid", "")),
                "ike_init_spi": str(ike.get("initiator-spi", "")),
                "ike_resp_spi": str(ike.get("responder-spi", "")),
                "children": child_rows,
            }
        )
    return sas


def _parse_swanctl_conns(out: str) -> list[dict]:
    """Parse ``swanctl --list-conns --raw`` into one record per configured tunnel."""
    if not out.strip():
        return []
    conns = []
    for name, conn in _iter_sections(_tokenize_vici(out), _CONN_MARKERS):
        children = conn.get("children")
        if _is_shunt_conn(children):
            continue
        child_rows: list[dict] = []
        if isinstance(children, dict):
            for ckey, child in children.items():
                if not isinstance(child, dict):
                    continue
                child_rows.append(
                    {
                        "name": ckey,
                        "local_ts": _clean_ts(_first(child.get("local-ts"))),
                        "remote_ts": _clean_ts(_first(child.get("remote-ts"))),
                    }
                )
        conns.append(
            {
                "name": name,
                "local": _first(conn.get("local_addrs")),
                "remote": _first(conn.get("remote_addrs")),
                "phase2_total": len(children) if isinstance(children, dict) else 0,
                "children": child_rows,
            }
        )
    return conns


def _child_row(cc: dict | None, sc: dict | None) -> dict:
    cc = cc or {}
    sc = sc or {}
    return {
        "name": cc.get("name") or sc.get("name") or "",
        "local_ts": cc.get("local_ts") or sc.get("local_ts") or "",
        "remote_ts": cc.get("remote_ts") or sc.get("remote_ts") or "",
        "state": sc.get("state", ""),
        "bytes_in": sc.get("bytes_in", 0),
        "bytes_out": sc.get("bytes_out", 0),
        "spi_in": sc.get("spi_in", ""),
        "spi_out": sc.get("spi_out", ""),
    }


def _merge_children(conn_children: list[dict], sa_children: list[dict]) -> list[dict]:
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


def _sa_rank(sa: dict) -> tuple:
    return (
        str(sa.get("status", "")).upper() == "ESTABLISHED",
        sa.get("phase2_up", 0),
        sa.get("bytes_in", 0) + sa.get("bytes_out", 0),
    )


def _index_best(sas: list[dict], key: Any) -> dict:
    best: dict = {}
    for s in sas:
        k = key(s)
        cur = best.get(k)
        if cur is None or _sa_rank(s) > _sa_rank(cur):
            best[k] = s
    return best


def _to_tunnel(name: str, conn: dict | None, sa: dict | None) -> IPsecTunnel:
    conn = conn or {}
    children = [
        IPsecChild(**c)
        for c in _merge_children(conn.get("children", []), (sa or {}).get("children", []))
    ]
    if sa is not None:
        return IPsecTunnel(
            id=name,
            description=name,
            remote=sa["remote"] or conn.get("remote", ""),
            local=sa["local"] or conn.get("local", ""),
            phase1_status=sa["status"],
            phase2_up=sa.get("phase2_up", 0),
            # max(): Securepoint configures one phase-2 with N remote subnets, which
            # strongSwan instantiates as N child SAs — the live count is the truth.
            phase2_total=max(conn.get("phase2_total", 0), sa.get("phase2_total", 0)),
            seconds_established=sa.get("seconds_established", 0),
            bytes_in=sa["bytes_in"],
            bytes_out=sa["bytes_out"],
            unique_id=sa["unique_id"],
            ike_init_spi=sa.get("ike_init_spi", ""),
            ike_resp_spi=sa.get("ike_resp_spi", ""),
            children=children,
        )
    return IPsecTunnel(
        id=name,
        description=name,
        remote=conn.get("remote", ""),
        local=conn.get("local", ""),
        phase1_status="down",
        phase2_total=conn.get("phase2_total", 0),
        children=children,
    )


def parse_ipsec(sas_raw: str, conns_raw: str) -> list[IPsecTunnel]:
    """Merge live SA status onto configured connections → Orbit tunnel rows."""
    sas = _parse_swanctl_sas(sas_raw)
    conns = _parse_swanctl_conns(conns_raw)
    sa_by_name = _index_best(sas, lambda s: s["name"])
    sa_by_ep = _index_best(sas, lambda s: (s["local"], s["remote"]))

    tunnels: list[IPsecTunnel] = []
    used_names: set[str] = set()
    used_eps: set[tuple[str, str]] = set()
    for c in conns:
        sa = sa_by_name.get(c["name"]) or sa_by_ep.get((c["local"], c["remote"]))
        if sa is not None:
            used_names.add(sa["name"])
            used_eps.add((sa["local"], sa["remote"]))
        tunnels.append(_to_tunnel(c["name"], c, sa))
    for s in sas:
        ep = (s["local"], s["remote"])
        if s["name"] in used_names or ep in used_eps:
            continue
        used_names.add(s["name"])
        used_eps.add(ep)
        best = sa_by_name.get(s["name"], s)
        tunnels.append(_to_tunnel(best["name"], None, best))
    return tunnels


def ipsec_status_from_swanctl(sas_raw: str, conns_raw: str, *, running: bool) -> IPsecServiceStatus:
    return IPsecServiceStatus(running=running, tunnels=parse_ipsec(sas_raw, conns_raw))


# --- per-tunnel scoping for the diagnose bundle -------------------------------
# Mirrors ``_slice_plain_conn`` / ``_slice_raw_conn`` in ``agent/orbit_agent.py``
# (separate app, can't import). ``swanctl --list-conns`` has no per-connection
# filter, so the box returns every tunnel and we slice to the selected one here —
# before the bundle reaches the LLM context — so the AI sees one tunnel, not all.


def slice_plain_conn(text: str, name: str) -> str:
    """Keep only the ``swanctl --list-conns`` block for connection ``name``.

    Plain output starts each connection at column 0 (``<name>: IKEv2, …``) with
    its Phase-2 children indented beneath; capture from our header to the next
    column-0 line.
    """
    kept: list[str] = []
    capturing = False
    for line in text.splitlines():
        is_header = bool(line.strip()) and line[:1] not in (" ", "\t")
        if is_header:
            capturing = line.startswith(name + ":") or line.startswith(name + " ")
        if capturing:
            kept.append(line)
    return "\n".join(kept).strip()


def slice_raw_conn(raw: str, name: str) -> str:
    """Extract the single ``name { … }`` block from ``swanctl --list-conns --raw``.

    Balanced-brace slice on the raw vici stream — keeps the configured crypto
    proposals (encr/integ/dh/esp) the plain listing omits when left at the
    strongSwan default. Returns "" when the connection is absent or the stream
    is unbalanced.
    """
    if not name:
        return ""  # empty needle would match at every offset and never advance
    pos = 0
    while True:
        idx = raw.find(name, pos)
        if idx < 0:
            return ""
        boundary = idx == 0 or raw[idx - 1] in "{ \t\n"
        rest = raw[idx + len(name) :]
        body = rest.lstrip()
        if boundary and body[:1] == "{":
            start = idx + len(name) + (len(rest) - len(body))
            depth = 0
            for j in range(start, len(raw)):
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                    if depth == 0:
                        return name + " " + raw[start : j + 1]
            return ""  # unbalanced — give up rather than emit garbage
        pos = idx + len(name)
