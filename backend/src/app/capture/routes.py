"""Remote packet capture endpoints.

Trigger via agent (only for agent_mode instances), store temporarily,
serve pcap download and parsed packet list for the browser viewer.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.capture.store import get_meta, get_pcap
from app.capture.store import store as cap_store
from app.db.base import get_session
from app.db.models import User
from app.instances import service as inst_service
from app.net import client_ip

router = APIRouter(prefix="/captures", tags=["captures"])


@router.post("/instances/{instance_id}")
async def start_packet_capture(
    instance_id: int,
    payload: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Trigger a bounded tcpdump via the agent.

    payload: {
      "interface": "igb0",
      "filter": "host 10.0.0.5 and port 443",  # optional BPF
      "max_seconds": 30,
      "max_bytes": 1000000
    }
    Returns {capture_id, meta} on success. Use the id for download/view.
    """
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if not inst.agent_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="packet capture requires the push agent (not available for direct-poll)",
        )

    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent not connected",
        )

    # forward params, agent validates bounds
    result = await agent.send_command(
        "packet_capture",
        payload,
        timeout=int(payload.get("max_seconds", 30)) + 60,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.get("output", "capture failed"),
        )

    pcap_b64 = result.get("pcap_b64") or ""
    if not pcap_b64:
        raise HTTPException(status_code=502, detail="empty capture result")

    try:
        pcap = base64.b64decode(pcap_b64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"bad pcap data: {exc}") from exc

    meta = {
        "bytes": result.get("bytes", len(pcap)),
        "truncated": bool(result.get("truncated")),
        "interface": result.get("interface"),
        "filter": result.get("filter", ""),
        "max_seconds": result.get("max_seconds"),
        "max_bytes": result.get("max_bytes"),
        "stderr": result.get("stderr", ""),
    }

    cid = cap_store(instance_id, pcap, meta)

    await write_audit(
        session,
        action="packet_capture.start",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"capture_id": cid, "interface": meta["interface"], "bytes": meta["bytes"]},
    )
    await session.commit()

    return {"capture_id": cid, "meta": meta}


@router.get("/{cap_id}/pcap")
async def download_pcap(
    cap_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> Response:
    """Download the raw pcap. Authenticated users can fetch by id (id is opaque)."""
    pcap = get_pcap(cap_id)
    if pcap is None:
        raise HTTPException(status_code=404, detail="capture not found or expired")

    meta = get_meta(cap_id) or {}
    iid = meta.get("instance_id")
    # light check: if we can get the instance for the user, ok (prevents guessing across groups)
    if iid is not None:
        inst = await inst_service.get_instance(session, iid, user)
        if inst is None:
            raise HTTPException(status_code=404, detail="capture not found")

    await write_audit(
        session,
        action="packet_capture.download",
        result="ok",
        user_id=user.id,
        target_type="capture",
        target_id=cap_id,
        source_ip=client_ip(request),
    )
    await session.commit()

    return Response(
        content=pcap,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="capture-{cap_id}.pcap"'},
    )


@router.get("/{cap_id}/packets")
async def get_packets(
    cap_id: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> dict:
    """Return parsed packet summary for the in-browser viewer + meta."""
    pcap = get_pcap(cap_id)
    if pcap is None:
        raise HTTPException(status_code=404, detail="capture not found or expired")

    meta = get_meta(cap_id) or {}
    iid = meta.get("instance_id")
    if iid is not None:
        inst = await inst_service.get_instance(session, iid, user)
        if inst is None:
            raise HTTPException(status_code=404, detail="capture not found")

    packets = _parse_pcap(pcap, max_packets=2000)
    return {"capture_id": cap_id, "meta": meta, "packets": packets}


def _parse_pcap(data: bytes, max_packets: int = 2000) -> list[dict]:
    """Minimal pcap parser for summary (stdlib only). Ethernet + basic IP/TCP/UDP."""
    packets: list[dict] = []
    if len(data) < 24:
        return packets
    # skip global header (24 bytes)
    off = 24
    idx = 0
    while off + 16 <= len(data) and idx < max_packets:
        # packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)  little endian
        incl = int.from_bytes(data[off + 8 : off + 12], "little")
        if incl == 0 or off + 16 + incl > len(data):
            break
        frame = data[off + 16 : off + 16 + incl]
        ts = (
            int.from_bytes(data[off : off + 4], "little")
            + int.from_bytes(data[off + 4 : off + 8], "little") / 1_000_000.0
        )
        pkt = _summarize_frame(frame, ts, idx)
        packets.append(pkt)
        off += 16 + incl
        idx += 1
    return packets


def _summarize_frame(frame: bytes, ts: float, idx: int) -> dict:
    if len(frame) < 14:
        return {
            "idx": idx,
            "ts": round(ts, 6),
            "src": "",
            "dst": "",
            "proto": "RAW",
            "len": len(frame),
            "info": "",
            "hex": _hex(frame[:128]),
        }
    eth_type = int.from_bytes(frame[12:14], "big")
    if eth_type == 0x0800:  # IPv4
        return _parse_ipv4(frame[14:], ts, idx, len(frame))
    if eth_type == 0x86DD:  # IPv6
        return _parse_ipv6(frame[14:], ts, idx, len(frame))
    if eth_type == 0x0806:  # ARP
        return {
            "idx": idx,
            "ts": round(ts, 6),
            "src": "",
            "dst": "",
            "proto": "ARP",
            "len": len(frame),
            "info": "ARP",
            "hex": _hex(frame[:64]),
        }
    return {
        "idx": idx,
        "ts": round(ts, 6),
        "src": "",
        "dst": "",
        "proto": "ETH",
        "len": len(frame),
        "info": f"0x{eth_type:04x}",
        "hex": _hex(frame[:64]),
    }


def _parse_ipv4(ip: bytes, ts: float, idx: int, wire_len: int) -> dict:
    if len(ip) < 20:
        return {
            "idx": idx,
            "ts": round(ts, 6),
            "src": "",
            "dst": "",
            "proto": "IP",
            "len": wire_len,
            "info": "",
            "hex": _hex(ip[:64]),
        }
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    l4 = ip[ihl:] if len(ip) > ihl else b""
    if proto == 6:  # TCP
        if len(l4) >= 4:
            sport = int.from_bytes(l4[0:2], "big")
            dport = int.from_bytes(l4[2:4], "big")
            flags = l4[13] if len(l4) > 13 else 0
            fl: list[str] = []
            if flags & 0x02:
                fl.append("SYN")
            if flags & 0x10:
                fl.append("ACK")
            if flags & 0x01:
                fl.append("FIN")
            if flags & 0x04:
                fl.append("RST")
            info = f"{sport} → {dport} [{' '.join(fl) or ' '}]"
            if dport in (80, 443, 8080) or sport in (80, 443, 8080):
                info += " HTTP/TLS?"
            return {
                "idx": idx,
                "ts": round(ts, 6),
                "src": f"{src}:{sport}",
                "dst": f"{dst}:{dport}",
                "proto": "TCP",
                "len": wire_len,
                "info": info,
                "hex": _hex(ip[:128]),
            }
    elif proto == 17:  # UDP
        if len(l4) >= 4:
            sport = int.from_bytes(l4[0:2], "big")
            dport = int.from_bytes(l4[2:4], "big")
            info = f"{sport} → {dport}"
            if dport == 53 or sport == 53:
                info += " DNS"
            elif dport in (67, 68):
                info += " DHCP"
            return {
                "idx": idx,
                "ts": round(ts, 6),
                "src": f"{src}:{sport}",
                "dst": f"{dst}:{dport}",
                "proto": "UDP",
                "len": wire_len,
                "info": info,
                "hex": _hex(ip[:96]),
            }
    elif proto == 1:  # ICMP
        return {
            "idx": idx,
            "ts": round(ts, 6),
            "src": src,
            "dst": dst,
            "proto": "ICMP",
            "len": wire_len,
            "info": "ICMP",
            "hex": _hex(ip[:64]),
        }
    return {
        "idx": idx,
        "ts": round(ts, 6),
        "src": src,
        "dst": dst,
        "proto": f"IP/{proto}",
        "len": wire_len,
        "info": "",
        "hex": _hex(ip[:64]),
    }


def _parse_ipv6(ip: bytes, ts: float, idx: int, wire_len: int) -> dict:
    if len(ip) < 40:
        return {
            "idx": idx,
            "ts": round(ts, 6),
            "src": "",
            "dst": "",
            "proto": "IPv6",
            "len": wire_len,
            "info": "",
            "hex": _hex(ip[:64]),
        }
    proto = ip[6]
    src = ":".join(f"{int.from_bytes(ip[8 + i : 8 + i + 2], 'big'):x}" for i in range(0, 16, 2))
    dst = ":".join(f"{int.from_bytes(ip[24 + i : 24 + i + 2], 'big'):x}" for i in range(0, 16, 2))
    return {
        "idx": idx,
        "ts": round(ts, 6),
        "src": src,
        "dst": dst,
        "proto": f"IPv6/{proto}",
        "len": wire_len,
        "info": "",
        "hex": _hex(ip[:64]),
    }


def _hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)
