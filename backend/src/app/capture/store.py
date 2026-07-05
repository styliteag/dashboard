"""Temporary storage for remote packet captures (bounded tcpdump pcaps).

Captures are kept in memory (with 1h TTL) keyed by short random id.
They are scoped only by possession of the id (the trigger already checked
instance access). Raw pcap bytes are kept for download + basic parsing for
the in-browser viewer. No encryption at rest (pcaps are diagnostic, short lived).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# cap_id -> Capture
_STORE: dict[str, Capture] = {}
TTL_SECONDS = 3600


@dataclass
class Capture:
    pcap: bytes
    meta: dict
    created: float
    instance_id: int


def _cleanup() -> None:
    now = time.time()
    for cid in list(_STORE):
        if now - _STORE[cid].created > TTL_SECONDS:
            _STORE.pop(cid, None)


def store(instance_id: int, pcap: bytes, meta: dict) -> str:
    """Store and return a short capture id."""
    _cleanup()
    # short id, 12 chars enough for in-mem
    cid = __import__("uuid").uuid4().hex[:12]
    _STORE[cid] = Capture(pcap=pcap, meta=meta, created=time.time(), instance_id=instance_id)
    return cid


def get(cid: str) -> Capture | None:
    _cleanup()
    return _STORE.get(cid)


def get_pcap(cid: str) -> bytes | None:
    cap = get(cid)
    return cap.pcap if cap else None


def get_meta(cid: str) -> dict | None:
    cap = get(cid)
    if not cap:
        return None
    return {"instance_id": cap.instance_id, **cap.meta}
