"""Persist + prune agent-pushed config.xml versions (encrypted at rest).

The agent sends ``{sha256, size, content_gz_b64}`` only when the file changed;
``record_config_backup`` additionally dedupes against the newest stored version
so an agent restart (which re-pushes its baseline) never creates a duplicate
row. Content is stored as a Fernet token — config.xml carries secrets. The pure
helpers (``decode_payload``, ``unified_config_diff``) carry the logic and are
unit-tested; the DB functions are thin wrappers verified live.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import zlib

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto.secrets import decrypt, encrypt
from app.db.models import ConfigBackup
from app.logs.store import surplus_ids

KEEP_PER_INSTANCE = 30
# Plaintext cap. MEDIUMBLOB holds 16 MB; the Fernet token of 8 MB stays under that.
MAX_BYTES = 8_000_000
DIFF_MAX_LINES = 4000
# Refuse to diff versions beyond this many lines (SequenceMatcher DoS guard).
DIFF_MAX_INPUT_LINES = 150_000


def _gunzip_capped(data: bytes, max_bytes: int) -> bytes | None:
    """Gunzip with an output cap so a tiny compressed bomb can't balloon memory."""
    d = zlib.decompressobj(wbits=31)  # 31 = gzip container
    try:
        out = d.decompress(data, max_bytes + 1)
    except zlib.error:
        return None
    if len(out) > max_bytes or not d.eof:
        return None
    return out


def decode_payload(payload: object, max_bytes: int = MAX_BYTES) -> tuple[str, str] | None:
    """Validate an agent config push into ``(sha256, xml_text)``.

    Rejects malformed payloads, over-cap content, and content whose sha256
    doesn't match the agent's claim (truncated/corrupt transfer)."""
    if not isinstance(payload, dict):
        return None
    b64 = payload.get("content_gz_b64")
    claimed = str(payload.get("sha256") or "")
    if not b64 or not claimed:
        return None
    try:
        gz = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        return None
    raw = _gunzip_capped(gz, max_bytes)
    if raw is None:
        return None
    if hashlib.sha256(raw).hexdigest() != claimed:
        return None
    return claimed, raw.decode("utf-8", errors="replace")


def unified_config_diff(
    a: str,
    b: str,
    from_label: str,
    to_label: str,
    max_lines: int = DIFF_MAX_LINES,
    max_input_lines: int = DIFF_MAX_INPUT_LINES,
) -> tuple[str, bool]:
    """Unified diff between two config texts, capped at ``max_lines`` lines.

    CPU-bound (SequenceMatcher is ~O(n*m) on line counts) — callers in async
    context must run it via ``asyncio.to_thread``. Oversized inputs are refused
    outright so a pathological version pair can't burn minutes of CPU."""
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    if max(len(a_lines), len(b_lines)) > max_input_lines:
        return "(versions too large to diff — download both and compare locally)", True
    out: list[str] = []
    for line in difflib.unified_diff(
        a_lines, b_lines, fromfile=from_label, tofile=to_label, lineterm=""
    ):
        if len(out) >= max_lines:
            return "\n".join(out), True
        out.append(line)
    return "\n".join(out), False


async def _newest_first_ids(session: AsyncSession, instance_id: int) -> list[int]:
    rows = await session.execute(
        select(ConfigBackup.id)
        .where(ConfigBackup.instance_id == instance_id)
        .order_by(ConfigBackup.collected_at.desc(), ConfigBackup.id.desc())
    )
    return list(rows.scalars().all())


async def _latest_sha(session: AsyncSession, instance_id: int) -> str | None:
    row = await session.execute(
        select(ConfigBackup.sha256)
        .where(ConfigBackup.instance_id == instance_id)
        .order_by(ConfigBackup.collected_at.desc(), ConfigBackup.id.desc())
        .limit(1)
    )
    return row.scalars().first()


async def record_config_backup(
    session: AsyncSession, instance_id: int, payload: object, source: str = "agent"
) -> bool:
    """Store one pushed config version; dedupe against the newest stored sha.

    Returns True when a new version row was created."""
    decoded = decode_payload(payload)
    if decoded is None:
        return False
    sha, text = decoded
    if await _latest_sha(session, instance_id) == sha:
        return False
    # encrypt() on a multi-MB config is CPU-bound — keep it off the event loop
    # (this runs inside the agent-ingest path, which serves every agent).
    content_enc = await asyncio.to_thread(encrypt, text)
    session.add(
        ConfigBackup(
            instance_id=instance_id,
            sha256=sha,
            bytes=len(text.encode()),
            source=source,
            content_enc=content_enc,
        )
    )
    await session.flush()
    extra = surplus_ids(await _newest_first_ids(session, instance_id), keep=KEEP_PER_INSTANCE)
    if extra:
        await session.execute(delete(ConfigBackup).where(ConfigBackup.id.in_(extra)))
    return True


async def list_config_backups(session: AsyncSession, instance_id: int) -> list[ConfigBackup]:
    rows = await session.execute(
        select(
            ConfigBackup.id,
            ConfigBackup.collected_at,
            ConfigBackup.sha256,
            ConfigBackup.bytes,
            ConfigBackup.source,
        )
        .where(ConfigBackup.instance_id == instance_id)
        .order_by(ConfigBackup.collected_at.desc(), ConfigBackup.id.desc())
    )
    return list(rows.all())


async def get_config_backup(
    session: AsyncSession, instance_id: int, backup_id: int
) -> ConfigBackup | None:
    """A single stored version, scoped to the instance (cross-instance ids miss)."""
    row = await session.execute(
        select(ConfigBackup).where(
            ConfigBackup.id == backup_id, ConfigBackup.instance_id == instance_id
        )
    )
    return row.scalars().first()


def config_text(row: ConfigBackup) -> str:
    """Decrypt a stored version back to XML text (server-side only)."""
    return decrypt(row.content_enc)
