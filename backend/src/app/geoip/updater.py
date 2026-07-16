"""Weekly GeoLite2-City download (DR-G1; City since 2026-07-16).

Pulls the official tarball from download.maxmind.com (HTTP basic auth with
account id + license key), extracts the single ``.mmdb`` member and replaces
the active database atomically — a crashed download can never leave a torn
file, and the lookup reader picks the new mtime up on its next call. Without
credentials the job is a no-op (manual volume updates keep working).

City replaced Country deliberately IN PLACE (same ``geoip_db_path``, historic
filename): the City edition carries identical country/continent records, so
the enforcement gate (``country_for``) is unaffected and existing deployments
upgrade seamlessly on their next download — no fail-open window from a path
switch. City merely adds city/subdivision detail for the UI hover labels.
"""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
from datetime import UTC, datetime

import httpx
import structlog

from app.config import get_settings

log = structlog.get_logger("app.geoip")

_DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download"
_MAX_TARBALL = 100 * 1024 * 1024  # GeoLite2-City is ~35 MB; 100 MB = clearly broken

# Last job outcome for the status endpoint (process-local, single worker).
_last: dict = {"at": None, "ok": None, "detail": "never ran"}


def last_download() -> dict:
    return dict(_last)


def _extract_mmdb(tarball: bytes) -> bytes:
    """The one ``*.mmdb`` member of the tarball. Never writes archive paths to
    disk (path traversal is irrelevant when we only read the member stream)."""
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith(".mmdb"):
                fh = tar.extractfile(member)
                if fh is not None:
                    return fh.read()
    raise ValueError("no .mmdb member in tarball")


async def refresh_geoip_db() -> dict:
    """Download + atomically install the current GeoLite2-City mmdb.

    Returns the outcome dict (also cached for the status endpoint).
    """
    settings = get_settings()
    account, key = settings.maxmind_account_id, settings.maxmind_license_key
    if not account or not key:
        return _finish(ok=None, detail="no maxmind credentials configured — job idle")
    try:
        async with httpx.AsyncClient(
            auth=(account, key), timeout=120.0, follow_redirects=True
        ) as client:
            resp = await client.get(_DOWNLOAD_URL, params={"suffix": "tar.gz"})
        if resp.status_code != 200:
            return _finish(ok=False, detail=f"download failed: HTTP {resp.status_code}")
        if len(resp.content) > _MAX_TARBALL:
            return _finish(ok=False, detail=f"tarball too large: {len(resp.content)} bytes")
        mmdb = _extract_mmdb(resp.content)
    except (httpx.HTTPError, tarfile.TarError, ValueError, OSError) as exc:
        return _finish(ok=False, detail=f"{exc.__class__.__name__}: {exc}")

    path = settings.geoip_db_path
    try:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".geoip-")
        with os.fdopen(fd, "wb") as f:
            f.write(mmdb)
        os.replace(tmp, path)
    except OSError as exc:
        return _finish(ok=False, detail=f"install failed: {exc}")
    return _finish(ok=True, detail=f"installed {len(mmdb)} bytes")


def _finish(ok: bool | None, detail: str) -> dict:
    _last.update(at=datetime.now(UTC).isoformat(), ok=ok, detail=detail)
    if ok is False:
        log.error("geoip.db_refresh_failed", detail=detail)
    else:
        log.info("geoip.db_refresh", detail=detail)
    return dict(_last)
