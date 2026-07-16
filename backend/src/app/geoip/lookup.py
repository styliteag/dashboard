"""Local GeoLite2 lookups (DR-G1; City edition since 2026-07-16) — no network calls, ever.

The reader auto-reopens when the mmdb file changes on disk (the weekly download
job atomically replaces it). A missing/broken database yields ``None`` country
and ``db_available() == False`` — the decision layer then fails OPEN by design
(DR-G5): a broken DB update must never lock the whole company out.
"""

from __future__ import annotations

import os
import threading

import maxminddb
import structlog

from app.config import get_settings

log = structlog.get_logger("app.geoip")

_lock = threading.Lock()
_reader: maxminddb.Reader | None = None
_reader_mtime: float | None = None


def _db_path() -> str:
    return get_settings().geoip_db_path


def _current_reader() -> maxminddb.Reader | None:
    """Open (or re-open after replacement) the mmdb reader; None when absent.

    One stat() per call — negligible next to request handling, and it makes a
    freshly downloaded DB active without any restart or explicit signal.
    """
    global _reader, _reader_mtime
    path = _db_path()
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        with _lock:
            if _reader is not None:
                _reader.close()
            _reader, _reader_mtime = None, None
        return None
    if _reader is not None and mtime == _reader_mtime:
        return _reader
    with _lock:
        if _reader is not None and mtime == _reader_mtime:
            return _reader
        try:
            fresh = maxminddb.open_database(path)
        except (OSError, maxminddb.InvalidDatabaseError) as exc:
            log.error("geoip.db_open_failed", path=path, error=str(exc))
            if _reader is not None:
                _reader.close()
            _reader, _reader_mtime = None, None
            return None
        if _reader is not None:
            _reader.close()
        _reader, _reader_mtime = fresh, mtime
        log.info("geoip.db_loaded", path=path)
        return _reader


def db_available() -> bool:
    return _current_reader() is not None


def country_for(ip: str) -> str | None:
    """ISO-3166-1 alpha-2 code for the IP (v4 or v6), or None.

    None for: private/loopback ranges (no country in the DB), unknown ranges,
    malformed input, missing DB. Callers must treat None per DR-G5.
    """
    reader = _current_reader()
    if reader is None:
        return None
    try:
        record = reader.get(ip)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    country = record.get("country") or record.get("registered_country") or {}
    iso = country.get("iso_code") if isinstance(country, dict) else None
    return iso if isinstance(iso, str) and len(iso) == 2 else None


def country_display(ip: str | None) -> tuple[str | None, str | None]:
    """(iso_code, hover label) for UI display of an IP's origin — never enforcement.

    The label is everything the local GeoLite2 DB knows beyond the code. With
    the City edition: "Frankfurt am Main, Hesse · Germany · Europe · EU"; a
    plain Country DB (older volumes) degrades to "Germany · Europe · EU", and
    missing pieces fall back to the bare code. The gate keeps using
    ``country_for``; do not swap them.
    """
    if not ip:
        return None, None
    reader = _current_reader()
    if reader is None:
        return None, None
    try:
        record = reader.get(ip)
    except ValueError:
        return None, None
    if not isinstance(record, dict):
        return None, None
    country = record.get("country") or record.get("registered_country") or {}
    if not isinstance(country, dict):
        return None, None
    iso = country.get("iso_code")
    if not (isinstance(iso, str) and len(iso) == 2):
        return None, None

    def _en(node: object) -> str | None:
        names = node.get("names") if isinstance(node, dict) else None
        return names.get("en") if isinstance(names, dict) else None

    # City-edition extras; absent in a plain Country DB. Subdivisions are
    # ordered largest→smallest, the last one is the most specific (state).
    city = _en(record.get("city"))
    subs = record.get("subdivisions")
    sub = _en(subs[-1]) if isinstance(subs, list) and subs else None
    place = ", ".join(p for p in (city, sub) if p)

    parts = [p for p in (place, _en(country) or iso, _en(record.get("continent"))) if p]
    if country.get("is_in_european_union"):
        parts.append("EU")
    return iso, " · ".join(parts)


def db_status() -> dict:
    """Facts for the superadmin status endpoint / UI banner."""
    path = _db_path()
    try:
        st = os.stat(path)
        present = True
        size = st.st_size
        mtime = st.st_mtime
    except OSError:
        present, size, mtime = False, 0, None
    return {
        "path": path,
        "present": present,
        "readable": db_available(),
        "size_bytes": size,
        "modified_unix": mtime,
    }
