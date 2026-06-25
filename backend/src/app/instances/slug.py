"""Derive and validate URL-safe slugs for instances (GUI-proxy persistent hosts).

A slug is the public DNS label in the prod GUI-proxy origin
``gui-<slug>.<domain>`` (see §18). It must be a valid DNS label: lowercase
``[a-z0-9-]``, no leading/trailing hyphen, 1..63 chars. The display ``name``
stays free-form — the slug is transliterated from it (German umlauts → ASCII
digraphs, other accents stripped) so "Firewall Büro Süd" → "firewall-buero-sued".
"""

from __future__ import annotations

import re
import unicodedata

MAX_SLUG_LEN = 63
_FALLBACK = "fw"

# German digraphs first: NFKD would split ü into "u" + combining mark, losing the
# "e", so map these explicitly before accent stripping. Keys are lowercase
# (slugify lowercases up front).
_DIGRAPHS = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def slugify_name(name: str) -> str:
    """Turn a free-form display name into a valid DNS-label slug (never empty)."""
    s = name.strip().lower()
    for src, dst in _DIGRAPHS.items():
        s = s.replace(src, dst)
    # Strip remaining combining accents (é → e).
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    # Anything not a DNS-label char becomes a separator; collapse and trim.
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    s = s[:MAX_SLUG_LEN].strip("-")  # re-trim: truncation may land on a hyphen
    return s or _FALLBACK


def is_valid_slug(value: str) -> bool:
    """True iff ``value`` is a valid DNS label usable as ``gui-<slug>``."""
    return bool(_SLUG_RE.fullmatch(value))
