"""Pure helpers of the config-backup store: payload decode + unified diff.

The DB functions are thin wrappers (verified live); the decode/diff logic
carries the correctness risk and is unit-tested here.
"""

from __future__ import annotations

import base64
import gzip
import hashlib

from app.configbackup.store import (
    KEEP_PER_INSTANCE,
    decode_payload,
    unified_config_diff,
)
from app.logs.store import surplus_ids

_XML = "<opnsense>\n  <system>\n    <hostname>fw1</hostname>\n  </system>\n</opnsense>\n"


def _payload(text: str = _XML, sha: str | None = None) -> dict:
    raw = text.encode()
    return {
        "sha256": sha or hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "content_gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
    }


def test_decode_payload_roundtrip():
    decoded = decode_payload(_payload())
    assert decoded is not None
    sha, text = decoded
    assert text == _XML
    assert sha == hashlib.sha256(_XML.encode()).hexdigest()


def test_decode_payload_rejects_sha_mismatch():
    assert decode_payload(_payload(sha="0" * 64)) is None


def test_decode_payload_rejects_garbage():
    assert decode_payload({"sha256": "x", "content_gz_b64": "not-base64!!!"}) is None
    assert decode_payload({"sha256": "x"}) is None
    assert decode_payload("nope") is None
    assert decode_payload({}) is None


def test_decode_payload_caps_decompressed_size():
    # A highly compressible payload must not expand past the cap (zip-bomb guard).
    big = "a" * 1000
    payload = _payload(big)
    assert decode_payload(payload, max_bytes=100) is None


def test_unified_diff_marks_changes():
    a = "<a>\n<hostname>fw1</hostname>\n</a>\n"
    b = "<a>\n<hostname>fw2</hostname>\n</a>\n"
    diff, truncated = unified_config_diff(a, b, "v1", "v2")
    assert not truncated
    assert "-<hostname>fw1</hostname>" in diff
    assert "+<hostname>fw2</hostname>" in diff
    assert "--- v1" in diff and "+++ v2" in diff


def test_unified_diff_identical_is_empty():
    diff, truncated = unified_config_diff(_XML, _XML, "v1", "v2")
    assert diff == ""
    assert not truncated


def test_unified_diff_truncates():
    a = "\n".join(f"line{i}" for i in range(500)) + "\n"
    b = "\n".join(f"LINE{i}" for i in range(500)) + "\n"
    diff, truncated = unified_config_diff(a, b, "v1", "v2", max_lines=50)
    assert truncated
    assert len(diff.splitlines()) <= 50


def test_unified_diff_refuses_oversized_input():
    a = "\n".join(f"line{i}" for i in range(20))
    diff, truncated = unified_config_diff(a, a, "v1", "v2", max_input_lines=10)
    assert truncated
    assert "too large to diff" in diff


def test_retention_uses_shared_surplus_helper():
    ids = list(range(100, 60, -1))  # newest first
    extra = surplus_ids(ids, keep=KEEP_PER_INSTANCE)
    assert len(extra) == len(ids) - KEEP_PER_INSTANCE
    assert extra[0] == ids[KEEP_PER_INSTANCE]
