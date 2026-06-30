"""RFC 6238 TOTP primitive: round-trip, drift window, rejection, URI shape."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from app.auth import totp


def test_generate_secret_is_base32_and_unique() -> None:
    a = totp.generate_secret()
    b = totp.generate_secret()
    assert a != b
    # decodes as base32 (pad to a multiple of 8)
    import base64

    base64.b32decode(a + "=" * (-len(a) % 8))


def test_verify_accepts_current_code() -> None:
    secret = totp.generate_secret()
    code = totp._hotp(secret, int(1_700_000_000 // totp.PERIOD))
    assert totp.verify(secret, code, at=1_700_000_000)


def test_verify_accepts_one_step_drift() -> None:
    secret = totp.generate_secret()
    base = 1_700_000_000
    prev = totp._hotp(secret, int(base // totp.PERIOD) - 1)
    nxt = totp._hotp(secret, int(base // totp.PERIOD) + 1)
    assert totp.verify(secret, prev, at=base, window=1)
    assert totp.verify(secret, nxt, at=base, window=1)


def test_verify_rejects_two_step_drift() -> None:
    secret = totp.generate_secret()
    base = 1_700_000_000
    far = totp._hotp(secret, int(base // totp.PERIOD) + 2)
    assert not totp.verify(secret, far, at=base, window=1)


def test_verify_rejects_garbage() -> None:
    secret = totp.generate_secret()
    assert not totp.verify(secret, "abcdef", at=1_700_000_000)
    assert not totp.verify(secret, "", at=1_700_000_000)
    assert not totp.verify(secret, "12345", at=1_700_000_000)  # wrong length


def test_verify_rejects_wrong_code() -> None:
    secret = totp.generate_secret()
    good = totp._hotp(secret, int(1_700_000_000 // totp.PERIOD))
    bad = str((int(good) + 1) % 1_000_000).zfill(6)
    assert not totp.verify(secret, bad, at=1_700_000_000)


def test_provisioning_uri_shape() -> None:
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(secret, account="admin", issuer="Orbit Dashboard")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    q = parse_qs(parsed.query)
    assert q["secret"] == [secret]
    assert q["issuer"] == ["Orbit Dashboard"]
    assert q["digits"] == ["6"]
