"""Tests for the agent self-update primitives (DR-5).

The deterministic parts (verify, stage/swap, rollback, probation cleanup) are
unit-tested here. The restart + supervisor rollback are integration-tested live
on a real box with the operator present.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import orbit_agent as agent
import pytest
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    return priv, pub


def test_ed25519_verify_interop_with_cryptography() -> None:
    # The pure-stdlib verify must agree with a real Ed25519 signer (RFC 8032).
    priv, pub = _keypair()
    for msg in (b"", b"agent code", b"\x00\xff" * 100):
        assert agent._ed25519_verify(priv.sign(msg), msg, pub) is True


def test_ed25519_verify_rejects_tampering() -> None:
    priv, pub = _keypair()
    sig = priv.sign(b"original")
    assert agent._ed25519_verify(sig, b"tampered", pub) is False  # wrong message
    bad = bytearray(sig)
    bad[0] ^= 1
    assert agent._ed25519_verify(bytes(bad), b"original", pub) is False  # mangled sig
    _, other = _keypair()
    assert agent._ed25519_verify(sig, b"original", other) is False  # wrong key


def test_signature_disabled_without_pubkey(monkeypatch: pytest.MonkeyPatch) -> None:
    # empty _UPDATE_PUBKEY → signing not enforced (dev). Forced here so the test is
    # independent of whether this build ships a baked production key.
    monkeypatch.setattr(agent, "_UPDATE_PUBKEY", "")
    assert agent._signature_ok(b"anything", "") is True


def test_shipped_build_enforces_signing() -> None:
    # Guard: this build must ship a baked, valid Ed25519 public key (32 bytes hex),
    # so signing stays enforced and an accidental blank-out is caught in CI.
    assert agent._UPDATE_PUBKEY != "", "agent ships with signing DISABLED"
    assert len(bytes.fromhex(agent._UPDATE_PUBKEY)) == 32


def test_signature_enforced_with_pubkey(monkeypatch: pytest.MonkeyPatch) -> None:
    priv, pub = _keypair()
    monkeypatch.setattr(agent, "_UPDATE_PUBKEY", pub.hex())
    code = b"new agent code"
    sig_b64 = base64.b64encode(priv.sign(code)).decode()
    assert agent._signature_ok(code, sig_b64) is True
    assert agent._signature_ok(b"forged code", sig_b64) is False  # signature/code mismatch
    assert agent._signature_ok(code, "!!notbase64") is False


def test_skip_sig_check_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_INSECURE_SKIP_SIG", raising=False)
    monkeypatch.setattr(agent, "cfg", SimpleNamespace(insecure_skip_sig=False), raising=False)
    assert agent._skip_sig_check() is False


def test_skip_sig_check_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "cfg", SimpleNamespace(insecure_skip_sig=False), raising=False)
    monkeypatch.setenv("AGENT_INSECURE_SKIP_SIG", "1")
    assert agent._skip_sig_check() is True


def test_skip_sig_check_via_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_INSECURE_SKIP_SIG", raising=False)
    monkeypatch.setattr(agent, "cfg", SimpleNamespace(insecure_skip_sig=True), raising=False)
    assert agent._skip_sig_check() is True


def test_verify_accepts_matching_sha_and_valid_syntax() -> None:
    code = b"x = 1\n"
    assert agent._verify_update_code(code, hashlib.sha256(code).hexdigest()) is True


def test_verify_rejects_bad_sha() -> None:
    assert agent._verify_update_code(b"x = 1\n", "deadbeef") is False


def test_verify_rejects_syntax_error() -> None:
    code = b"def (:\n"  # not valid Python
    assert agent._verify_update_code(code, hashlib.sha256(code).hexdigest()) is False


def test_apply_and_rollback(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "orbit_agent.py"
    target.write_bytes(b"OLD VERSION\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))

    agent._apply_update(b"NEW VERSION\n", "9.9.9")
    assert target.read_bytes() == b"NEW VERSION\n"
    assert (tmp_path / "orbit_agent.py.bak").read_bytes() == b"OLD VERSION\n"
    assert (tmp_path / "orbit_agent.py.updating").read_text() == "9.9.9"
    assert not (tmp_path / "orbit_agent.py.new").exists()  # temp consumed by rename

    assert agent._rollback() is True
    assert target.read_bytes() == b"OLD VERSION\n"
    assert not (tmp_path / "orbit_agent.py.updating").exists()


def test_clear_probation_removes_marker_and_backup(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "orbit_agent.py"
    target.write_bytes(b"X\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))
    (tmp_path / "orbit_agent.py.bak").write_bytes(b"OLD\n")
    (tmp_path / "orbit_agent.py.updating").write_text("1.0")

    agent._clear_probation()
    assert not (tmp_path / "orbit_agent.py.bak").exists()
    assert not (tmp_path / "orbit_agent.py.updating").exists()


def test_rollback_without_backup_returns_false(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "orbit_agent.py"
    target.write_bytes(b"X\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))
    assert agent._rollback() is False


# --- anti-rollback: gate on the version embedded in the signed code -----------


def test_code_version_extracts_embedded_version() -> None:
    assert agent._code_version(b'#!/usr/bin/env python3\n__version__ = "1.6.4"\nx=1\n') == "1.6.4"
    assert agent._code_version(b"__version__ = '0.3.0'\n") == "0.3.0"
    assert agent._code_version(b"x = 1\n# no version here\n") is None


def test_version_tuple_orders_numerically() -> None:
    assert agent._version_tuple("1.6.10") > agent._version_tuple("1.6.9")
    assert agent._version_tuple("1.6.3") == agent._version_tuple("1.6.3")
    assert agent._version_tuple("2.0.0") > agent._version_tuple("1.99.99")


def test_is_forward_update_accepts_strictly_newer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "__version__", "1.6.3")
    assert agent._is_forward_update(b'__version__ = "1.6.4"\nx=1\n') is True
    assert agent._is_forward_update(b'__version__ = "2.0.0"\n') is True


def test_is_forward_update_refuses_downgrade_and_same(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "__version__", "1.6.3")
    assert agent._is_forward_update(b'__version__ = "1.5.0"\n') is False  # older = replay
    assert agent._is_forward_update(b'__version__ = "1.6.3"\n') is False  # same


def test_is_forward_update_refuses_unversioned_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "__version__", "1.6.3")
    assert agent._is_forward_update(b"x = 1\n") is False  # no embedded version → refuse
