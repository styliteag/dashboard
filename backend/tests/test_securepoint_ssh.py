"""Unit tests for the Securepoint SSH host-key comparison helper.

The connect/run paths need a live SSH server and are exercised manually; this pins
down the pure host-key identity-extraction used for fail-closed pinning.
"""

from __future__ import annotations

import pytest

from app.securepoint.ssh import (
    SecurepointSSHError,
    SSHConfig,
    _connect,
    _key_blob,
    _parse_sections,
    fetch_ipsec_status,
)


def test_key_blob_extracts_identity_ignoring_comment() -> None:
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOg2zyW90uxt9vdS"
    # Same key, different comments → same blob (so a re-labeled host key still matches).
    assert _key_blob(f"ssh-ed25519 {blob} root@box") == blob
    assert _key_blob(f"ssh-ed25519 {blob}") == blob
    assert _key_blob(f"ssh-ed25519 {blob} a different comment here") == blob


def test_key_blob_distinguishes_different_keys() -> None:
    a = _key_blob("ssh-ed25519 AAAAaaaa first")
    b = _key_blob("ssh-ed25519 AAAAbbbb second")
    assert a != b


def test_key_blob_handles_malformed_line() -> None:
    assert _key_blob("garbage") == "garbage"
    assert _key_blob("  spaced  ") == "spaced"


def test_ssh_config_defaults() -> None:
    cfg = SSHConfig(host="h", port=9922, user="root", private_key="KEY")
    assert cfg.host_key is None  # unpinned by default


def test_parse_sections_splits_on_markers() -> None:
    out = (
        "@@SEC@@Connection config\nbonis-test: IKEv2\n  local: %any\n"
        "@@SEC@@Recent IPsec log (charon)\nline1\nline2\n"
        "@@SEC@@Peer reachability\nping 1.2.3.4:\n"
    )
    secs = _parse_sections(out)
    assert [s.title for s in secs] == [
        "Connection config",
        "Recent IPsec log (charon)",
        "Peer reachability",
    ]
    assert secs[0].content == "bonis-test: IKEv2\n  local: %any"
    assert secs[1].content == "line1\nline2"


def test_parse_sections_empty() -> None:
    assert _parse_sections("") == []
    assert _parse_sections("no markers here\njust text") == []


# --- fail-closed host-key handling (no network: the guard raises first) -------


@pytest.mark.asyncio
async def test_connect_refuses_unpinned_host_key() -> None:
    # A command-running connection must refuse to proceed without a pinned key,
    # before any socket is opened.
    with pytest.raises(SecurepointSSHError, match="not pinned"):
        await _connect("h", 9922, "root", "PRIVATE_KEY", host_key=None)


@pytest.mark.asyncio
async def test_fetch_ipsec_status_fails_closed_when_unpinned() -> None:
    # The caller (SecurepointClient.ipsec_status) catches this and falls back to spcgi.
    with pytest.raises(SecurepointSSHError):
        await fetch_ipsec_status("h", 9922, "root", "PRIVATE_KEY", None, running=True)


@pytest.mark.asyncio
async def test_connect_unpinned_allowed_on_probe_path() -> None:
    # require_host_key=False (the probe/TOFU path) bypasses the pin guard; an empty
    # private key makes it fail on the NEXT check, proving it got past the guard.
    with pytest.raises(SecurepointSSHError, match="no SSH private key"):
        await _connect("h", 9922, "root", "  ", host_key=None, require_host_key=False)
