"""Unit tests for the Securepoint SSH host-key comparison helper.

The connect/run paths need a live SSH server and are exercised manually; this pins
down the pure host-key identity-extraction used for fail-closed pinning.
"""

from __future__ import annotations

import pytest

from app.securepoint.ssh import (
    _PLAIN_TITLE,
    _RAW_TITLE,
    SecurepointSSHError,
    SSHConfig,
    _connect,
    _diag_script,
    _key_blob,
    _parse_sections,
    _scope_sections,
    fetch_ipsec_status,
)
from app.xsense.schemas import DiagnosisSection

# Two-tunnel swanctl output: the box has no per-connection filter, so the diagnose
# bundle scopes these down to the selected tunnel before returning.
_PLAIN_TWO = (
    "tunA: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 10s\n"
    "  local:  1.1.1.1[500]\n"
    "  remote: 2.2.2.2[500]\n"
    "tunB: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 10s\n"
    "  local:  1.1.1.1[500]\n"
    "  remote: 3.3.3.3[500]\n"
)
_RAW_TWO = (
    "list-conn event {tunA {remote_addrs=[2.2.2.2] "
    "proposals {0 {encr=[AES_CBC_256] ke=[MODP_2048]}}} "
    "tunB {remote_addrs=[3.3.3.3] proposals {0 {encr=[AES_CBC_128]}}}}"
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


# --- per-tunnel scoping of the diagnose bundle --------------------------------


def test_diag_script_emits_plain_and_raw_conns() -> None:
    script = _diag_script("tunA")
    assert "swanctl --list-conns 2>&1" in script
    assert "swanctl --list-conns --raw 2>&1" in script
    assert _RAW_TITLE in script
    # the SAs block stays scoped on the box with --ike
    assert 'swanctl --list-sas --ike "$N"' in script


def test_scope_sections_slices_both_config_blocks_to_selected() -> None:
    sections = [
        DiagnosisSection(title=_PLAIN_TITLE, content=_PLAIN_TWO),
        DiagnosisSection(title=_RAW_TITLE, content=_RAW_TWO),
        DiagnosisSection(title="Peer reachability", content="ping 2.2.2.2"),
    ]
    out = {s.title: s.content for s in _scope_sections(sections, "tunA")}
    # plain block: only tunA survives
    assert out[_PLAIN_TITLE].startswith("tunA: IKEv2")
    assert "tunB" not in out[_PLAIN_TITLE]
    assert "3.3.3.3" not in out[_PLAIN_TITLE]
    # raw block: only tunA, with its proposals
    assert out[_RAW_TITLE].startswith("tunA {")
    assert "AES_CBC_256" in out[_RAW_TITLE]
    assert "AES_CBC_128" not in out[_RAW_TITLE]
    assert "tunB" not in out[_RAW_TITLE]
    # unrelated section untouched
    assert out["Peer reachability"] == "ping 2.2.2.2"


def test_scope_sections_missing_conn_notes_absence() -> None:
    sections = [DiagnosisSection(title=_PLAIN_TITLE, content=_PLAIN_TWO)]
    out = _scope_sections(sections, "no-such-tunnel")
    assert out[0].content == "(connection not found)"
