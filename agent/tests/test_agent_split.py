"""Agent split (§28), phase 2: the firewall line is slimmed — checkmk bridge,
linux collectors/branches and package-manager code live only in the linux
line. The linux line still carries the full combined feature set until phase 3
strips the firewall-only code from it, so a linux node that self-updates from
the old combined agent onto the linux line loses nothing.
"""

import re

import orbit_agent
import orbit_agent_linux


def test_both_versions_are_purely_numeric_dotted():
    # A suffix like "-rc1" makes the anti-rollback parser refuse ALL updates.
    # The two lines version independently since the split — no cross-line
    # ordering is required, each box only ever compares within its line.
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent.__version__)
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent_linux.__version__)
    assert orbit_agent.__version__ != orbit_agent_linux.__version__


def test_firewall_registry_is_the_linux_registry_minus_checkmk():
    # Phase 2: exactly one section left the firewall line. Order preserved —
    # anything else missing/extra means an accidental registry edit.
    linux_sections = [s for s in orbit_agent_linux._SNAPSHOT_SECTIONS if s[0] != "checkmk_raw"]
    assert list(orbit_agent._SNAPSHOT_SECTIONS) == linux_sections
    assert any(s[0] == "checkmk_raw" for s in orbit_agent_linux._SNAPSHOT_SECTIONS)


def test_checkmk_update_command_is_linux_line_only():
    assert "checkmk.update" not in orbit_agent._COMMANDS
    assert "checkmk.update" in orbit_agent_linux._COMMANDS
    # All other commands are still identical until phase 3.
    assert set(orbit_agent_linux._COMMANDS) - set(orbit_agent._COMMANDS) == {"checkmk.update"}


def test_firewall_line_has_no_linux_helpers():
    for name in (
        "_linux_update_check",
        "_apt_update_check",
        "_dnf_update_check",
        "_read_linux_version",
        "_collect_logfiles_linux",
        "collect_checkmk",
        "_checkmk_script_sha",
    ):
        assert not hasattr(orbit_agent, name), name
        assert hasattr(orbit_agent_linux, name), name


def test_both_lines_bake_the_same_update_pubkey():
    # One key chain for all root-run code (§25) — and signing must stay ON.
    assert orbit_agent_linux._UPDATE_PUBKEY == orbit_agent._UPDATE_PUBKEY
    assert orbit_agent._UPDATE_PUBKEY
