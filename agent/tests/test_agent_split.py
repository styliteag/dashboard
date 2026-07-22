"""Agent split (§28), phase 1: the linux line exists as its own single-file
agent with its own identity. Content divergence (stripping firewall code from
the linux line and linux code from the firewall line) comes in later phases —
until then both lines must stay functionally identical, so a linux node that
self-updates from the old combined agent onto the linux line loses nothing.
"""

import re

import orbit_agent
import orbit_agent_linux


def _vkey(version: str):
    return tuple(int(x) for x in version.split("."))


def test_linux_line_has_its_own_strictly_newer_version():
    # Strictly newer than the firewall line's: deployed linux nodes still run
    # the combined agent, and their anti-rollback only accepts a numerically
    # newer version — equal or older would strand them on the old file.
    assert orbit_agent_linux.__version__ != orbit_agent.__version__
    assert _vkey(orbit_agent_linux.__version__) > _vkey(orbit_agent.__version__)


def test_linux_version_is_purely_numeric_dotted():
    # A suffix like "-rc1" makes the anti-rollback parser refuse ALL updates.
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent_linux.__version__)


def test_phase_1_keeps_the_lines_functionally_identical():
    assert orbit_agent_linux._SNAPSHOT_SECTIONS == orbit_agent._SNAPSHOT_SECTIONS
    assert set(orbit_agent_linux._COMMANDS) == set(orbit_agent._COMMANDS)


def test_both_lines_bake_the_same_update_pubkey():
    # One key chain for all root-run code (§25) — and signing must stay ON.
    assert orbit_agent_linux._UPDATE_PUBKEY == orbit_agent._UPDATE_PUBKEY
    assert orbit_agent_linux._UPDATE_PUBKEY
