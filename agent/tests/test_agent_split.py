"""Agent split (§28), phase 3: both lines are slim. The firewall line carries
the OPNsense/pfSense feature set (no checkmk/apt/journald), the linux line
carries only what a generic server needs (checkmk transport, apt/dnf,
journald) — each refuses to start on the other's platform, so a wrong update
push dies into the supervisor's probation rollback. These tests pin both
surfaces so an accidental registry/command edit on either line is loud.
"""

import importlib.util
import re
from pathlib import Path

import orbit_agent
import orbit_agent_linux

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _build_agent():
    """Import tools/build_agent.py by path (not on sys.path under the tools venv)."""
    spec = importlib.util.spec_from_file_location(
        "build_agent", _REPO_ROOT / "tools" / "build_agent.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FIREWALL_SECTIONS = (
    "system",
    "uptime",
    "loadavg",
    "cpu",
    "memory",
    "disks",
    "pf",
    "pf_top",
    "ntp",
    "interfaces",
    "gateways",
    "external_ip",
    "ipsec",
    "connectivity",
    "firmware",
    "firewall_log",
    "config",
    "services",
    "certificates",
    "logfiles",
    "config_backup",
)

LINUX_SECTIONS = (
    "system",
    "uptime",
    "disks",
    "ntp",
    "external_ip",
    "connectivity",
    "firmware",
    "logfiles",
    "checkmk_raw",
)

LINUX_COMMANDS = {
    "connectivity.ping_test",
    "firmware.check",
    "firmware.update",
    "firmware.upgrade",  # explicit refusal, not an unknown-command error
    "reboot",
    "checkmk.update",
    "firmware.upgrade_status",
    "ping",
    "packet_capture",
}


def test_both_versions_are_purely_numeric_dotted():
    # A suffix like "-rc1" makes the anti-rollback parser refuse ALL updates.
    # The two lines version independently — each box compares within its line.
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent.__version__)
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent_linux.__version__)
    assert orbit_agent.__version__ != orbit_agent_linux.__version__


def test_registries_are_pinned_per_line():
    assert tuple(k for k, _ in orbit_agent._SNAPSHOT_SECTIONS) == FIREWALL_SECTIONS
    assert tuple(k for k, _ in orbit_agent_linux._SNAPSHOT_SECTIONS) == LINUX_SECTIONS


def test_linux_command_surface_is_pinned():
    assert set(orbit_agent_linux._COMMANDS) == LINUX_COMMANDS


def test_checkmk_is_linux_line_only():
    assert "checkmk.update" not in orbit_agent._COMMANDS
    assert not hasattr(orbit_agent, "collect_checkmk")
    assert "checkmk.update" in orbit_agent_linux._COMMANDS


def test_firewall_line_has_no_linux_helpers():
    for name in (
        "_linux_update_check",
        "_apt_update_check",
        "_dnf_update_check",
        "_read_linux_version",
        "_collect_logfiles_linux",
        "collect_checkmk",
    ):
        assert not hasattr(orbit_agent, name), name
        assert hasattr(orbit_agent_linux, name), name


def test_linux_line_has_no_firewall_machinery():
    for name in (
        "_read_opnsense_version",
        "_read_pfsense_version",
        "_pfsense_switch_train",
        "_zfs_boot_snapshot",
        "_firewall_upgrade_status",
        "collect_ipsec",
        "collect_pf_top",
        "collect_gateways",
        "collect_firewall_log",
        "collect_config_backup",
        "_relay_http",
        "_gui_login",
        "_ensure_api_credentials",
        "_cmd_get_aliases",
    ):
        assert hasattr(orbit_agent, name), name
        assert not hasattr(orbit_agent_linux, name), name


def test_committed_agents_match_the_generator_output():
    """The generator gate (§28): the committed orbit_agent*.py must be exactly
    what tools/build_agent.py produces from agent/src/. This is what makes the
    shared core a single source of truth — a shared fix edited in the source
    reaches both lines, and a hand-edit of a generated file (or a forgotten
    rebuild) fails here loudly. Mirrors the sign_agent --verify gate."""
    build = _build_agent()
    for template, dest in build.LINES.items():
        assert build.build(template) == dest.read_text(), (
            f"{dest.name} is out of sync with agent/src/ — run `just build-agent` "
            "and commit the result (never hand-edit the generated file)"
        )


def test_shared_core_is_one_source_used_by_both_lines():
    """Every shared block is spliced into BOTH templates from the same source
    file, so byte-identity across the lines is structural, not test-enforced."""
    src = _REPO_ROOT / "agent" / "src"
    shared = {p.stem for p in (src / "shared").glob("*.py")}
    assert shared, "no shared blocks found"
    for template in ("firewall.py.in", "linux.py.in"):
        used = set(re.findall(r"# @@shared: ([a-z0-9-]+)", (src / template).read_text()))
        assert used == shared, f"{template} uses {sorted(used)}, shared has {sorted(shared)}"


def test_both_lines_bake_the_same_update_pubkey():
    # One key chain for all root-run code (§25) — and signing must stay ON.
    assert orbit_agent_linux._UPDATE_PUBKEY == orbit_agent._UPDATE_PUBKEY
    assert orbit_agent._UPDATE_PUBKEY
