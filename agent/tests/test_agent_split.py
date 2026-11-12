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
    "storage",
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
    "checkmk_raw",
    "checkmk_status",
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
    # The two lines MAY version independently (each box only ever compares
    # within its own line) but MAY also share a number when re-aligned to the
    # product release version — so equality is allowed, only the format is fixed.
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent.__version__)
    assert re.fullmatch(r"\d+(\.\d+)+", orbit_agent_linux.__version__)


def test_registries_are_pinned_per_line():
    # Core sections pinned on both lines; drop-in parts (agent/src/<line>.d)
    # may append x_* sections only.
    fw_keys = [k for k, _ in orbit_agent._SNAPSHOT_SECTIONS]
    assert tuple(k for k in fw_keys if not k.startswith("x_")) == FIREWALL_SECTIONS
    # The linux line's CORE sections are pinned; a downstream/pro build may
    # append drop-in sections (agent/src/linux.d parts), which push under the
    # x_* vendor namespace the hub passthrough stores (§28). Anything not in
    # the core set must be an x_* extra — never a silent core edit.
    linux_keys = [k for k, _ in orbit_agent_linux._SNAPSHOT_SECTIONS]
    assert tuple(k for k in linux_keys if not k.startswith("x_")) == LINUX_SECTIONS
    for k in linux_keys:
        assert k in LINUX_SECTIONS or k.startswith("x_"), f"unexpected section {k!r}"


def test_linux_command_surface_is_pinned():
    # Every core command must be present; a downstream/pro build may add more
    # via drop-in parts (e.g. "zfs.scrub"), so this is a subset check, not
    # equality (the firewall line takes firewall.d parts the same way).
    assert LINUX_COMMANDS <= set(orbit_agent_linux._COMMANDS)


def test_checkmk_bridge_is_on_both_lines():
    # one shared source (agent/src/shared/checkmk.py), each line its own script
    for mod in (orbit_agent, orbit_agent_linux):
        assert "checkmk.update" in mod._COMMANDS
        assert hasattr(mod, "collect_checkmk")
    assert orbit_agent._CHECKMK_DEPLOY_PATH.endswith("check_mk_agent.freebsd")
    assert orbit_agent_linux._CHECKMK_DEPLOY_PATH.endswith("check_mk_agent.linux")
    # the linux line registers no status section; its values come from the output
    assert "checkmk_status" not in dict(orbit_agent_linux._SNAPSHOT_SECTIONS)


def test_firewall_line_has_no_linux_helpers():
    for name in (
        "_linux_update_check",
        "_apt_update_check",
        "_dnf_update_check",
        "_read_linux_version",
        "_collect_logfiles_linux",
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


def test_firewall_line_takes_drop_in_parts(tmp_path, monkeypatch):
    """agent/src/firewall.d/*.py parts are spliced into the firewall line like
    linux.d into the linux line: a part's command lands in _COMMANDS and its
    section at the end of _SNAPSHOT_SECTIONS (a downstream build adds
    firewall commands without editing firewall.py.in)."""
    import shutil
    import types

    build = _build_agent()
    src = tmp_path / "src"
    shutil.copytree(build.SRC, src)
    (src / "firewall.d").mkdir(exist_ok=True)
    (src / "firewall.d" / "50-probe.py").write_text(
        "def _cmd_probe(params):\n"
        "    return {'success': True, 'output': 'probe'}\n"
        "\n"
        "def collect_probe():\n"
        "    return {}\n"
        "\n"
        "_DROPIN_COMMANDS['probe.run'] = _cmd_probe\n"
        "_DROPIN_SECTIONS.append(('x_probe', 'collect_probe'))\n"
    )
    monkeypatch.setattr(build, "SRC", src)
    (src / "firewall.version").unlink(missing_ok=True)

    module = types.ModuleType("orbit_agent_probe")
    exec(compile(build.build("firewall.py.in"), "orbit_agent_probe", "exec"), module.__dict__)

    assert module._COMMANDS["probe.run"]({})["output"] == "probe"
    assert module._SNAPSHOT_SECTIONS[-1] == ("x_probe", "collect_probe")
