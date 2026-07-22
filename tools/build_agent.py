#!/usr/bin/env python3
"""Assemble the two single-file agent lines from shared + line-specific sources.

The agent ships as ONE file per line (DR-4: self-update swaps exactly one file,
no imports, no runtime build on the box). But the two lines — orbit_agent.py
(OPNsense/pfSense) and orbit_agent_linux.py (generic Linux, §28) — share ~820
lines of the most dangerous code (WS client, Ed25519 self-update, enrollment,
push loop, shell/capture, probation). Keeping that in one source and generating
the two files makes divergence impossible instead of merely test-guarded.

Sources live under agent/src/:
  - shared/<name>.py        one canonical copy of each shared block
  - firewall.py.in          the firewall line template
  - linux.py.in             the linux line template
  - linux.d/*.py            build-time drop-in parts (empty in the open build;
                            a downstream/pro build adds collectors here)

Templates carry directives, each on its own line:
  # @@shared: <name>        -> spliced with agent/src/shared/<name>.py
  # @@dropins: <dir>        -> spliced with sorted agent/src/<dir>/*.py parts

The generated files (agent/orbit_agent.py, agent/orbit_agent_linux.py) are
COMMITTED — self-update, serving and signing all read them as-is. `--check`
rebuilds in memory and fails if the committed files drift from the sources,
so `just agent-test` and release.sh catch a forgotten rebuild.

    python tools/build_agent.py            # write both agent files
    python tools/build_agent.py --check    # verify committed == freshly built
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "agent" / "src"

# template basename -> generated agent file
LINES = {
    "firewall.py.in": ROOT / "agent" / "orbit_agent.py",
    "linux.py.in": ROOT / "agent" / "orbit_agent_linux.py",
}

_SHARED_DIRECTIVE = "# @@shared: "
_DROPINS_DIRECTIVE = "# @@dropins: "


def _shared_block(name: str) -> str:
    body = (SRC / "shared" / f"{name}.py").read_text()
    return (
        f"# >>> shared:{name} — generated from agent/src/shared/{name}.py; "
        "edit there, run `just build-agent`\n"
        f"{body}"
        f"# <<< shared:{name}\n"
    )


def _dropin_block(dirname: str) -> str:
    parts = sorted(
        p for p in (SRC / dirname).glob("*.py") if not p.name.startswith("_")
    )
    if not parts:
        return f"# (no drop-in parts in agent/src/{dirname}/)\n"
    out = []
    for p in parts:
        out.append(
            f"# >>> dropin:{p.name} — from agent/src/{dirname}/{p.name}\n"
            f"{p.read_text()}"
            f"# <<< dropin:{p.name}\n"
        )
    return "".join(out)


def build(template: str) -> str:
    lines = []
    for line in (SRC / template).read_text().splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped.startswith(_SHARED_DIRECTIVE):
            lines.append(_shared_block(stripped[len(_SHARED_DIRECTIVE):].strip()))
        elif stripped.startswith(_DROPINS_DIRECTIVE):
            lines.append(_dropin_block(stripped[len(_DROPINS_DIRECTIVE):].strip()))
        else:
            lines.append(line)
    return "".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the committed agent files match a fresh build (no write)",
    )
    args = ap.parse_args()

    drift = []
    for template, dest in LINES.items():
        built = build(template)
        if args.check:
            current = dest.read_text() if dest.exists() else ""
            if built != current:
                drift.append(dest.relative_to(ROOT))
        else:
            dest.write_text(built)
            print(f"built {dest.relative_to(ROOT)} ({len(built.splitlines())} lines)")

    if args.check and drift:
        names = ", ".join(str(d) for d in drift)
        sys.exit(
            f"agent build drift: {names} differ from agent/src/. "
            "Run `just build-agent` and commit the result."
        )
    if args.check:
        print("agent files are in sync with agent/src/")


if __name__ == "__main__":
    main()
