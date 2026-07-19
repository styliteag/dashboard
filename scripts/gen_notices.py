#!/usr/bin/env python3
"""Generate THIRD-PARTY-NOTICES.md from the shipped runtime dependencies.

Stdlib-only. Run via ``just notices`` (out of the tools/ venv).

Two sources, both restricted to what actually ships in the production image:

* orbit    -> ``mix.lock`` closure, license + text from the fetched Hex deps
* vendored -> single files shipped verbatim (the Checkmk Linux agent)

The pypi and npm collectors died with the FastAPI+React stack at the orbit
cutover — the release image carries neither any more.

Dev/test tooling is intentionally excluded: it is not part of the distributed
artifact, so its licenses impose no attribution obligation on the image.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "THIRD-PARTY-NOTICES.md"
SBOM_OUT = ROOT / "sbom.cdx.json"



# --------------------------------------------------------------------------- #
# orbit (Elixir/Hex runtime deps of the release image)
# --------------------------------------------------------------------------- #
ORBIT = ROOT / "orbit"
# Dev bind-mount cache (compose-dev mounts ./orbit/data/deps to /app/deps);
# bare orbit/deps is the fallback for a host-side `mix deps.get`.
ORBIT_DEPS_DIRS = (ORBIT / "data" / "deps", ORBIT / "deps")

# mix.lock entries NOT shipped in the release: dev/test-only apps and
# build-time tooling (runtime: false / asset compilers). Everything else in
# the lock lands in `mix release` and carries an attribution obligation.
_ORBIT_EXCLUDE = {
    "phoenix_live_reload",  # only: :dev
    "lazy_html",  # only: :test
    "esbuild",  # runtime only in :dev; the binary never ships
    "tailwind",  # same
    "file_system",  # phoenix_live_reload dependency (dev-only closure)
}


def _orbit_deps_dir() -> Path | None:
    return next((d for d in ORBIT_DEPS_DIRS if d.is_dir()), None)


def _orbit_lock_entries() -> list[tuple[str, str, str]]:
    """(name, version, ecosystem) from mix.lock — hex and git entries."""
    lock = ORBIT / "mix.lock"
    if not lock.exists():
        return []
    text = lock.read_text()
    rows: list[tuple[str, str, str]] = []
    for m in re.finditer(r'"([a-z0-9_]+)": \{:hex, :[a-z0-9_]+, "([^"]+)"', text):
        rows.append((m.group(1), m.group(2), "hex"))
    # Git deps (heroicons/daisyui): sparse asset checkouts compiled INTO the
    # shipped css/components — attribution needed even though they are not
    # OTP apps in the release.
    for m in re.finditer(r'"([a-z0-9_]+)": \{:git, "([^"]+)", "([a-f0-9]{7,40})"', text):
        rows.append((m.group(1), m.group(3)[:12], "github:" + m.group(2)))
    return rows


# Sparse git checkouts (assets subtree only) carry no LICENSE file — both
# upstreams are MIT; link the canonical text instead of bundling none.
_ORBIT_GIT_LICENSES = {
    "heroicons": ("MIT", "https://github.com/tailwindlabs/heroicons/blob/master/LICENSE"),
    "daisyui": ("MIT", "https://github.com/saadeghi/daisyui/blob/master/LICENSE"),
}


def _orbit_license(dep_dir: Path) -> str:
    meta = dep_dir / "hex_metadata.config"
    if meta.exists():
        m = re.search(r'\{<<"licenses">>,\[(.*?)\]\}', meta.read_text(errors="replace"))
        if m:
            names = re.findall(r'<<"([^"]+)">>', m.group(1))
            if names:
                return " AND ".join(names)
    # Git deps have no hex metadata — read the LICENSE head instead.
    text = _orbit_license_text(dep_dir) or ""
    if "MIT License" in text or text.startswith("MIT"):
        return "MIT"
    return "UNKNOWN"


def _orbit_license_text(dep_dir: Path) -> str | None:
    for pattern in ("LICENSE*", "LICENCE*", "*/LICENSE*"):
        for p in sorted(dep_dir.glob(pattern)):
            if p.is_file():
                return p.read_text(errors="replace")
    return None


def collect_orbit() -> list[dict]:
    """Hex/git runtime deps of the orbit release (plan §M7: SBOM obligation)."""
    deps_dir = _orbit_deps_dir()
    rows: list[dict] = []
    for name, version, eco in sorted(_orbit_lock_entries()):
        if name in _ORBIT_EXCLUDE:
            continue
        dep_dir = deps_dir / name if deps_dir else None
        has_dir = dep_dir is not None and dep_dir.is_dir()
        license_name = _orbit_license(dep_dir) if has_dir else "UNKNOWN"
        text = _orbit_license_text(dep_dir) if has_dir else None

        if license_name == "UNKNOWN" and name in _ORBIT_GIT_LICENSES:
            license_name, canonical = _ORBIT_GIT_LICENSES[name]
            text = f"MIT — sparse asset checkout bundles no license file.\nFull text: {canonical}"

        rows.append(
            {
                "name": name,
                "version": version,
                "license": license_name,
                "url": (
                    eco.removeprefix("github:")
                    if eco.startswith("github:")
                    else f"https://hex.pm/packages/{name}"
                ),
                "text": text,
                "_eco": eco,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# vendored (shipped verbatim, not package-managed)
# --------------------------------------------------------------------------- #
def collect_vendored() -> list[dict]:
    """Single-file components vendored into the repo and shipped/distributed.

    The Checkmk Linux agent (GPLv2 shell script) is served by the dashboard to
    linux nodes (docs/agent-architecture.md §25, DR-10). Serving it is
    distribution, so it carries an attribution obligation even though no
    package manager knows about it. The script is its own complete source.
    """
    rows: list[dict] = []
    cmk = ROOT / "agent" / "vendor" / "check_mk_agent.linux"
    if cmk.exists():
        src = cmk.read_text(errors="replace")
        m = re.search(r'^\s*echo "Version: ([^"]+)"', src, re.M)
        rows.append(
            {
                "name": "check_mk_agent.linux (Checkmk Linux agent, vendored unmodified)",
                "version": m.group(1) if m else "unknown",
                "license": "GPL-2.0-only",
                "url": "https://github.com/Checkmk/checkmk",
                "text": (
                    "Copyright (C) 2019 Checkmk GmbH — GNU General Public License v2.\n"
                    "Vendored unmodified from the Checkmk sources (agents/check_mk_agent.linux);\n"
                    "the shell script is its own complete corresponding source.\n"
                    "Full license text: https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt"
                ),
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# render
# --------------------------------------------------------------------------- #
def _table(rows: list[dict]) -> str:
    lines = ["| Component | Version | License |", "|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['name']} | {r['version']} | {r['license']} |")
    return "\n".join(lines)


def _texts(rows: list[dict]) -> str:
    blocks: list[str] = []
    for r in rows:
        head = f"### {r['name']} {r['version']} — {r['license']}"
        if r.get("url"):
            head += f"\n\n<{r['url']}>"
        if r.get("text"):
            blocks.append(f"{head}\n\n```\n{r['text'].strip()}\n```")
        else:
            blocks.append(
                f"{head}\n\n_No license file bundled by the distributor; see the link above._"
            )
    return "\n\n".join(blocks)


def render(orbit: list[dict], vendored: list[dict]) -> str:
    return "\n".join(
        [
            "# Third-Party Notices",
            "",
            "STYLiTE Orbit Dashboard is distributed under the Business Source License 1.1",
            "(see `LICENSE`). It bundles the third-party open-source components listed below,",
            "each under its own license. **This file is generated — do not edit by hand.**",
            "Regenerate with `just notices` after changing runtime dependencies.",
            "",
            "Only components shipped in the production container are listed; build/test-only",
            "tooling is excluded as it is not part of the distributed artifact.",
            "",
            "## Orbit (Elixir/Hex runtime, orbit release image)",
            "",
            _table(orbit),
            "",
            "## Vendored (shipped verbatim)",
            "",
            _table(vendored),
            "",
            "---",
            "",
            "## Full license texts",
            "",
            "### Orbit",
            "",
            _texts(orbit),
            "",
            "### Vendored",
            "",
            _texts(vendored),
            "",
        ]
    )


# --------------------------------------------------------------------------- #
# SBOM (CycloneDX 1.6)
# --------------------------------------------------------------------------- #
def _cdx_license(value: str) -> list[dict]:
    v = (value or "").strip()
    if not v or v == "UNKNOWN":
        return []
    if " OR " in v or " AND " in v or " WITH " in v:
        return [{"expression": v}]  # SPDX license expression
    # A single bare token (e.g. MIT, BSD-3-Clause, MPL-2.0) is a usable SPDX id;
    # anything with spaces (e.g. "MIT License") is a free-text name, not an id.
    if re.fullmatch(r"[A-Za-z0-9.+-]+", v):
        return [{"license": {"id": v}}]
    return [{"license": {"name": v}}]


def _cdx_vendored(rows: list[dict]) -> list[dict]:
    comps: list[dict] = []
    for r in rows:
        if r["version"] == "unknown":
            continue
        purl = f"pkg:github/checkmk/checkmk@v{r['version']}"
        comps.append(
            {
                "type": "application",
                "bom-ref": purl,
                "name": "check_mk_agent.linux",
                "version": r["version"],
                "purl": purl,
                "licenses": [{"license": {"id": "GPL-2.0-only"}}],
            }
        )
    return comps


def _cdx_orbit(rows: list[dict]) -> list[dict]:
    comps: list[dict] = []
    for r in rows:
        eco = r.get("_eco", "hex")
        if eco.startswith("github:"):
            repo = eco.removeprefix("github:").removeprefix("https://github.com/")
            repo = repo.removesuffix(".git")
            purl = f"pkg:github/{repo}@{r['version']}"
        else:
            purl = f"pkg:hex/{r['name']}@{r['version']}"
        comp = {
            "type": "library",
            "bom-ref": purl,
            "name": r["name"],
            "version": r["version"],
            "purl": purl,
        }
        lic = _cdx_license(r["license"])
        if lic:
            comp["licenses"] = lic
        comps.append(comp)
    return comps


def build_sbom(orbit: list[dict], vendored: list[dict]) -> dict:
    version = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "unknown"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "stylite-orbit-dashboard",
                "name": "stylite-orbit-dashboard",
                "version": version,
            }
        },
        "components": _cdx_orbit(orbit) + _cdx_vendored(vendored),
    }


def main() -> None:
    orbit = collect_orbit()
    vendored = collect_vendored()
    OUT.write_text(render(orbit, vendored))
    sbom = build_sbom(orbit, vendored)
    SBOM_OUT.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n")
    notices = OUT.relative_to(ROOT)
    bom = SBOM_OUT.relative_to(ROOT)
    n = len(orbit) + len(vendored)
    print(f"wrote {notices} ({len(orbit)}+{len(vendored)} components)")
    print(f"wrote {bom} (CycloneDX 1.6, {len(sbom['components'])} of {n} components)")


if __name__ == "__main__":
    main()
