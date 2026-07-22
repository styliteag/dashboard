#!/usr/bin/env python3
"""Sign the agent for self-update (Ed25519). Run with the OFFLINE private key.

    DASH_AGENT_SIGNING_KEY=<base64 raw 32-byte priv> \
        uv --project tools run python scripts/sign_agent.py
    # or
    uv --project tools run python scripts/sign_agent.py --key-file path

Writes ``<agent>.sig`` (base64 of the Ed25519 signature over the agent bytes).
The agent must have ``_UPDATE_PUBKEY`` set to the matching public key (hex,
printed below). Keep the private key OFFLINE — never on the dashboard.

Generate a fresh keypair with ``--gen`` (prints PRIV_B64 + PUB_HEX), keep the
private offline, and bake PUB_HEX into the agent's _UPDATE_PUBKEY.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _key_from_dotenv() -> str | None:
    """Read DASH_AGENT_SIGNING_KEY from the gitignored repo-root .env (None if absent).

    Lets ``just sign-agent`` / a bare ``python scripts/sign_agent.py`` work without
    exporting the key by hand — the offline private key already lives in .env.
    """
    env = Path(".env")
    if not env.exists():
        return None
    for line in env.read_text().splitlines():
        line = line.strip()
        if line.startswith("DASH_AGENT_SIGNING_KEY="):
            val = line.split("=", 1)[1].strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            return val or None
    return None


def _load_private_key(key_file: str | None) -> Ed25519PrivateKey:
    if key_file:
        raw = base64.b64decode(Path(key_file).read_text().strip())
    elif os.environ.get("DASH_AGENT_SIGNING_KEY"):
        raw = base64.b64decode(os.environ["DASH_AGENT_SIGNING_KEY"])
    elif _key_from_dotenv():
        raw = base64.b64decode(_key_from_dotenv())
    else:
        sys.exit("no key: set DASH_AGENT_SIGNING_KEY (base64), pass --key-file, or add it to .env")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _baked_pubkey_hex(agent_path: str) -> str:
    """The hex value of ``_UPDATE_PUBKEY`` baked into the agent ("" if signing is off)."""
    import re

    src = Path(agent_path).read_text()
    m = re.search(r'^_UPDATE_PUBKEY = "([0-9a-fA-F]*)"', src, re.MULTILINE)
    return m.group(1) if m else ""


def _verify_one(path: str, pub_hex: str) -> None:
    """Verify ``<path>.sig`` against ``pub_hex`` or exit with a clear message."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig_path = Path(path + ".sig")
    if not sig_path.exists():
        sys.exit(f"_UPDATE_PUBKEY is set but {sig_path} is missing — sign before releasing.")
    code = Path(path).read_bytes()
    sig = base64.b64decode(sig_path.read_text().strip())
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, code)
    except InvalidSignature:
        sys.exit(f"{sig_path} does not verify against _UPDATE_PUBKEY — re-sign.")
    print(f"{path}: signature verifies against baked _UPDATE_PUBKEY. OK")


def _verify(agent_paths: list[str], vendor_path: str | None = None) -> None:
    """Release guard: every committed .sig must verify against the baked pubkey.

    Exits non-zero (with a clear message) if signing is enabled but a signature
    is missing or stale — stale agent .sig = deployed agents reject every future
    update; stale vendor .sig = linux nodes refuse the Checkmk-agent deploy.
    Each agent line (§28: orbit_agent.py + orbit_agent_linux.py) verifies
    against its OWN baked _UPDATE_PUBKEY. The vendor script has no baked key
    of its own; it verifies against the first agent's _UPDATE_PUBKEY (one key
    chain for all root-run code, §25).
    """
    first_pub = ""
    for agent_path in agent_paths:
        pub_hex = _baked_pubkey_hex(agent_path)
        if not pub_hex:
            print(f"{agent_path}: _UPDATE_PUBKEY empty — self-update signing is OFF.")
            continue
        first_pub = first_pub or pub_hex
        _verify_one(agent_path, pub_hex)
    if first_pub and vendor_path and Path(vendor_path).exists():
        _verify_one(vendor_path, first_pub)


# Both single-file agent lines (§28). Signing/verifying always covers both —
# a forgotten linux .sig would make every linux node reject its next update.
_AGENT_FILES = ["agent/orbit_agent.py", "agent/orbit_agent_linux.py"]


def main() -> None:
    ap = argparse.ArgumentParser(description="Sign the agent for self-update.")
    ap.add_argument(
        "--agent",
        default=None,
        help="sign/verify only this agent file (default: both lines)",
    )
    # Vendored Checkmk agent (§25/DR-10) — signed with the same key so linux
    # nodes can verify it before running it as root. Skipped when absent.
    ap.add_argument("--vendor", default="agent/vendor/check_mk_agent.linux")
    ap.add_argument("--key-file", help="file containing the base64 raw private key")
    ap.add_argument("--gen", action="store_true", help="generate a keypair and exit")
    ap.add_argument(
        "--verify",
        action="store_true",
        help="verify the committed .sig files against the baked pubkey (no private key needed)",
    )
    args = ap.parse_args()

    agents = [args.agent] if args.agent else _AGENT_FILES
    for agent_path in agents:
        if not Path(agent_path).exists():
            sys.exit(f"{agent_path} not found — both agent lines must exist (§28).")

    if args.verify:
        _verify(agents, args.vendor)
        return

    if args.gen:
        k = Ed25519PrivateKey.generate()
        priv_b64 = base64.b64encode(
            k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        ).decode()
        pub_hex = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
        print(f"PRIV_B64={priv_b64}\nPUB_HEX={pub_hex}")
        return

    priv = _load_private_key(args.key_file)
    targets = list(agents)
    if args.vendor and Path(args.vendor).exists():
        targets.append(args.vendor)
    for target in targets:
        code = Path(target).read_bytes()
        Path(target + ".sig").write_text(base64.b64encode(priv.sign(code)).decode() + "\n")
        print(f"signed {target} -> {target}.sig")

    pub_hex = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    print(f"public key (set _UPDATE_PUBKEY in the agent to): {pub_hex}")


if __name__ == "__main__":
    main()
