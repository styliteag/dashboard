#!/usr/bin/env python3
"""Sign the agent for self-update (Ed25519). Run with the OFFLINE private key.

    DASH_AGENT_SIGNING_KEY=<base64 raw 32-byte priv> \
        uv --project backend run python scripts/sign_agent.py
    # or
    uv --project backend run python scripts/sign_agent.py --key-file path

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


def _load_private_key(key_file: str | None) -> Ed25519PrivateKey:
    if key_file:
        raw = base64.b64decode(Path(key_file).read_text().strip())
    elif os.environ.get("DASH_AGENT_SIGNING_KEY"):
        raw = base64.b64decode(os.environ["DASH_AGENT_SIGNING_KEY"])
    else:
        sys.exit("no key: set DASH_AGENT_SIGNING_KEY (base64) or pass --key-file")
    return Ed25519PrivateKey.from_private_bytes(raw)


def main() -> None:
    ap = argparse.ArgumentParser(description="Sign the agent for self-update.")
    ap.add_argument("--agent", default="agent/opnsense_agent.py")
    ap.add_argument("--key-file", help="file containing the base64 raw private key")
    ap.add_argument("--gen", action="store_true", help="generate a keypair and exit")
    args = ap.parse_args()

    if args.gen:
        k = Ed25519PrivateKey.generate()
        priv_b64 = base64.b64encode(
            k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        ).decode()
        pub_hex = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
        print(f"PRIV_B64={priv_b64}\nPUB_HEX={pub_hex}")
        return

    priv = _load_private_key(args.key_file)
    code = Path(args.agent).read_bytes()
    signature = priv.sign(code)
    Path(args.agent + ".sig").write_text(base64.b64encode(signature).decode() + "\n")

    pub_hex = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    print(f"signed {args.agent} -> {args.agent}.sig")
    print(f"public key (set _UPDATE_PUBKEY in the agent to): {pub_hex}")


if __name__ == "__main__":
    main()
