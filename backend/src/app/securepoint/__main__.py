"""Runnable PoC demo for the Securepoint connector.

Reads credentials from the environment (never hardcoded) and prints a status
summary pulled live from a Securepoint UTM box::

    SP_URL=https://host:11115 SP_USER=admin SP_PASS=secret \\
        SP_SSL_VERIFY=0 python -m app.securepoint

Self-signed appliance certs: set ``SP_SSL_VERIFY=0`` to skip verification (PoC only;
pin a CA bundle in production).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from app.securepoint.client import SecurepointClient, SecurepointError


async def _run() -> int:
    base_url = os.environ.get("SP_URL", "")
    user = os.environ.get("SP_USER", "")
    password = os.environ.get("SP_PASS", "")
    if not (base_url and user and password):
        print("set SP_URL, SP_USER, SP_PASS in the environment", file=sys.stderr)
        return 2
    ssl_verify = os.environ.get("SP_SSL_VERIFY", "1") not in ("0", "false", "False", "")

    async with SecurepointClient(base_url, user, password, ssl_verify=ssl_verify) as sp:
        status = await sp.poll_status()
        print(f"# host: {status.name or '?'}  version: {status.version or '?'}")

        ipsec = await sp.ipsec_status()
        print(f"\n# ipsec service running: {ipsec.running}  tunnels: {len(ipsec.tunnels)}")
        for t in ipsec.tunnels:
            up = "UP " if t.phase1_status == "established" else "DOWN"
            print(
                f"  [{up}] {t.id:20s} {t.local} -> {t.remote}  "
                f"phase2 {t.phase2_up}/{t.phase2_total}"
            )
            for c in t.children:
                mark = "*" if c.state else " "
                print(f"        {mark} {c.local_ts} <-> {c.remote_ts}")

        ovpn = await sp.openvpn_status()
        print(f"\n# openvpn servers: {len(ovpn)}")
        for row in ovpn:
            print(f"  {json.dumps(row, separators=(',', ':'))}")

        services = await sp.appmgmt_status()
        vpn = {k: services.get(k) for k in ("ipsec", "openvpn", "wireguard", "l2tpd")}
        print(f"\n# vpn services: {vpn}")
    return 0


def main() -> None:
    try:
        sys.exit(asyncio.run(_run()))
    except SecurepointError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
