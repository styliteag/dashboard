# Securepoint SSH enrichment

A Securepoint UTM instance is polled over its `/spcgi.cgi` API (status, metrics,
IPsec service + tunnels). That API does **not** expose the IKE cookies, ESP SPIs
or per-tunnel byte counters — so the dashboard cannot pair a Securepoint tunnel
with its peer firewall when the link is behind NAT (the reversed-IP fallback
fails, and there is no shared key in the API view).

**SSH enrichment** closes that gap: when enabled, the dashboard opens an SSH
session to the box and runs `swanctl --list-sas --raw` / `--list-conns --raw`
(read-only). That yields the IKE cookie pair, the ESP SPIs and byte counters —
the same data the OPNsense/pfSense agent pushes — so cross-instance tunnel
pairing and exact Phase-2 matching work even across NAT.

It stays a **pull** model (the dashboard reaches *out* to the box on the SSH
port) — it is *not* an agent and does not run anything persistent on the box.

## How it works

- One ed25519 keypair **per instance**. The **private** key is pasted into the
  instance form and stored Fernet-encrypted in the DB (like the API secret); it
  is never returned by the API or logged. The **public** key is installed on the
  box by an admin (below).
- On each poll the dashboard SSHes in (default `root@<host>:9922`), runs the two
  `swanctl` commands, and parses them. If SSH fails, it falls back to the plain
  spcgi IPsec view automatically.
- The box's SSH host key is pinned trust-on-first-use — but only if SSH is already
  reachable when you save the instance, so **install the public key on the box
  (step 2) before enabling SSH in the dashboard (step 3)**. If the box isn't
  reachable at save time it stays unpinned (defense-in-depth only — pubkey auth
  means the private key can't be stolen); re-save once reachable to pin it. A later
  host-key mismatch is always refused.

## 1. Generate the keypair (dashboard side)

```
just gen-ssh-key
```

Prints the **private key** (PEM block — paste into the instance form, "SSH private
key" field) followed by the **public key** line (`ssh-ed25519 AAAA… `). Install
the public key on the box.

## 2. Install the public key on the Securepoint (admin, on the box)

### One-time: enable public-key auth

```
spcli
extc global set variable "GLOB_SSH_PUBKEY_AUTH" value 1
```

### Add and enable the key

```
ssh root@securepoint
spcli
system ssh pubkey new key "ssh-ed25519 AAAA…… dashboard-key"
system ssh pubkey get          # note the id of the key you just added
system ssh pubkey enable id 1  # use that id
system update system
```

In the WebUI the same lives under **Netzwerk → Server-Einstellungen → SSH**
(public-key authentication + the key list) — but the `spcli` steps above are the
reliable path and persist across reboots/firmware updates.

## 3. Enable SSH on the instance (dashboard)

Edit the Securepoint instance → enable **SSH enrichment**, set port (`9922`) and
user (`root`), paste the private key, save. The VPN view then shows the tunnel
with its peer paired and live byte counters.

## Security notes

- `system ssh pubkey new` installs an **unrestricted root key** — Securepoint has
  no forced-command option, so this key is root on the box. "The dashboard only
  runs `swanctl --list-*`" is policy, not something the box enforces.
- Mitigate accordingly: **restrict TCP 9922 to the dashboard's source IP** with a
  firewall rule, treat the dashboard's DB + master key as crown jewels, and use a
  **separate keypair per box** so a single key's blast radius is one box.
- Public-key auth means the private key is never sent to the box, so a MITM cannot
  steal it; host-key pinning guards against an impostor feeding false swanctl data.
- To rotate: `just gen-ssh-key` again, paste the new private key (re-pins the host
  key), and replace the public key on the box (`system ssh pubkey new` + enable,
  remove the old one).
