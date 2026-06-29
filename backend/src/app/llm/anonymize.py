"""Scrub firewall log text before it is sent to an external LLM.

Rules (per operator choice):
- Internal/private IPs are **kept** (they aid diagnosis and are not sensitive);
  only globally-routable IPs are replaced with consistent pseudonyms.
- MAC addresses keep their last two octets and zero the first four
  (``aa:bb:cc:dd:ee:ff`` → ``00:00:00:00:ee:ff``) — devices stay distinguishable,
  vendor/OUI is removed.
- FQDN hostnames are replaced with consistent ``HOST<n>`` tokens (file-extension
  -like names such as ``filter.log`` are left alone).
- Passwords / secrets / keys (key=value, PSK, Bearer tokens, PEM blocks) are
  replaced with ``REDACTED``.

Pure and deterministic: the pseudonym map is built per call, so the same input
always yields the same output and tokens correlate within one document.
"""

from __future__ import annotations

import ipaddress
import re

_PEM_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)

# key=value / "psk: ..." / "Bearer ..." secrets. Keep the label + separator,
# redact the value (a quoted string or a whitespace-delimited token).
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|psk|pre-?shared[ _-]?key|api[_-]?key|token|bearer)\b"
    r"(\s*[:=]\s*|\s+)"
    r"(\"[^\"]*\"|'[^']*'|\S+)"
)

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Full IPv6 incl. "::" compression (the previous pattern missed every compressed
# address, leaking public IPv6). Candidates are validated by ipaddress below, so a
# loose-but-broad match is fine; internal (ULA/link-local/loopback) IPs are kept.
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"  # 1:2:3:4:5:6:7:8
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"  # 1::            1:2:3:4:5:6:7::
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"  # 1::8          1:2:3:4:5:6::8
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"  # ::8          ::
    r")(?![\w:.])"
)
_FQDN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

# TLD-shaped tokens that are really filenames/keywords, not hostnames — leave them.
_NOT_TLD = frozenset(
    {
        "log",
        "conf",
        "txt",
        "gz",
        "pid",
        "sock",
        "db",
        "pem",
        "crt",
        "cer",
        "key",
        "sh",
        "py",
        "js",
        "json",
        "yaml",
        "yml",
        "xml",
        "html",
        "css",
        "md",
        "arpa",
        "in-addr",
    }
)


def _mac_repr(match: re.Match[str]) -> str:
    octets = match.group(0).lower().split(":")
    return "00:00:00:00:" + ":".join(octets[4:])


def anonymize(text: str) -> str:
    """Return ``text`` with public IPs, MAC OUIs, FQDNs and secrets scrubbed."""
    text = _PEM_RE.sub("REDACTED", text)
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}REDACTED", text)
    text = _MAC_RE.sub(_mac_repr, text)

    pub4: dict[str, str] = {}

    def _ipv4(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            return token
        if ip.is_global:
            return pub4.setdefault(token, f"PUBIP{len(pub4) + 1}")
        return token

    text = _IPV4_RE.sub(_ipv4, text)

    pub6: dict[str, str] = {}

    def _ipv6(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            return token
        if ip.version == 6 and ip.is_global:
            return pub6.setdefault(token, f"PUBIP6_{len(pub6) + 1}")
        return token

    text = _IPV6_RE.sub(_ipv6, text)

    hosts: dict[str, str] = {}

    def _fqdn(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.rsplit(".", 1)[-1].lower() in _NOT_TLD:
            return token
        return hosts.setdefault(token.lower(), f"HOST{len(hosts) + 1}")

    return _FQDN_RE.sub(_fqdn, text)
