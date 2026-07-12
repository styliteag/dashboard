"""Pure GeoIP decision logic — no DB, no I/O, fully unit-testable.

The semantics here are the contract of docs/geoip-access-restriction.md:
DR-G3 (empty config = allow all, so there is no first-boot lockout path),
DR-G4 (whitelist = CIDRs v4/v6 or DynDNS hostnames), DR-G5 (unknown country
fails closed; a missing/broken mmdb fails OPEN so a bad DB update cannot lock
the whole company out).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

# RFC 1123 hostname with at least one dot (a bare label is almost always a typo
# for a CIDR entry, and DynDNS names are always fully qualified).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)

ALLOW = "allow"
DENY = "deny"


@dataclass(frozen=True)
class GeoipRules:
    """Parsed, immutable snapshot of the geoip_config row."""

    enabled: bool = False
    countries: frozenset[str] = frozenset()
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    hostnames: tuple[str, ...] = ()

    @property
    def restricting(self) -> bool:
        """False when the config cannot block anything (DR-G3 allow-all)."""
        return self.enabled and bool(self.countries or self.cidrs or self.hostnames)


DISABLED = GeoipRules()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    country: str | None = None
    # Extra key/values worth logging (kept small — this ends up in structlog).
    detail: dict = field(default_factory=dict)


def classify_entry(entry: str) -> tuple[str, object]:
    """('cidr', ip_network) or ('hostname', str) — raises ValueError otherwise.

    Single IPs are accepted and normalized to /32 (v4) or /128 (v6).
    """
    text = entry.strip()
    if not text:
        raise ValueError("empty whitelist entry")
    try:
        return "cidr", ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    if _HOSTNAME_RE.match(text):
        return "hostname", text.lower()
    raise ValueError(f"neither a CIDR/IP nor a hostname: {text!r}")


def parse_rules(enabled: bool, countries_json: str, whitelist_json: str) -> GeoipRules:
    """DB row → GeoipRules. Tolerant: unparseable entries are dropped, not fatal —
    a bad row must degrade to "less restrictive", never crash the middleware."""
    try:
        countries = [c for c in json.loads(countries_json or "[]") if isinstance(c, str)]
    except ValueError:
        countries = []
    try:
        entries = [e for e in json.loads(whitelist_json or "[]") if isinstance(e, str)]
    except ValueError:
        entries = []
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    hostnames: list[str] = []
    for entry in entries:
        try:
            kind, value = classify_entry(entry)
        except ValueError:
            continue
        if kind == "cidr":
            cidrs.append(value)  # type: ignore[arg-type]
        else:
            hostnames.append(value)  # type: ignore[arg-type]
    return GeoipRules(
        enabled=bool(enabled),
        countries=frozenset(c.upper() for c in countries if len(c) == 2),
        cidrs=tuple(cidrs),
        hostnames=tuple(hostnames),
    )


def ip_whitelisted(ip: str, rules: GeoipRules, resolved_ips: frozenset[str]) -> bool:
    """CIDR match (v4+v6) or membership in the DynDNS-resolved IP set."""
    if ip in resolved_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in rules.cidrs if addr.version == net.version)


def decide(
    ip: str,
    rules: GeoipRules,
    country: str | None,
    resolved_ips: frozenset[str],
    db_available: bool,
) -> Decision:
    """The single yes/no every enforcement point uses.

    Evaluation order matters and is part of the contract:
    disabled/empty-config allow (DR-G3) → whitelist (DR-G4) → mmdb missing
    fails open (DR-G5) → country allowlist, unknown country fails closed.
    """
    if not rules.restricting:
        return Decision(True, "not_restricting")
    if ip_whitelisted(ip, rules, resolved_ips):
        return Decision(True, "whitelisted")
    if not db_available:
        # Infrastructure failure, not a policy answer — allow, callers log loud.
        return Decision(True, "db_unavailable")
    if country is not None and country.upper() in rules.countries:
        return Decision(True, "country_allowed", country=country)
    reason = "country_blocked" if country else "no_country"
    return Decision(False, reason, country=country, detail={"ip": ip})
