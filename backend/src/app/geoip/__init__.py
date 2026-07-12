"""GeoIP access restriction (docs/geoip-access-restriction.md).

Country-gates every interactive request against a superadmin-managed allowlist,
with a CIDR/DynDNS whitelist bypass. Agent connections and orbit_ API keys are
exempt; ``DASH_GEOIP_DISABLE=true`` is the env-only kill switch.
"""
