"""Log anonymization before sending to an external LLM."""

from __future__ import annotations

from app.llm.anonymize import anonymize


def test_internal_ipv4_preserved() -> None:
    text = "ping 192.168.1.1 and 10.20.1.198 and 172.18.0.3"
    assert anonymize(text) == text


def test_public_ipv4_pseudonymized_consistently() -> None:
    out = anonymize("from 8.8.8.8 to 8.8.8.8 via 1.1.1.1")
    assert "8.8.8.8" not in out and "1.1.1.1" not in out
    assert out.count("PUBIP1") == 2  # same public IP → same token
    assert "PUBIP2" in out  # a different public IP → a new token


def test_mac_zeroes_first_four_octets() -> None:
    out = anonymize("a 00:1b:b5:05:e5:1d b 94:A6:7E:54:5E:6F")
    assert "00:00:00:00:e5:1d" in out
    assert "00:00:00:00:5e:6f" in out
    assert "1b:b5" not in out and "a6:7e" not in out.lower()


def test_secrets_redacted() -> None:
    assert "hunter2" not in anonymize("password=hunter2")
    assert "topsecret" not in anonymize('psk "topsecret"')
    assert "sekrit" not in anonymize("Authorization: Bearer sekrit")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    out = anonymize(pem)
    assert "MIIabc" not in out and "REDACTED" in out


def test_public_ipv6_pseudonymized_internal_kept() -> None:
    out = anonymize("pub 2606:4700:4700::1111 ula fd00::1 ll fe80::1 lo ::1")
    assert "2606:4700:4700::1111" not in out  # public IPv6 → scrubbed
    assert "PUBIP6_1" in out
    assert "fd00::1" in out  # ULA kept
    assert "fe80::1" in out  # link-local kept
    # a second distinct public IPv6 gets its own token
    out2 = anonymize("2606:4700:4700::1111 and 2001:4860:4860::8888")
    assert out2.count("PUBIP6_1") == 1 and "PUBIP6_2" in out2


def test_fqdn_pseudonymized_but_filenames_kept() -> None:
    out = anonymize("host host1.example.com is down")
    assert "host1.example.com" not in out and "HOST1" in out
    assert "filter.log" in anonymize("reading filter.log")  # file ext not a hostname
