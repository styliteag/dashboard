"""Tests for the local API relay (http.relay action).

The relay tunnels a dashboard HTTP request to the box's own OPNsense REST API,
injecting Basic auth locally so the dashboard never holds firewall credentials.
The actual HTTPS call (_http_request) and provisioning (_run PHP) are stubbed —
these cover the pure request/response mapping, auth injection, header filtering,
credential precedence, and dispatch.
"""

from __future__ import annotations

import base64
import json

import orbit_agent as agent
import pytest


def _cfg(**over: object) -> agent.Config:
    cfg = agent.Config(path="/nonexistent-relay-test")
    cfg.local_api_url = "https://127.0.0.1:4444"
    cfg.relay_provision = False  # tests opt in explicitly
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def _decode_basic(header: str) -> tuple[str, str]:
    raw = base64.b64decode(header.split(" ", 1)[1]).decode()
    key, _, secret = raw.partition(":")
    return key, secret


# --- credential resolution ---------------------------------------------------


def test_no_config_yields_transport_failure() -> None:
    result = agent._relay_http({"method": "GET", "path": "api/x"}, None)
    assert result["success"] is False
    assert result["status"] == 0


def test_missing_credentials_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    assert result["success"] is False
    assert result["status"] == 0
    assert "credentials" in result["output"]


def test_credential_precedence_config_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("CACHED", "X"))
    cfg = _cfg(local_api_key="CFGKEY", local_api_secret="CFGSEC")
    assert agent._ensure_api_credentials(cfg) == ("CFGKEY", "CFGSEC")


def test_credential_precedence_cache_over_provision(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("CK", "CS"))
    monkeypatch.setattr(agent, "_provision_api_credentials", lambda: ("PK", "PS"))
    assert agent._ensure_api_credentials(_cfg(relay_provision=True)) == ("CK", "CS")


def test_provision_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    monkeypatch.setattr(agent, "_provision_api_credentials", lambda: ("PK", "PS"))
    assert agent._ensure_api_credentials(_cfg(relay_provision=False)) is None
    assert agent._ensure_api_credentials(_cfg(relay_provision=True)) == ("PK", "PS")


# --- request/response mapping ------------------------------------------------


def test_relay_injects_auth_and_builds_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout, *, verify=True):
        captured.update(url=url, method=method, headers=headers, body=body, verify=verify)
        return 200, [("Content-Type", "application/json")], b'{"ok":1}'

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    result = agent._relay_http({"method": "get", "path": "/api/core/firmware/status"}, _cfg())

    assert captured["url"] == "https://127.0.0.1:4444/api/core/firmware/status"
    assert captured["method"] == "GET"
    assert captured["verify"] is False  # local self-signed API → verification skipped
    assert _decode_basic(captured["headers"]["Authorization"]) == ("K", "S")
    assert result["success"] is True
    assert result["status"] == 200
    assert result["headers"]["Content-Type"] == "application/json"
    assert base64.b64decode(result["body"]) == b'{"ok":1}'


def test_relay_forwards_request_body(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout, *, verify=True):
        captured["body"] = body
        captured["content_length"] = headers.get("Content-Length")
        return 200, [], b""

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    payload = b'{"enabled":true}'
    agent._relay_http(
        {"method": "POST", "path": "api/x", "body": base64.b64encode(payload).decode()},
        _cfg(),
    )
    assert captured["body"] == payload
    assert captured["content_length"] == str(len(payload))


def test_relay_drops_hop_by_hop_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout, *, verify=True):
        captured["headers"] = headers
        # Response carries hop-by-hop + a dashboard cookie that must not leak back.
        return 200, [("Connection", "close"), ("Set-Cookie", "x=1"), ("X-Ok", "1")], b""

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    result = agent._relay_http(
        {
            "method": "GET",
            "path": "api/x",
            "headers": {"Host": "evil", "Cookie": "session=abc", "Accept": "application/json"},
        },
        _cfg(),
    )
    # Inbound: Host/Cookie stripped, Accept kept, Authorization injected.
    assert "Host" not in captured["headers"]
    assert "Cookie" not in captured["headers"]
    assert captured["headers"]["Accept"] == "application/json"
    assert "Authorization" in captured["headers"]
    # Outbound: Connection stripped, other headers preserved.
    assert "Connection" not in result["headers"]
    assert result["headers"]["X-Ok"] == "1"


def test_relay_transport_error_is_status_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", boom)

    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    assert result["success"] is False
    assert result["status"] == 0
    assert "failed" in result["output"]


def test_relay_propagates_api_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(
        agent, "_http_request", lambda *a, **k: (403, [], b'{"status":403}')
    )
    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    # A real API 403 is NOT a transport failure: status preserved, success False.
    assert result["status"] == 403
    assert result["success"] is False


# --- provisioning ------------------------------------------------------------


def test_provision_non_opnsense_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    assert agent._provision_api_credentials() is None


def test_provision_parses_pair_and_caches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    cache = tmp_path / "agent.apikey"
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(cache))
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(
        agent, "_run", lambda *a, **k: json.dumps({"key": "NK", "secret": "NS"})
    )
    assert agent._provision_api_credentials() == ("NK", "NS")
    cached = json.loads(cache.read_text())
    assert cached["key"] == "NK" and cached["secret"] == "NS"


def test_provision_bad_output_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(tmp_path / "agent.apikey"))
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "not json")
    assert agent._provision_api_credentials() is None


# --- dispatch ----------------------------------------------------------------


def test_execute_command_dispatches_relay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_CONFIG", _cfg(local_api_key="K", local_api_secret="S"))
    monkeypatch.setattr(
        agent, "_http_request", lambda *a, **k: (200, [("X", "Y")], b"hi")
    )
    result = agent.execute_command("http.relay", {"method": "GET", "path": "api/x"})
    assert result["status"] == 200
    assert base64.b64decode(result["body"]) == b"hi"


def test_config_reads_legacy_opnsense_api_keys(tmp_path):
    """Back-compat: a pre-rename config with opnsense_api_* still populates local_api_*."""
    cfgfile = tmp_path / "legacy.conf"
    cfgfile.write_text(
        json.dumps(
            {
                "opnsense_api_url": "https://10.0.0.1:4444",
                "opnsense_api_key": "OLDKEY",
                "opnsense_api_secret": "OLDSEC",
            }
        )
    )
    cfg = agent.Config(path=str(cfgfile))
    assert cfg.local_api_url == "https://10.0.0.1:4444"
    assert cfg.local_api_key == "OLDKEY"
    assert cfg.local_api_secret == "OLDSEC"


def test_config_prefers_new_local_api_keys(tmp_path):
    """New local_api_* names win over the legacy opnsense_api_* fallback."""
    cfgfile = tmp_path / "both.conf"
    cfgfile.write_text(
        json.dumps(
            {
                "local_api_url": "https://new:4444",
                "opnsense_api_url": "https://old:4444",
                "local_api_key": "NEW",
                "opnsense_api_key": "OLD",
            }
        )
    )
    cfg = agent.Config(path=str(cfgfile))
    assert cfg.local_api_url == "https://new:4444"
    assert cfg.local_api_key == "NEW"


# --- port discovery ----------------------------------------------------------


def _set_config_xml(monkeypatch, tmp_path, body: str) -> None:
    p = tmp_path / "config.xml"
    p.write_text(f"<opnsense><system><webgui>{body}</webgui></system></opnsense>")
    monkeypatch.setattr(agent, "_CONFIG_XML", str(p))


def test_discover_reads_webgui_port(monkeypatch, tmp_path):
    _set_config_xml(monkeypatch, tmp_path, "<protocol>https</protocol><port>4444</port>")
    assert agent._discover_local_api_url() == "https://127.0.0.1:4444"


def test_discover_defaults_https_443_when_port_absent(monkeypatch, tmp_path):
    _set_config_xml(monkeypatch, tmp_path, "<protocol>https</protocol>")
    assert agent._discover_local_api_url() == "https://127.0.0.1:443"


def test_discover_defaults_http_80(monkeypatch, tmp_path):
    _set_config_xml(monkeypatch, tmp_path, "<protocol>http</protocol>")
    assert agent._discover_local_api_url() == "http://127.0.0.1:80"


def test_discover_missing_file_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "_CONFIG_XML", str(tmp_path / "nope.xml"))
    assert agent._discover_local_api_url() is None


def test_apply_discovery_overrides_default(monkeypatch, tmp_path):
    _set_config_xml(monkeypatch, tmp_path, "<protocol>https</protocol><port>8443</port>")
    cfg = _cfg()  # not explicit
    cfg.local_api_url_explicit = False
    agent._apply_port_discovery(cfg)
    assert cfg.local_api_url == "https://127.0.0.1:8443"


def test_apply_discovery_respects_explicit_config(monkeypatch, tmp_path):
    _set_config_xml(monkeypatch, tmp_path, "<protocol>https</protocol><port>8443</port>")
    cfg = _cfg()
    cfg.local_api_url = "https://127.0.0.1:9999"
    cfg.local_api_url_explicit = True  # admin pinned it → discovery must not override
    agent._apply_port_discovery(cfg)
    assert cfg.local_api_url == "https://127.0.0.1:9999"


# --- pfSense relay (package install + user provisioning) ---------------------


def test_provision_pfsense_needs_package(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(tmp_path / "a.apikey"))
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_pfrest_installed", lambda: False)
    # No package → must NOT provision (and must not install here).
    assert agent._provision_api_credentials() is None


def test_provision_pfsense_creates_orbit_user(monkeypatch, tmp_path):
    cache = tmp_path / "a.apikey"
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(cache))
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_pfrest_installed", lambda: True)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: json.dumps({"key": "orbit", "secret": "PW"}))
    # pfSense returns (username, password) — same shape, so the relay Basic-injects it.
    assert agent._provision_api_credentials() == ("orbit", "PW")
    assert json.loads(cache.read_text())["secret"] == "PW"


def test_install_pfrest_skips_when_present(monkeypatch):
    monkeypatch.setattr(agent, "_pfrest_installed", lambda: True)
    called = {"n": 0}
    monkeypatch.setattr(agent, "_run", lambda *a, **k: called.__setitem__("n", 1))
    assert agent._install_pfrest() is True
    assert called["n"] == 0  # already installed → no download


def test_install_pfrest_downloads_pinned_verified_asset(monkeypatch):
    captured = {}
    states = iter([False, True])  # not installed before, installed after

    def fake_download(url, dest, expected):
        captured.update(url=url, dest=dest, expected=expected)
        return True

    monkeypatch.setattr(agent, "_pfrest_installed", lambda: next(states))
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.8.1-RELEASE")
    monkeypatch.setattr(agent, "_download_verified", fake_download)
    monkeypatch.setattr(agent, "_run", lambda cmd, **k: captured.update(cmd=cmd))

    assert agent._install_pfrest() is True
    # Pinned release tag + per-version asset + the baked hash all feed the download.
    assert agent._PFREST_VERSION in captured["url"]
    assert captured["url"].endswith("/pfSense-2.8.1-pkg-RESTAPI.pkg")
    assert captured["expected"] == agent._PFREST_SHA256["2.8.1"]
    # Installs the verified local file, never the raw URL.
    assert captured["cmd"][0:2] == ["pkg-static", "add"]
    assert captured["cmd"][2] == captured["dest"]


def test_install_pfrest_refuses_unpinned_version(monkeypatch):
    # A pfSense version with no baked hash must fail closed: no download, no install.
    called = {"download": 0, "run": 0}
    monkeypatch.setattr(agent, "_pfrest_installed", lambda: False)
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.7.0-RELEASE")
    monkeypatch.setattr(
        agent, "_download_verified", lambda *a: called.__setitem__("download", 1) or True
    )
    monkeypatch.setattr(agent, "_run", lambda *a, **k: called.__setitem__("run", 1))
    assert agent._install_pfrest() is False
    assert called == {"download": 0, "run": 0}


def test_install_pfrest_aborts_on_verification_failure(monkeypatch):
    # A download that fails hash verification must install nothing.
    called = {"run": 0}
    monkeypatch.setattr(agent, "_pfrest_installed", lambda: False)
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.8.1-RELEASE")
    monkeypatch.setattr(agent, "_download_verified", lambda *a: False)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: called.__setitem__("run", 1))
    assert agent._install_pfrest() is False
    assert called["run"] == 0


def test_relay_enable_pfsense_installs_then_provisions(monkeypatch):
    order = []
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_install_pfrest", lambda: order.append("install") or True)
    monkeypatch.setattr(
        agent, "_provision_api_credentials", lambda: order.append("provision") or ("orbit", "PW")
    )
    result = agent.execute_command("relay.enable", {})
    assert result["success"] is True
    assert order == ["install", "provision"]  # package before credentials


def test_relay_enable_fails_if_install_fails(monkeypatch):
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_install_pfrest", lambda: False)
    result = agent.execute_command("relay.enable", {})
    assert result["success"] is False
    assert "install failed" in result["output"]


def test_relay_enable_opnsense_skips_install(monkeypatch):
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_provision_api_credentials", lambda: ("K", "S"))
    # _install_pfrest must never run on OPNsense — make it explode if called.
    monkeypatch.setattr(agent, "_install_pfrest", lambda: (_ for _ in ()).throw(AssertionError()))
    assert agent.execute_command("relay.enable", {})["success"] is True
