"""http.relay request hardening.

The relay injects the box's own API credentials (Basic auth) and forwards to
the LOCAL API as root. It therefore only forwards what the dashboard actually
sends: an `api/...` path (no traversal, no encoded separators, no control
characters), GET/POST/PUT/DELETE, and only content-negotiation headers — never
anything that could override the injected credentials or the target host.
Refusals never reach _http_request.
"""

from __future__ import annotations

import orbit_agent as agent
import pytest


def _cfg() -> agent.Config:
    cfg = agent.Config(path="/nonexistent-relay-hardening")
    cfg.local_api_url = "https://127.0.0.1:4444"
    cfg.relay_provision = False
    return cfg


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> dict:
    seen: dict = {}

    def fake_request(url, method, headers, body, timeout, *, verify=True):
        seen.update(url=url, method=method, headers=dict(headers))
        return 200, [], b"{}"

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)
    return seen


BAD_PATHS = [
    "",
    "core/system/status",
    "/etc/passwd",
    "api/../../ui/",
    "api/core/..",
    "api/%2e%2e/ui",
    "api/%2E%2e/ui",
    "api%2f..%2fui",
    "api/x%2Fy",
    "api//x",
    "//evil.example/api/x",
    "api\\..\\ui",
    "api/x\r\nX-Injected: 1",
    "api/x\nfoo",
    "api/x\tfoo",
    "api/x\x00",
    "https://evil.example/api/x",
    "api/x#frag",
    # Non-ASCII: fullwidth dot/slash and Unicode spaces some HTTP stacks
    # normalise, plus a raw U+0085 (NEL) line break.
    "api/\uff0e\uff0e/ui",
    "api/x\uff0fy",
    "api/x\u00a0y",
    "api/x\u0085y",
    "api/caf\u00e9",
]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_unsafe_paths_are_refused(captured: dict, path: str) -> None:
    result = agent._relay_http({"method": "GET", "path": path}, _cfg())
    assert result["success"] is False
    assert result["status"] == 0
    assert "refused" in result["output"]
    assert captured == {}


@pytest.mark.parametrize("path", ["api/core/system/status", "/api/v2/system/version",
                                  "api/firewall/filter/search_rule?interface=lan&show_all=1"])
def test_api_paths_pass(captured: dict, path: str) -> None:
    result = agent._relay_http({"method": "GET", "path": path}, _cfg())
    assert result["status"] == 200
    assert captured["url"].startswith("https://127.0.0.1:4444/api/")


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "OPTIONS", "PROPFIND", "GET /x HTTP/1.1"])
def test_methods_outside_the_allow_list_are_refused(captured: dict, method: str) -> None:
    result = agent._relay_http({"method": method, "path": "api/x"}, _cfg())
    assert result["success"] is False
    assert "refused" in result["output"]
    assert captured == {}


@pytest.mark.parametrize("method", ["GET", "post", "PUT", "DELETE"])
def test_allowed_methods_pass(captured: dict, method: str) -> None:
    assert agent._relay_http({"method": method, "path": "api/x"}, _cfg())["status"] == 200


def test_only_content_negotiation_headers_are_forwarded(captured: dict) -> None:
    agent._relay_http(
        {
            "method": "POST",
            "path": "api/x",
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Basic ZXZpbDpldmls",
                "AUTHORIZATION": "Bearer x",
                "X-Forwarded-For": "1.2.3.4",
                "X-API-Key": "evil",
                "Host": "evil",
                "Cookie": "a=b",
                "Proxy-Authorization": "x",
            },
        },
        _cfg(),
    )
    names = {k.lower() for k in captured["headers"]}
    assert names == {"accept", "content-type", "authorization"}
    # The only Authorization is the injected one.
    assert captured["headers"]["Authorization"] == "Basic SzpT"


def test_header_values_with_line_breaks_are_dropped(captured: dict) -> None:
    agent._relay_http(
        {"method": "GET", "path": "api/x", "headers": {"Accept": "a\r\nX-Injected: 1"}},
        _cfg(),
    )
    assert "Accept" not in captured["headers"]


def test_non_dict_headers_are_ignored(captured: dict) -> None:
    result = agent._relay_http({"method": "GET", "path": "api/x", "headers": ["junk"]}, _cfg())
    assert result["status"] == 200
