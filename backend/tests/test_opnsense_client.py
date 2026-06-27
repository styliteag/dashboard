"""Smoke test for the OPNsense client using respx for HTTP mocking."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from app.xsense.client import OPNsenseClient, OPNsenseError


@pytest.mark.asyncio
async def test_system_information_parses_response() -> None:
    async with respx.mock(base_url="https://fw.example.test") as mock:
        mock.get("/api/diagnostics/system/system_information").mock(
            return_value=Response(200, json={"name": "fw01", "versions": ["24.7.5"]})
        )
        client = OPNsenseClient(
            base_url="https://fw.example.test",
            api_key="key",
            api_secret="secret",
        )
        try:
            info = await client.system_information()
        finally:
            await client.aclose()
    assert info.name == "fw01"
    assert info.versions == ["24.7.5"]


@pytest.mark.asyncio
async def test_system_information_raises_on_http_error() -> None:
    async with respx.mock(base_url="https://fw.example.test") as mock:
        mock.get("/api/diagnostics/system/system_information").mock(
            return_value=Response(503, text="boom")
        )
        client = OPNsenseClient(
            base_url="https://fw.example.test",
            api_key="key",
            api_secret="secret",
        )
        try:
            with pytest.raises(OPNsenseError):
                await client.system_information()
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_non_json_200_is_wrapped_as_opnsense_error() -> None:
    # A 200 with an HTML body (captive portal / WAF / missing endpoint privilege)
    # used to raise a bare JSONDecodeError that escaped OPNsenseError handling.
    async with respx.mock(base_url="https://fw.example.test") as mock:
        mock.get("/api/diagnostics/system/system_information").mock(
            return_value=Response(200, text="<html>login</html>")
        )
        client = OPNsenseClient(
            base_url="https://fw.example.test", api_key="key", api_secret="secret"
        )
        try:
            with pytest.raises(OPNsenseError):
                await client.system_information()
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_poll_status_resilient_to_non_json_body() -> None:
    # Every endpoint returns a 200 HTML body. poll_status must still return a
    # (partial/empty) SystemStatus instead of propagating a decode/validation error.
    async with respx.mock(base_url="https://fw.example.test", assert_all_called=False) as mock:
        mock.route().mock(return_value=Response(200, text="<html>captive portal</html>"))
        client = OPNsenseClient(
            base_url="https://fw.example.test", api_key="key", api_secret="secret"
        )
        try:
            status = await client.poll_status()  # must not raise
        finally:
            await client.aclose()
    assert status.name is None  # system_information swallowed, defaulted
