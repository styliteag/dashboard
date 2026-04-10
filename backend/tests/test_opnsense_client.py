"""Smoke test for the OPNsense client using respx for HTTP mocking."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from app.opnsense.client import OPNsenseClient, OPNsenseError


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
