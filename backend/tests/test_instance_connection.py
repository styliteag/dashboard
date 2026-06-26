"""`test_connection` probes a Securepoint box via login + system_info."""

from __future__ import annotations

import json

import pytest
import respx
from cryptography.fernet import Fernet
from httpx import Request, Response

from app.db.models import Instance
from app.instances import service

_BASE = "https://sp.example.test:11115"
_SID = "0123456789abcdef0123456789abcdef"
_SYSINFO = [{"attribute": "hostname", "value": "bensheim"}, {"attribute": "version", "value": "14"}]


@pytest.fixture(autouse=True)
def _set_master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASH_MASTER_KEY", Fernet.generate_key().decode())
    from app.crypto import secrets as crypto_secrets

    crypto_secrets._fernet.cache_clear()  # type: ignore[attr-defined]
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def _ok(content: object, *, sessionid: str | None = None) -> Response:
    body: dict[str, object] = {"result": {"code": 200, "status": "OK", "content": content}}
    if sessionid is not None:
        body["sessionid"] = sessionid
    return Response(200, json=body)


def _router(request: Request) -> Response:
    payload = json.loads(request.content)
    key = (payload["module"], payload["command"])
    if key == ("auth", ["login"]):
        if payload["arguments"].get("pass") != "pw":
            return Response(200, json={"result": {"code": 401, "message": "insufficient creds"}})
        return _ok(["session opened"], sessionid=_SID)
    if key == ("system", ["info"]):
        return _ok(_SYSINFO)
    return _ok([])


def _instance() -> Instance:
    from app.crypto.secrets import encrypt

    return Instance(
        id=1,
        base_url=_BASE,
        device_type="securepoint",
        ssl_verify=False,
        api_key_enc=encrypt("admin"),
        api_secret_enc=encrypt("pw"),
    )


@pytest.mark.asyncio
async def test_test_connection_securepoint_ok() -> None:
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        ok, code, latency, error = await service.test_connection(_instance())
    assert ok is True
    assert code == 200
    assert error is None
    assert latency is not None


@pytest.mark.asyncio
async def test_test_connection_securepoint_bad_credentials() -> None:
    inst = _instance()
    from app.crypto.secrets import encrypt

    inst.api_secret_enc = encrypt("wrong")
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        ok, code, _latency, error = await service.test_connection(inst)
    assert ok is False
    assert code is None
    assert error is not None
