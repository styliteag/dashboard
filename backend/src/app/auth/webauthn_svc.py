"""Thin wrappers around ``py_webauthn`` bound to our settings.

The crypto lives in the library; we own the challenge lifecycle (server-generated,
session-stored, single-use) and the RP id / expected origin — the values that, when
wrong, make WebAuthn fail with opaque browser errors. Both are ``DASH_`` settings.
"""

from __future__ import annotations

from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
)

from app.config import get_settings
from app.db.models import WebauthnCredential


def _descriptors(creds: list[WebauthnCredential]) -> list[PublicKeyCredentialDescriptor]:
    out: list[PublicKeyCredentialDescriptor] = []
    for c in creds:
        transports = None
        if c.transports:
            transports = [
                AuthenticatorTransport(t)
                for t in c.transports.split(",")
                if t in {e.value for e in AuthenticatorTransport}
            ]
        out.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(c.credential_id), transports=transports
            )
        )
    return out


def registration_options(
    user_id: int, username: str, existing: list[WebauthnCredential]
) -> tuple[str, str]:
    """(options JSON, base64url challenge) for ``navigator.credentials.create``."""
    s = get_settings()
    options = generate_registration_options(
        rp_id=s.webauthn_rp_id,
        rp_name=s.webauthn_rp_name,
        user_id=str(user_id).encode(),
        user_name=username,
        exclude_credentials=_descriptors(existing),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED
        ),
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def authentication_options(allow: list[WebauthnCredential]) -> tuple[str, str]:
    """(options JSON, base64url challenge) for ``navigator.credentials.get``."""
    s = get_settings()
    options = generate_authentication_options(
        rp_id=s.webauthn_rp_id,
        allow_credentials=_descriptors(allow),
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def verify_registration(credential: dict[str, Any], challenge: bytes) -> Any:
    s = get_settings()
    return verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=s.webauthn_rp_id,
        expected_origin=s.webauthn_origin,
    )


def verify_authentication(
    credential: dict[str, Any], challenge: bytes, public_key: bytes, sign_count: int
) -> Any:
    s = get_settings()
    return verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=s.webauthn_rp_id,
        expected_origin=s.webauthn_origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
    )
