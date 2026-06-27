"""The instance-update audit detail must never carry a secret value.

Regression guard: ssh_key (an ed25519 private key) used to leak verbatim into the
permanent audit log because the old denylist only excluded api_key/api_secret.
"""

from __future__ import annotations

import json

from app.instances.routes import _safe_audit_detail
from app.instances.schemas import InstanceUpdate

_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretkeymaterial\n-----END OPENSSH PRIVATE KEY-----"
)


def test_secret_values_never_appear_in_audit_detail() -> None:
    payload = InstanceUpdate(name="fw1", ssh_key=_PEM, api_secret="topsecret")
    detail = _safe_audit_detail(payload)
    blob = json.dumps(detail)

    assert _PEM not in blob
    assert "topsecret" not in blob
    assert detail["name"] == "fw1"
    # The fact of rotation is recorded by name only.
    assert detail["secrets_rotated"] == ["api_secret", "ssh_key"]


def test_empty_secret_is_not_logged_as_rotation() -> None:
    # Empty string means "keep existing" — not a rotation.
    payload = InstanceUpdate(api_secret="", ssh_key="")
    detail = _safe_audit_detail(payload)
    assert "secrets_rotated" not in detail


def test_only_allowlisted_fields_are_emitted() -> None:
    payload = InstanceUpdate(name="fw2", ssh_user="root", ssh_port=9922, location="dc1")
    detail = _safe_audit_detail(payload)
    assert detail == {"name": "fw2", "ssh_user": "root", "ssh_port": 9922, "location": "dc1"}
