"""Tests for comma-separated base_url validation + the primary_base_url helper.

base_url may hold several clickable web-UI links; the first is the canonical API
endpoint used to build the direct/relay client.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.db.models import Instance
from app.instances.schemas import InstanceCreate, InstanceUpdate


def test_single_url_accepted() -> None:
    assert InstanceCreate(name="fw", base_url="https://a.example").base_url == "https://a.example"


def test_multiple_urls_trimmed_and_joined() -> None:
    m = InstanceCreate(name="fw", base_url="https://a.example ,  http://b.example:4444")
    assert m.base_url == "https://a.example, http://b.example:4444"


def test_invalid_url_rejected() -> None:
    with pytest.raises(ValidationError):
        InstanceCreate(name="fw", base_url="not-a-url")


def test_one_bad_url_in_list_rejects_whole() -> None:
    with pytest.raises(ValidationError):
        InstanceCreate(name="fw", base_url="https://ok.example, ftp://nope.example")


def test_empty_rejected() -> None:
    with pytest.raises(ValidationError):
        InstanceCreate(name="fw", base_url="  ,  ")


def test_update_none_skips_validation() -> None:
    assert InstanceUpdate(base_url=None).base_url is None


def test_update_validates_when_present() -> None:
    with pytest.raises(ValidationError):
        InstanceUpdate(base_url="garbage")


def test_primary_base_url_is_first() -> None:
    inst = Instance(base_url="https://a.example, https://b.example")
    assert inst.primary_base_url == "https://a.example"


def test_primary_base_url_single() -> None:
    assert Instance(base_url="https://only.example").primary_base_url == "https://only.example"
