"""Guarantee of azure/sdk_values.py: SDK values read correctly as enum OR str.

This locks the fix class behind AZ-NR9-003 (28.07.2026): a value wrapped in
``str()`` before comparison silently changed a compliance verdict once the SDK
started returning real enum members instead of plain strings.
"""

from enum import Enum

import pytest

from nis2scan.engine.providers.azure.sdk_values import enum_value, enum_value_lower, sdk_list


class _PricingList:
    """Real azure-mgmt-security 6.x shape: a wrapper model, NOT a pager.

    Deliberately without ``__iter__`` — that is precisely why ``list(...)``
    raised ``TypeError: 'PricingList' object is not iterable`` for every user
    of 0.2.0. A plain list as fixture would not reproduce the trap at all,
    which is exactly how the old check tests missed it.
    """

    def __init__(self, value):
        self.value = value


class _SkuName(str, Enum):  # noqa: UP042 — StrEnum would defeat the test
    """Real azure-mgmt shape: a (str, Enum) mixin.

    Deliberately NOT ``StrEnum``: there ``str(member)`` returns the value, so
    the trap this module guards against would not be reproduced at all.

    On Python 3.11+ ``str()`` of such a member yields "_SkuName.PREMIUM",
    while ``.value`` yields "Premium" — exactly the trap that produced the
    AZ-NR9-003 false negative. Proven live for azure-mgmt-containerregistry
    (Registry.sku.name -> SkuName.PREMIUM) in the 30.07.2026 sweep.
    """

    PREMIUM = "Premium"


def test_enum_member_yields_canonical_value_not_class_qualified_str():
    # Guard the premise: if str() ever equalled the value, the helper would be
    # pointless — and this test would tell us instead of silently passing.
    assert str(_SkuName.PREMIUM) != "Premium"
    assert enum_value(_SkuName.PREMIUM) == "Premium"
    assert enum_value_lower(_SkuName.PREMIUM) == "premium"


def test_plain_string_passes_through_unchanged():
    # Today's msrest-generated SDKs deserialize these fields as plain str —
    # the helper must be a no-op there.
    assert enum_value("Premium") == "Premium"
    assert enum_value_lower("Premium") == "premium"


def test_none_is_stringified_safely():
    # No path may crash or accidentally match a real value.
    assert enum_value_lower(None) == "none"


def test_wrapper_model_yields_its_items():
    # Guard the premise: if the wrapper were iterable, sdk_list would be
    # pointless — and this assert tells us instead of silently passing.
    wrapper = _PricingList(["a", "b"])
    assert not hasattr(wrapper, "__iter__")
    with pytest.raises(TypeError):
        list(wrapper)  # what the checks did before, and why they errored

    assert sdk_list(wrapper) == ["a", "b"]


def test_wrapper_with_empty_value_is_an_answer_not_a_failure():
    # An empty result set is a real answer from Azure. It must NOT raise —
    # the caller decides what "no plans" means.
    assert sdk_list(_PricingList([])) == []
    assert sdk_list(_PricingList(None)) == []


def test_pager_or_plain_iterable_passes_through():
    # Other operations (and other SDK majors) return an iterable pager.
    assert sdk_list(["x", "y"]) == ["x", "y"]
    assert sdk_list(iter(["x"])) == ["x"]


def test_unexpected_shape_fails_loudly_instead_of_returning_empty():
    # ADR-0016: AZ-NR5-001 reads an empty list as "Defender not enabled" and
    # would report a defect that was never measured. A read failure must
    # surface as a CheckError, never as a silent empty result.
    class _Unexpected:
        pass

    with pytest.raises(TypeError):
        sdk_list(_Unexpected())
