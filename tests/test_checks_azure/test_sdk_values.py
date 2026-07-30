"""Guarantee of azure/sdk_values.py: SDK values read correctly as enum OR str.

This locks the fix class behind AZ-NR9-003 (28.07.2026): a value wrapped in
``str()`` before comparison silently changed a compliance verdict once the SDK
started returning real enum members instead of plain strings.
"""

from enum import Enum

from nis2scan.engine.providers.azure.sdk_values import enum_value, enum_value_lower


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
