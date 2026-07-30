"""Safe reading of azure-mgmt SDK values that may be enums OR plain strings.

Why this exists (AZ-NR9-003, 28.07.2026): azure-mgmt models declare many
fields as ``"type": "str"`` in their msrest attribute maps, so today they
usually deserialize into plain strings. But newer, typespec-generated SDKs
already return real enum members for the very same fields — the 30.07.2026
sweep proved this for ``Registry.sku.name`` (azure-mgmt-containerregistry),
which arrives as ``SkuName.PREMIUM``.

That difference is invisible to ``==`` comparisons (azure enums are
``(str, Enum)`` mixins, so ``SkuName.PREMIUM == "Premium"`` holds), but it is
FATAL as soon as the value is wrapped in ``str()`` first: on Python 3.11+
``str(SkuName.PREMIUM)`` yields ``"SkuName.PREMIUM"``, not ``"Premium"``.
Exactly that turned AZ-NR9-003 into a false negative — an open inbound port
was reported as compliant because ``str(rule.direction).lower()`` never
equalled ``"inbound"``.

Use these helpers wherever an SDK value has to become a string before it is
compared or looked up. They are correct under BOTH representations, so a
future SDK upgrade cannot silently flip a compliance verdict.
"""


def enum_value(value: object) -> str:
    """Canonical string of an SDK value (``"Premium"``), enum or plain str."""
    return str(getattr(value, "value", value))


def enum_value_lower(value: object) -> str:
    """Lowercased canonical string, for case-insensitive comparisons."""
    return enum_value(value).lower()
