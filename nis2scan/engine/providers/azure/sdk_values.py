"""Safe reading of azure-mgmt SDK values that may be enums OR plain strings.

Why this exists (AZ-NR9-003, 28.07.2026): azure-mgmt models declare many
fields as ``"type": "str"`` in their msrest attribute maps, so today they
usually deserialize into plain strings. But newer, typespec-generated SDKs
already return real enum members for the very same fields — the 30.07.2026
sweep proved this for ``Registry.sku.name`` (azure-mgmt-containerregistry),
which arrives as ``SkuName.PREMIUM``.

That difference is invisible to ``==`` comparisons (azure enums are
``(str, Enum)`` mixins, so ``SkuName.PREMIUM == "Premium"`` holds), but it is
FATAL as soon as the value is wrapped in ``str()`` first: ``str()`` on a
``(str, Enum)`` member has ALWAYS yielded the qualified ``"SkuName.PREMIUM"``
rather than ``"Premium"`` — this is not a Python 3.11 regression (3.11 only
changed ``format()``/f-strings), so the risk is older and broader than a
single interpreter upgrade.
Exactly that turned AZ-NR9-003 into a false negative — an open inbound port
was reported as compliant because ``str(rule.direction).lower()`` never
equalled ``"inbound"``.

Use these helpers wherever an SDK value has to become a string before it is
compared or looked up. They are correct under BOTH representations, so a
future SDK upgrade cannot silently flip a compliance verdict.
"""

from typing import Any


def enum_value(value: object) -> str:
    """Canonical string of an SDK value (``"Premium"``), enum or plain str."""
    return str(getattr(value, "value", value))


def enum_value_lower(value: object) -> str:
    """Lowercased canonical string, for case-insensitive comparisons."""
    return enum_value(value).lower()


def sdk_list(response: Any) -> list[Any]:
    """Items of a list-style azure-mgmt response, pager OR wrapper model.

    Why this exists (AZ-NR1-001/AZ-NR5-001, 30.07.2026): the same operation
    returns different container shapes across azure-mgmt majors. In
    azure-mgmt-security 6.x, ``pricings.list()`` returns a ``PricingList``
    MODEL — it carries the items in ``.value`` and has no ``__iter__`` at all,
    so ``list(...)`` raises ``TypeError: 'PricingList' object is not
    iterable``. Other operations (and other majors) return an ``ItemPaged``
    pager, which iterates but has no ``.value``.

    That difference shipped to every user of 0.2.0: the dev environment had
    azure-mgmt-security 7.0.0 installed while pyproject caps it at ``<7.0.0``,
    so the code was only ever exercised against a version customers are
    excluded from. Two checks errored out on every real scan.

    Deliberately NOT fail-soft: an unexpected shape raises instead of
    returning ``[]``. AZ-NR5-001 treats an empty list as "Defender for Servers
    not enabled" and would report a defect that was never measured — a silent
    empty fallback would manufacture findings out of a read failure
    (ADR-0016). A raised error becomes a visible CheckError instead.
    """
    if hasattr(response, "value"):
        # Wrapper model (PricingList & friends). ``value`` may legitimately be
        # None for an empty result set; that is a real answer, not a failure.
        return list(response.value or [])
    return list(response)  # pager; raises TypeError on any other shape
