"""Scenario-aware integration tests (Task #54, Azure port of the AWS pattern).

See test_integration_nr0_scenarios.py (AWS) for the full rationale — this file
mirrors it for Azure. Unlike every other file in this package, it runs in ALL
THREE Azure scenarios (gaps | hardened | mixed — see infra/azure/variables.tf
::scenario) instead of only "gaps" (see tests/integration/conftest.py::
SKIP_UNLESS_GAPS_SCENARIO, applied to the legacy per-nr Azure test files —
the SAME helper AWS uses, since both providers share the one NIS2SCAN_SCENARIO
env var).

It reads its expectations from the Terraform output "fixture_expectations"
(infra/azure/outputs.tf) instead of hard-coding "expected == non_compliant" per
check — that output already resolves, per fixture, whether THIS apply's
scenario should have closed the gap or not. Only the SET of tracked check_ids
(CHECK_CLASSES below) is static in this file; every per-fixture expected/
resource_ref value is read at runtime.

Azure-specific wrinkle (see infra/azure/main.tf for the full explanation):
several tracked checks (CheckGeoRedundantStorage AZ-NR3-003,
CheckImmutableBlobStorage AZ-NR3-006, CheckStoragePublicAccess AZ-NR9-004,
plus the two hardened_supported=false checks AZ-NR8-001/AZ-NR6-004) are
Subscription-weite Aggregat-Checks — they emit exactly ONE Finding for the
whole subscription rather than one per resource like AWS. Their resource_ref
(read from the Terraform output, not hard-coded here) is the subscription path
itself, which trivially matches that single Finding's resource_id.

Fixture-scoped only (mirrors the AWS file's design point 6): every assertion
matches a single tracked resource_ref against the findings of its check. This
file deliberately never asserts account-wide totals — the shared CI
subscription has real findings beyond these tracked Terraform fixtures
(positive-path/absence-based checks like Defender for Cloud, Conditional
Access, PIM, ... — see the "Scope note" in infra/azure/outputs.tf for why
those have no fixture entry at all).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from nis2scan.engine.models.finding import Finding, FindingStatus
from nis2scan.engine.providers.azure.checks.nr3_bcm import (
    CheckGeoRedundantStorage,
    CheckImmutableBlobStorage,
)
from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckContainerRegistryScan
from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import (
    CheckDiagnosticSettings,
    CheckLogRetention,
)
from nis2scan.engine.providers.azure.checks.nr8_kryptographie import (
    CheckAppServiceHttps,
    CheckKeyVaultRotation,
    CheckStorageEncryption,
)
from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import (
    CheckNsgOpenAccess,
    CheckStoragePublicAccess,
)

if TYPE_CHECKING:
    from nis2scan.engine.models.check import BaseCheck

pytestmark = pytest.mark.integration

# One entry per check_id referenced in infra/azure/outputs.tf::fixture_expectations.
# This mapping (which checks exist) is necessarily static — pytest needs to
# collect this file without a deployed az_tf_outputs.json (see
# ``pytest --collect-only``) — but the per-fixture expected/resource_ref
# values below are always read from az_tf_outputs at runtime, never hard-coded.
CHECK_CLASSES: dict[str, type[BaseCheck]] = {
    "AZ-NR3-003": CheckGeoRedundantStorage,
    "AZ-NR3-006": CheckImmutableBlobStorage,
    "AZ-NR5-003": CheckContainerRegistryScan,
    "AZ-NR6-003": CheckLogRetention,
    "AZ-NR6-004": CheckDiagnosticSettings,
    "AZ-NR8-001": CheckStorageEncryption,
    "AZ-NR8-004": CheckKeyVaultRotation,
    "AZ-NR8-005": CheckAppServiceHttps,
    "AZ-NR9-003": CheckNsgOpenAccess,
    "AZ-NR9-004": CheckStoragePublicAccess,
}

# Unlike AWS-NR8-005 (a pure deny-list check with no symmetric compliant
# evidence path), every Azure check tracked here DOES emit compliant_finding()
# on the good path (verified against each check's source as of Task #54) — so
# this set is empty. Kept for structural parity with the AWS file and as an
# explicit anchor for the "unverifiable" escape hatch below, which still
# applies generically: e.g. CheckAppServiceHttps emits an "UnverifiableState"
# CheckError (never a Finding) when the App Service TLS version cannot be
# read, and that must not fail this test either.
CHECK_IDS_WITHOUT_COMPLIANT_EVIDENCE: set[str] = set()


def _matches(finding: Finding, resource_ref: str) -> bool:
    """resource_ref is either the exact resource_id or a unique substring of it
    (see the fixture_expectations description in infra/azure/outputs.tf). For
    the Subscription-weiten Aggregat-Checks, resource_ref is the subscription
    path itself, which every Finding for that check_id shares — there is only
    ever at most one Finding per check_id for those, so this still uniquely
    identifies it."""
    return resource_ref in finding.resource_id


@pytest.mark.integration
class TestScenarioAwareFixtureExpectations:
    """Runs every check referenced in fixture_expectations exactly once and
    asserts each tracked fixture matches its scenario-resolved expectation."""

    @pytest.mark.asyncio
    async def test_every_fixture_matches_its_scenario_expectation(
        self, azure_session: Any, az_tf_outputs: dict[str, Any]
    ) -> None:
        expectations: dict[str, dict[str, Any]] = az_tf_outputs["fixture_expectations"]["value"]
        assert expectations, "fixture_expectations output ist leer — infra/azure/outputs.tf geaendert?"

        # Run each distinct check exactly once, cache the findings + raw error
        # messages (some checks tolerate rare UnverifiableState conditions —
        # see CheckAppServiceHttps's handling of unreadable TLS versions).
        findings_by_check_id: dict[str, list[Finding]] = {}
        error_messages_by_check_id: dict[str, list[str]] = {}
        for entry in expectations.values():
            check_id = entry["check_id"]
            if check_id in findings_by_check_id:
                continue
            check_cls = CHECK_CLASSES.get(check_id)
            if check_cls is None:
                pytest.fail(
                    f"fixture_expectations referenziert check_id {check_id!r} ohne Eintrag in "
                    "CHECK_CLASSES — vermutlich wurde infra/azure/outputs.tf um eine neue Fixture "
                    "erweitert, ohne diese Testdatei nachzuziehen."
                )
            result = await check_cls().execute(azure_session)
            findings_by_check_id[check_id] = result.findings
            error_messages_by_check_id[check_id] = [f"{e.error_type}: {e.message}" for e in result.errors]

        failures: list[str] = []
        for key, entry in expectations.items():
            check_id: str = entry["check_id"]
            resource_ref: str = entry["resource_ref"]
            expected: str = entry["expected"]
            findings = findings_by_check_id[check_id]
            matched = [f for f in findings if _matches(f, resource_ref)]
            non_compliant = [f for f in matched if f.status == FindingStatus.NON_COMPLIANT]
            compliant = [f for f in matched if f.status == FindingStatus.COMPLIANT]

            if expected == "compliant":
                if non_compliant:
                    failures.append(
                        f"[{key}] erwartet compliant, aber {check_id} meldet NON_COMPLIANT fuer "
                        f"resource_ref={resource_ref!r}: {[f.title for f in non_compliant]}"
                    )
                elif not compliant and check_id not in CHECK_IDS_WITHOUT_COMPLIANT_EVIDENCE:
                    unverifiable = any("UnverifiableState" in msg for msg in error_messages_by_check_id[check_id])
                    if not unverifiable:
                        failures.append(
                            f"[{key}] erwartet compliant, aber {check_id} lieferte gar kein Finding fuer "
                            f"resource_ref={resource_ref!r} (Fehler: {error_messages_by_check_id[check_id]})"
                        )
            elif expected == "non_compliant":
                if not non_compliant:
                    failures.append(
                        f"[{key}] erwartet non_compliant, aber {check_id} meldet kein non_compliant Finding fuer "
                        f"resource_ref={resource_ref!r} (Fehler: {error_messages_by_check_id[check_id]})"
                    )
            else:
                failures.append(f"[{key}] unbekannter expected-Wert {expected!r} (weder compliant noch non_compliant)")

        assert not failures, "Szenario-Erwartungen verletzt:\n" + "\n".join(f"  - {f}" for f in failures)
