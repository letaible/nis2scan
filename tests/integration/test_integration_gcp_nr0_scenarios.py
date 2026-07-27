"""Scenario-aware integration tests (Task #54, GCP-Portierung des AWS-Musters).

Unlike every other test_integration_gcp_*.py file, this one runs in ALL THREE
GCP scenarios (gaps | hardened | mixed — see infra/gcp/variables.tf::scenario)
instead of only "gaps" (see tests/integration/conftest.py::SKIP_UNLESS_GAPS_SCENARIO,
applied to the legacy per-nr test files test_integration_gcp_nr1.py..nr10.py).

It reads its expectations from the Terraform output "fixture_expectations"
(infra/gcp/outputs.tf) instead of hard-coding "expected == non_compliant" per
check — that output already resolves, per fixture, whether THIS apply's
scenario should have closed the gap or not. Only the SET of tracked check_ids
(CHECK_CLASSES below) is static in this file; every per-fixture
expected/resource_ref value is read at runtime.

Fixture-scoped only (mirrors the AWS design point in test_integration_nr0_
scenarios.py): every assertion matches a single tracked resource_ref against
the findings of its check. This file deliberately never asserts project-wide
totals — the shared CI project has real findings beyond these tracked
Terraform fixtures (positive-path/absence-based checks like Security Command
Center, Org Policies, Essential Contacts, ... — see the "Scope note" in
infra/gcp/outputs.tf for why those have no fixture entry at all: only 3 of
the 51 GCP checks have an actual Terraform resource to invert).

Unlike AWS, GCP has no hardened_supported=false exceptions and no check that
lacks full symmetric compliant/non_compliant evidence — all three tracked
checks support compliant_finding() evidence, so no CHECK_IDS_WITHOUT_COMPLIANT_
EVIDENCE set is needed here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from nis2scan.engine.models.finding import Finding, FindingStatus
from nis2scan.engine.providers.gcp.checks.nr3_bcm import CheckGcsVersioning
from nis2scan.engine.providers.gcp.checks.nr8_kryptographie import CheckKmsKeyRotation
from nis2scan.engine.providers.gcp.checks.nr9_zugriffskontrolle import CheckVpcFirewallRules

if TYPE_CHECKING:
    from nis2scan.engine.models.check import BaseCheck

pytestmark = pytest.mark.integration

# One entry per check_id referenced in infra/gcp/outputs.tf::fixture_expectations.
# This mapping (which checks exist) is necessarily static — pytest needs to
# collect this file without a deployed gcp_tf_outputs.json (see
# ``pytest --collect-only``) — but the per-fixture expected/resource_ref
# values below are always read from gcp_tf_outputs at runtime, never
# hard-coded.
CHECK_CLASSES: dict[str, type[BaseCheck]] = {
    "GCP-NR3-002": CheckGcsVersioning,
    "GCP-NR8-001": CheckKmsKeyRotation,
    "GCP-NR9-004": CheckVpcFirewallRules,
}


def _matches(finding: Finding, resource_ref: str) -> bool:
    """resource_ref is either the exact resource_id or a unique substring of it
    (see the fixture_expectations description in infra/gcp/outputs.tf)."""
    return resource_ref in finding.resource_id


@pytest.mark.integration
class TestScenarioAwareFixtureExpectations:
    """Runs every check referenced in fixture_expectations exactly once and
    asserts each tracked fixture matches its scenario-resolved expectation."""

    @pytest.mark.asyncio
    async def test_every_fixture_matches_its_scenario_expectation(
        self, gcp_session: Any, gcp_tf_outputs: dict[str, Any]
    ) -> None:
        expectations: dict[str, dict[str, Any]] = gcp_tf_outputs["fixture_expectations"]["value"]
        assert expectations, "fixture_expectations output ist leer — infra/gcp/outputs.tf geaendert?"

        # Run each distinct check exactly once, cache the findings + raw error
        # messages (mirrors the AWS pattern for rare UnverifiableState conditions).
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
                    "CHECK_CLASSES — vermutlich wurde infra/gcp/outputs.tf um eine neue Fixture "
                    "erweitert, ohne diese Testdatei nachzuziehen."
                )
            result = await check_cls().execute(gcp_session)
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
                elif not compliant:
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
