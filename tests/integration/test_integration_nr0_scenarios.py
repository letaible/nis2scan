"""Scenario-aware integration tests (Task #54, Gründer-Vorgabe 27.07.2026).

Unlike every other file in this package, this one runs in ALL THREE AWS
scenarios (gaps | hardened | mixed — see infra/aws/variables.tf::scenario)
instead of only "gaps" (see tests/integration/conftest.py::SKIP_UNLESS_GAPS_SCENARIO,
applied to the legacy per-nr test files).

It reads its expectations from the Terraform output "fixture_expectations"
(infra/aws/outputs.tf) instead of hard-coding "expected == non_compliant" per
check — that output already resolves, per fixture, whether THIS apply's
scenario should have closed the gap or not. Only the SET of tracked
check_ids (CHECK_CLASSES below) is static in this file; every per-fixture
expected/resource_ref value is read at runtime.

Fixture-scoped only (Task #54 design point 6): every assertion matches a
single tracked resource_ref against the findings of its check. This file
deliberately never asserts account-wide totals — the shared CI account has
real findings beyond these tracked Terraform fixtures (positive-path/
absence-based checks like GuardDuty, Config Recorder, Organizations, ... —
see the "Scope note" in infra/aws/outputs.tf for why those have no fixture
entry at all).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from nis2scan.engine.models.finding import Finding, FindingStatus
from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import CheckCloudTrail
from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckEbsSnapshotEncryption,
    CheckRdsBackupRetention,
    CheckRdsMultiAz,
    CheckS3ObjectLock,
    CheckS3Versioning,
)
from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckEcrImageScanning,
    CheckLambdaRuntimeDeprecation,
)
from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import CheckCloudWatchLogRetention
from nis2scan.engine.providers.aws.checks.nr7_cyberhygiene import CheckIamPasswordPolicy
from nis2scan.engine.providers.aws.checks.nr8_kryptographie import (
    CheckEbsEncryption,
    CheckElbTlsMinVersion,
    CheckKmsKeyRotation,
    CheckRdsEncryption,
    CheckS3DefaultEncryption,
    CheckTlsPolicy,
)
from nis2scan.engine.providers.aws.checks.nr9_zugriffskontrolle import (
    CheckIamMfa,
    CheckIamWildcardPolicy,
    CheckS3PublicAccessBlock,
    CheckSecurityGroupOpenAccess,
)
from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import CheckIamUserMfaEnforcement

if TYPE_CHECKING:
    from nis2scan.engine.models.check import BaseCheck

pytestmark = pytest.mark.integration

# One entry per check_id referenced in infra/aws/outputs.tf::fixture_expectations.
# This mapping (which checks exist) is necessarily static — pytest needs to
# collect this file without a deployed tf_outputs.json (see
# ``pytest --collect-only``) — but the per-fixture expected/resource_ref
# values below are always read from tf_outputs at runtime, never hard-coded.
CHECK_CLASSES: dict[str, type[BaseCheck]] = {
    "AWS-NR1-004": CheckCloudTrail,
    "AWS-NR3-001": CheckRdsBackupRetention,
    "AWS-NR3-002": CheckS3Versioning,
    "AWS-NR3-003": CheckS3ObjectLock,
    "AWS-NR3-004": CheckRdsMultiAz,
    "AWS-NR3-006": CheckEbsSnapshotEncryption,
    "AWS-NR5-001": CheckEcrImageScanning,
    "AWS-NR5-004": CheckLambdaRuntimeDeprecation,
    "AWS-NR6-004": CheckCloudWatchLogRetention,
    "AWS-NR7-001": CheckIamPasswordPolicy,
    "AWS-NR8-001": CheckS3DefaultEncryption,
    "AWS-NR8-002": CheckEbsEncryption,
    "AWS-NR8-003": CheckRdsEncryption,
    "AWS-NR8-004": CheckKmsKeyRotation,
    "AWS-NR8-005": CheckTlsPolicy,
    "AWS-NR8-006": CheckElbTlsMinVersion,
    "AWS-NR9-001": CheckIamMfa,
    "AWS-NR9-003": CheckS3PublicAccessBlock,
    "AWS-NR9-004": CheckSecurityGroupOpenAccess,
    "AWS-NR9-005": CheckIamWildcardPolicy,
    "AWS-NR10-002": CheckIamUserMfaEnforcement,
}

# AWS-NR8-005 (CheckTlsPolicy) is a pure deny-list check (see its own
# pruefgrenzen docstring): it only ever emits a Finding for a listener whose
# SslPolicy is on a fixed deny-list of known-insecure policies. Any other
# policy — including the secure one the "hardened"/"mixed" toggle switches
# to — produces NO finding at all (the authoritative protocol check lives in
# AWS-NR8-006 instead). So for THIS check_id, "expected == compliant" can
# only mean "no non_compliant finding for this resource", not "a
# COMPLIANT finding exists" — every other tracked check_id supports the full
# symmetric compliant_finding() evidence path (verified against the check
# source as of Task #54) and gets the stronger assertion.
CHECK_IDS_WITHOUT_COMPLIANT_EVIDENCE = {"AWS-NR8-005"}


def _matches(finding: Finding, resource_ref: str) -> bool:
    """resource_ref is either the exact resource_id or a unique substring of it
    (see the fixture_expectations description in infra/aws/outputs.tf)."""
    return resource_ref in finding.resource_id


@pytest.mark.integration
class TestScenarioAwareFixtureExpectations:
    """Runs every check referenced in fixture_expectations exactly once and
    asserts each tracked fixture matches its scenario-resolved expectation."""

    @pytest.mark.asyncio
    async def test_every_fixture_matches_its_scenario_expectation(
        self, aws_session: Any, tf_outputs: dict[str, Any]
    ) -> None:
        expectations: dict[str, dict[str, Any]] = tf_outputs["fixture_expectations"]["value"]
        assert expectations, "fixture_expectations output ist leer — infra/aws/outputs.tf geaendert?"

        # Run each distinct check exactly once, cache the findings + raw error
        # messages (some checks tolerate rare UnverifiableState conditions —
        # see the AWS-NR8-001 handling below, mirroring
        # test_integration_nr8.py::TestNR8001S3Encryption).
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
                    "CHECK_CLASSES — vermutlich wurde infra/aws/outputs.tf um eine neue Fixture "
                    "erweitert, ohne diese Testdatei nachzuziehen."
                )
            result = await check_cls().execute(aws_session)
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
