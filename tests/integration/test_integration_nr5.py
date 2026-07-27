"""Integration tests for §30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckEcrImageScanning,
    CheckSsmPatchCompliance,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR5001EcrImageScanning:
    """Test ECR image scanning check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        repo_arn = tf_outputs["non_compliant_ecr_repo_arn"]["value"]
        check = CheckEcrImageScanning()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == repo_arn]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        repo_arn = tf_outputs["compliant_ecr_repo_arn"]["value"]
        check = CheckEcrImageScanning()
        result = await check.execute(aws_session)

        # The compliant repo now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if f.resource_id == repo_arn and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR5002SsmPatchCompliance:
    """Test SSM patch compliance check against real infrastructure.

    Positive-path only — no EC2 instances in CI account.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSsmPatchCompliance()
        result = await check.execute(aws_session)
        assert result.errors == []
        # No running instances = no findings
        assert len(result.findings) == 0
