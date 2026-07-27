"""Integration tests for §30 Abs. 2 Nr. 5 — Phase 4 checks (Lambda Runtime)."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckLambdaRuntimeDeprecation,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR5004LambdaRuntime:
    """Test Lambda runtime deprecation check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        lambda_arn = tf_outputs["non_compliant_lambda_arn"]["value"]
        check = CheckLambdaRuntimeDeprecation()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == lambda_arn]
        assert len(matched) == 1
        assert matched[0].severity == Severity.MEDIUM
        assert matched[0].check_id == "AWS-NR5-004"

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        lambda_arn = tf_outputs["compliant_lambda_arn"]["value"]
        check = CheckLambdaRuntimeDeprecation()
        result = await check.execute(aws_session)

        # The compliant Lambda (python3.12) now surfaces as COMPLIANT positive
        # evidence (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [
            f for f in result.findings if f.resource_id == lambda_arn and f.status == FindingStatus.NON_COMPLIANT
        ]
        assert len(matched) == 0
