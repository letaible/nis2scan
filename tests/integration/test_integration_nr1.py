"""Integration tests for §30 Abs. 2 Nr. 1 — Risikoanalyse checks."""

import pytest

from nis2scan.engine.models.finding import Severity
from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import (
    CheckCloudTrail,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR1004CloudTrail:
    """Test CloudTrail log integrity check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        trail_arn = tf_outputs["non_compliant_trail_arn"]["value"]
        check = CheckCloudTrail()
        result = await check.execute(aws_session)

        assert result.errors == []
        # The non-compliant trail has log validation disabled
        matched = [f for f in result.findings if f.resource_id == trail_arn]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        trail_arn = tf_outputs["compliant_trail_arn"]["value"]
        check = CheckCloudTrail()
        result = await check.execute(aws_session)

        assert result.errors == []
        # The compliant trail should not be flagged for log validation
        matched = [f for f in result.findings if f.resource_id == trail_arn and "Log-File-Validation" in f.title]
        assert len(matched) == 0
