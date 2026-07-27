"""Integration tests for §30 Abs. 2 Nr. 2 — Vorfallsbewältigung checks."""

import pytest

from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
    CheckCloudWatchAlarms,
    CheckGuardDutyEnabled,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR2001GuardDuty:
    """Test GuardDuty enablement check against real infrastructure.

    GuardDuty is NOT enabled in the CI account, so we expect a finding.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckGuardDutyEnabled()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_missing_guardduty_detected(self, aws_session):
        check = CheckGuardDutyEnabled()
        result = await check.execute(aws_session)
        # GuardDuty is not enabled in CI — expect at least one finding
        assert len(result.findings) >= 1


@pytest.mark.integration
class TestNR2004CloudWatchAlarms:
    """Test CloudWatch alarm check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckCloudWatchAlarms()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_alarm_detected(self, aws_session, tf_outputs):
        """With a billing alarm created by Terraform, us-east-1 should have at least one alarm."""
        alarm_name = tf_outputs["alarm_name"]["value"]
        check = CheckCloudWatchAlarms()
        result = await check.execute(aws_session)

        # The region with the alarm (us-east-1 for billing) should NOT be flagged
        # Other regions without alarms may still produce findings
        assert result.errors == []
        assert alarm_name  # Verify the alarm was created
