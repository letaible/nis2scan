"""Integration tests for §30 Abs. 2 Nr. 6 — Phase 4 checks (Config Rules, Log Retention)."""

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import (
    CheckCloudWatchLogRetention,
    CheckConfigRulesCompliance,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR6002ConfigRulesCompliance:
    """Test Config Rules compliance check against real infrastructure.

    Positive-path: CI account has no Config Rules → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckConfigRulesCompliance()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_config_rules_produces_finding(self, aws_session):
        check = CheckConfigRulesCompliance()
        result = await check.execute(aws_session)
        # CI account has no Config Rules → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR6-002"


@pytest.mark.integration
class TestNR6004CloudWatchLogRetention:
    """Test CloudWatch Log retention check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        log_group_name = tf_outputs["non_compliant_log_group_name"]["value"]
        check = CheckCloudWatchLogRetention()
        result = await check.execute(aws_session)

        # Find the finding for our non-compliant log group (retention=7 days)
        matched = [f for f in result.findings if log_group_name in f.resource_id]
        assert len(matched) >= 1

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        log_group_name = tf_outputs["compliant_log_group_name"]["value"]
        check = CheckCloudWatchLogRetention()
        result = await check.execute(aws_session)

        # The compliant log group now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [
            f for f in result.findings if log_group_name in f.resource_id and f.status == FindingStatus.NON_COMPLIANT
        ]
        assert len(matched) == 0
