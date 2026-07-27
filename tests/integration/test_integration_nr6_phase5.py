"""Integration tests for §30 Abs. 2 Nr. 6 — Phase 5 checks (Security Hub Compliance Score)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import (
    CheckSecurityHubComplianceScore,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR6003SecurityHubComplianceScore:
    """Test Security Hub Compliance Score check against real infrastructure.

    Positive-path: CI account has no Security Hub enabled → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSecurityHubComplianceScore()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_security_hub_produces_finding(self, aws_session):
        check = CheckSecurityHubComplianceScore()
        result = await check.execute(aws_session)
        # CI account has no Security Hub → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR6-003"
