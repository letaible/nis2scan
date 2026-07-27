"""Integration tests for §30 Abs. 2 Nr. 1 — Phase 5 checks (Organizations/SCPs, GuardDuty Risk)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import (
    CheckGuardDutyRiskAnalysis,
    CheckOrganizationsScp,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR1003OrganizationsScp:
    """Test Organizations/SCP check against real infrastructure.

    Positive-path: CI account is not an Organizations master → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckOrganizationsScp()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_organization_produces_finding(self, aws_session):
        check = CheckOrganizationsScp()
        result = await check.execute(aws_session)
        # CI account has no Organizations → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR1-003"


@pytest.mark.integration
class TestNR1005GuardDutyRiskAnalysis:
    """Test GuardDuty risk analysis check against real infrastructure.

    Positive-path: CI account has no GuardDuty enabled → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckGuardDutyRiskAnalysis()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_guardduty_produces_finding(self, aws_session):
        check = CheckGuardDutyRiskAnalysis()
        result = await check.execute(aws_session)
        # CI account has no GuardDuty → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR1-005"
