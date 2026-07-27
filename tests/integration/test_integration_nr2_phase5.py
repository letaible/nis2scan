"""Integration tests for §30 Abs. 2 Nr. 2 — Phase 5 checks (Security Hub Findings, Incident Manager)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
    CheckIncidentManagerResponsePlans,
    CheckSecurityHubFindings,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR2002SecurityHubFindings:
    """Test Security Hub Findings check against real infrastructure.

    Positive-path: CI account has no Security Hub enabled → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSecurityHubFindings()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_security_hub_produces_finding(self, aws_session):
        check = CheckSecurityHubFindings()
        result = await check.execute(aws_session)
        # CI account has no Security Hub → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR2-002"


@pytest.mark.integration
class TestNR2003IncidentManagerResponsePlans:
    """Test Incident Manager Response Plans check against real infrastructure.

    Positive-path: CI account has no Incident Manager response plans → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckIncidentManagerResponsePlans()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_response_plans_produces_finding(self, aws_session):
        check = CheckIncidentManagerResponsePlans()
        result = await check.execute(aws_session)
        # CI account has no response plans → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR2-003"
