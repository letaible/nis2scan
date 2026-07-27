"""Integration tests for §30 Abs. 2 Nr. 3 — Phase 6 check (Route 53 Health Checks)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckRoute53HealthChecks,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR3007Route53HealthChecks:
    """Test Route 53 Health Checks against real infrastructure.

    Positive-path: CI account has no Route 53 Health Checks → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckRoute53HealthChecks()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_health_checks_produces_finding(self, aws_session):
        check = CheckRoute53HealthChecks()
        result = await check.execute(aws_session)
        # CI account has no Route 53 Health Checks → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR3-007"
