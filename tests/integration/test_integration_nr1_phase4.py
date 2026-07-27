"""Integration tests for §30 Abs. 2 Nr. 1 — Phase 4 checks (Config Recorder, Security Hub)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import (
    CheckConfigRecorder,
    CheckSecurityHub,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR1001ConfigRecorder:
    """Test Config Recorder check against real infrastructure.

    Positive-path: CI account has no Config Recorder → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckConfigRecorder()
        result = await check.execute(aws_session)
        # Should run without errors regardless of Config state
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_config_produces_finding(self, aws_session):
        check = CheckConfigRecorder()
        result = await check.execute(aws_session)
        # CI account has no Config Recorder → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR1-001"


@pytest.mark.integration
class TestNR1002SecurityHub:
    """Test Security Hub check against real infrastructure.

    Positive-path: CI account has no Security Hub → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSecurityHub()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_security_hub_produces_finding(self, aws_session):
        check = CheckSecurityHub()
        result = await check.execute(aws_session)
        # CI account has no Security Hub → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR1-002"
