"""Integration tests for §30 Abs. 2 Nr. 10 — Phase 4 checks (Break-Glass procedure)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import (
    CheckBreakGlassProcedure,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR10005BreakGlass:
    """Test Break-Glass procedure check against real infrastructure.

    Positive-path: CI account has no break-glass user → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckBreakGlassProcedure()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_break_glass_user_produces_finding(self, aws_session):
        check = CheckBreakGlassProcedure()
        result = await check.execute(aws_session)
        # CI account has no break-glass user → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR10-005"
