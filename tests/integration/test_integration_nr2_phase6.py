"""Integration tests for §30 Abs. 2 Nr. 2 — Phase 6 check (Detective)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
    CheckDetectiveEnabled,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR2005DetectiveEnabled:
    """Test Detective check against real infrastructure.

    Positive-path: CI account has no Detective enabled → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckDetectiveEnabled()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_detective_produces_finding(self, aws_session):
        check = CheckDetectiveEnabled()
        result = await check.execute(aws_session)
        # CI account has no Detective → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR2-005"
