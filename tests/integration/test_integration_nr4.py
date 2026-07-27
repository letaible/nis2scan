"""Integration tests for §30 Abs. 2 Nr. 4 — Lieferkette checks."""

import pytest

from nis2scan.engine.providers.aws.checks.nr4_lieferkette import (
    CheckTrustedAdvisorAccess,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR4001TrustedAdvisor:
    """Test Trusted Advisor access check against real infrastructure.

    The CI account uses Basic support, so we expect a finding about
    limited or no Trusted Advisor access.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckTrustedAdvisorAccess()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_basic_support_detected(self, aws_session):
        check = CheckTrustedAdvisorAccess()
        result = await check.execute(aws_session)
        # Basic support → expect a finding about limited access
        assert len(result.findings) >= 1
