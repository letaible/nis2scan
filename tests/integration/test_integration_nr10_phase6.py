"""Integration tests for §30 Abs. 2 Nr. 10 — Phase 6 checks (VPN, SES/SNS TLS)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import (
    CheckSesSnsTls,
    CheckVpnAdminAccess,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR10003VpnAdminAccess:
    """Test VPN Admin Access check against real infrastructure.

    Positive-path: CI account has no VPN → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckVpnAdminAccess()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_vpn_produces_finding(self, aws_session):
        check = CheckVpnAdminAccess()
        result = await check.execute(aws_session)
        # CI account has no VPN → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR10-003"


@pytest.mark.integration
class TestNR10004SesSnsTls:
    """Test SES/SNS TLS check against real infrastructure.

    The CI account likely has no SNS topics → no findings.
    The check should at minimum run without errors.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSesSnsTls()
        result = await check.execute(aws_session)
        assert result.errors == []
