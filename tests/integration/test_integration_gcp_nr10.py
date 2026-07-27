"""Integration tests for GCP NR10 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr10_mfa_kommunikation import (
    CheckIapAdminAccess,
    CheckOsLoginWith2fa,
    CheckSecureLdap,
    CheckTwoStepVerification,
    CheckVpnGateways,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckTwoStepVerification:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckTwoStepVerification()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR10-001"


@pytest.mark.integration
class TestCheckIapAdminAccess:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckIapAdminAccess()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR10-002"


@pytest.mark.integration
class TestCheckVpnGateways:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckVpnGateways()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR10-003"


@pytest.mark.integration
class TestCheckOsLoginWith2fa:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckOsLoginWith2fa()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR10-004"


@pytest.mark.integration
class TestCheckSecureLdap:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckSecureLdap()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR10-005"
