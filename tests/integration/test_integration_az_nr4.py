"""Integration tests for Azure NR4 checks (Lieferkette / Supply Chain).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckLighthouseDelegations:
    """AZ-NR4-001: Lighthouse Delegations."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr4_lieferkette import CheckLighthouseDelegations

        check = CheckLighthouseDelegations()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR4-001"


@pytest.mark.integration
class TestCheckGuestUsersConditionalAccess:
    """AZ-NR4-002: Guest Users with Conditional Access."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr4_lieferkette import CheckGuestUsersConditionalAccess

        check = CheckGuestUsersConditionalAccess()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR4-002"


@pytest.mark.integration
class TestCheckPrivateEndpoints:
    """AZ-NR4-003: Private Endpoints for PaaS."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr4_lieferkette import CheckPrivateEndpoints

        check = CheckPrivateEndpoints()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR4-003"


@pytest.mark.integration
class TestCheckServicePrincipalCredentials:
    """AZ-NR4-004: Service Principal Credentials rotation."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr4_lieferkette import CheckServicePrincipalCredentials

        check = CheckServicePrincipalCredentials()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR4-004"


@pytest.mark.integration
class TestCheckMarketplaceImageTrust:
    """AZ-NR4-005: Marketplace Image Trust."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr4_lieferkette import CheckMarketplaceImageTrust

        check = CheckMarketplaceImageTrust()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR4-005"
