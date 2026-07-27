"""Integration tests for Azure NR10 checks (MFA & Kommunikation).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckMfaAllUsers:
    """AZ-NR10-001: MFA for all users."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import CheckMfaAllUsers

        check = CheckMfaAllUsers()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR10-001"


@pytest.mark.integration
class TestCheckPhishingResistantMfa:
    """AZ-NR10-002: Phishing-resistant MFA."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import CheckPhishingResistantMfa

        check = CheckPhishingResistantMfa()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR10-002"


@pytest.mark.integration
class TestCheckVpnBastion:
    """AZ-NR10-003: VPN Gateway / Bastion Host."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import CheckVpnBastion

        check = CheckVpnBastion()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR10-003"


@pytest.mark.integration
class TestCheckO365TlsEnforcement:
    """AZ-NR10-004: O365 TLS Enforcement."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import CheckO365TlsEnforcement

        check = CheckO365TlsEnforcement()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR10-004"


@pytest.mark.integration
class TestCheckBreakGlassAccounts:
    """AZ-NR10-005: Emergency Access Accounts."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import CheckBreakGlassAccounts

        check = CheckBreakGlassAccounts()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR10-005"
