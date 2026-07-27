"""Integration tests for Azure NR7 checks (Cyberhygiene & Schulungen).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckPasswordProtection:
    """AZ-NR7-001: Entra ID Password Protection."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr7_cyberhygiene import CheckPasswordProtection

        check = CheckPasswordProtection()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR7-001"


@pytest.mark.integration
class TestCheckSecurityDefaults:
    """AZ-NR7-002: Security Defaults or Conditional Access Baseline."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr7_cyberhygiene import CheckSecurityDefaults

        check = CheckSecurityDefaults()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR7-002"
