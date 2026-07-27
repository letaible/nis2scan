"""Integration tests for Azure NR6 checks (Wirksamkeitsbewertung).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckDefenderSecureScore:
    """AZ-NR6-001: Defender Secure Score >= 70%."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import CheckDefenderSecureScore

        check = CheckDefenderSecureScore()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR6-001"


@pytest.mark.integration
class TestCheckPolicyComplianceState:
    """AZ-NR6-002: Azure Policy Compliance State."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import CheckPolicyComplianceState

        check = CheckPolicyComplianceState()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR6-002"


@pytest.mark.integration
class TestCheckLogRetention:
    """AZ-NR6-003: Activity Log Retention >= 365 days."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import CheckLogRetention

        check = CheckLogRetention()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR6-003"


@pytest.mark.integration
class TestCheckDiagnosticSettings:
    """AZ-NR6-004: Diagnostic Settings on critical resources."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import CheckDiagnosticSettings

        check = CheckDiagnosticSettings()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR6-004"
