"""Integration tests for Azure NR5 checks (Schwachstellenmanagement).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckDefenderVulnAssessment:
    """AZ-NR5-001: Defender Vulnerability Assessment."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckDefenderVulnAssessment

        check = CheckDefenderVulnAssessment()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR5-001"


@pytest.mark.integration
class TestCheckUpdateManagement:
    """AZ-NR5-002: Update Management Center."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckUpdateManagement

        check = CheckUpdateManagement()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR5-002"


@pytest.mark.integration
class TestCheckContainerRegistryScan:
    """AZ-NR5-003: Container Registry Image Scan."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckContainerRegistryScan

        check = CheckContainerRegistryScan()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR5-003"


@pytest.mark.integration
class TestCheckAppServiceRuntime:
    """AZ-NR5-004: App Service Runtime."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckAppServiceRuntime

        check = CheckAppServiceRuntime()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR5-004"


@pytest.mark.integration
class TestCheckSqlVulnAssessment:
    """AZ-NR5-005: SQL Vulnerability Assessment."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import CheckSqlVulnAssessment

        check = CheckSqlVulnAssessment()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR5-005"
