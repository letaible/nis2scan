"""Integration tests for Azure NR1 checks (Risikoanalyse).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckDefenderForCloud:
    """AZ-NR1-001: Defender for Cloud enabled."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckDefenderForCloud

        check = CheckDefenderForCloud()
        result = await check.execute(azure_session)
        # Check should execute without crashing; findings or errors expected
        assert result.check_id == "AZ-NR1-001"


@pytest.mark.integration
class TestCheckAzurePolicyAssignments:
    """AZ-NR1-002: Azure Policy Assignments."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckAzurePolicyAssignments

        check = CheckAzurePolicyAssignments()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR1-002"


@pytest.mark.integration
class TestCheckManagementGroups:
    """AZ-NR1-003: Management Groups configured."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckManagementGroups

        check = CheckManagementGroups()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR1-003"


@pytest.mark.integration
class TestCheckActivityLogRetention:
    """AZ-NR1-004: Activity Log Export."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckActivityLogRetention

        check = CheckActivityLogRetention()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR1-004"


@pytest.mark.integration
class TestCheckSentinelWorkspace:
    """AZ-NR1-005: Sentinel/SIEM Workspace."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckSentinelWorkspace

        check = CheckSentinelWorkspace()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR1-005"
