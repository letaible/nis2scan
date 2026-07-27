"""Integration tests for Azure NR2 checks (Bewältigung von Sicherheitsvorfällen).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckDefenderAlertNotifications:
    """AZ-NR2-001: Defender Alert Notifications."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import (
            CheckDefenderAlertNotifications,
        )

        check = CheckDefenderAlertNotifications()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR2-001"


@pytest.mark.integration
class TestCheckSentinelAnalyticsRules:
    """AZ-NR2-002: Sentinel Analytics Rules."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import CheckSentinelAnalyticsRules

        check = CheckSentinelAnalyticsRules()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR2-002"


@pytest.mark.integration
class TestCheckSentinelPlaybooks:
    """AZ-NR2-003: Sentinel Playbooks / Logic Apps."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import CheckSentinelPlaybooks

        check = CheckSentinelPlaybooks()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR2-003"


@pytest.mark.integration
class TestCheckActionGroups:
    """AZ-NR2-004: Action Groups."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import CheckActionGroups

        check = CheckActionGroups()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR2-004"


@pytest.mark.integration
class TestCheckAlertProcessingRules:
    """AZ-NR2-005: Alert Processing Rules."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import CheckAlertProcessingRules

        check = CheckAlertProcessingRules()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR2-005"
