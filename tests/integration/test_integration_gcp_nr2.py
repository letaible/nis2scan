"""Integration tests for GCP NR2 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr2_vorfallsbewaltigung import (
    CheckLogBasedAlerts,
    CheckLoggingSinks,
    CheckMonitoringAlertPolicies,
    CheckNotificationChannels,
    CheckSccNotifications,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckSccNotifications:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckSccNotifications()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR2-001"


@pytest.mark.integration
class TestCheckMonitoringAlertPolicies:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckMonitoringAlertPolicies()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR2-002"


@pytest.mark.integration
class TestCheckNotificationChannels:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckNotificationChannels()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR2-003"


@pytest.mark.integration
class TestCheckLogBasedAlerts:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckLogBasedAlerts()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR2-004"


@pytest.mark.integration
class TestCheckLoggingSinks:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckLoggingSinks()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR2-005"
