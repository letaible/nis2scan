"""Integration tests for GCP NR6 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr6_wirksamkeit import (
    CheckAuditLogIntegrity,
    CheckMonitoringDashboards,
    CheckPolicyIntelligence,
    CheckSecurityHealthAnalytics,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckAuditLogIntegrity:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckAuditLogIntegrity()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR6-001"


@pytest.mark.integration
class TestCheckSecurityHealthAnalytics:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckSecurityHealthAnalytics()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR6-002"


@pytest.mark.integration
class TestCheckPolicyIntelligence:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckPolicyIntelligence()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR6-003"


@pytest.mark.integration
class TestCheckMonitoringDashboards:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckMonitoringDashboards()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR6-004"
