"""Integration tests for GCP NR1 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr1_risikoanalyse import (
    CheckAssetInventory,
    CheckAuditLogConfig,
    CheckOrgPolicies,
    CheckSecurityCommandCenter,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckSecurityCommandCenter:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckSecurityCommandCenter()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR1-001"


@pytest.mark.integration
class TestCheckOrgPolicies:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckOrgPolicies()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR1-002"


@pytest.mark.integration
class TestCheckAuditLogConfig:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckAuditLogConfig()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR1-003"


@pytest.mark.integration
class TestCheckAssetInventory:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckAssetInventory()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR1-004"
