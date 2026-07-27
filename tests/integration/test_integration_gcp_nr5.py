"""Integration tests for GCP NR5 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr5_schwachstellen import (
    CheckArtifactRegistryScanning,
    CheckContainerAnalysis,
    CheckGkeNodeVersions,
    CheckOsConfigPatchManagement,
    CheckWebSecurityScanner,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckContainerAnalysis:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckContainerAnalysis()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR5-001"


@pytest.mark.integration
class TestCheckOsConfigPatchManagement:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckOsConfigPatchManagement()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR5-002"


@pytest.mark.integration
class TestCheckWebSecurityScanner:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckWebSecurityScanner()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR5-003"


@pytest.mark.integration
class TestCheckArtifactRegistryScanning:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckArtifactRegistryScanning()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR5-004"


@pytest.mark.integration
class TestCheckGkeNodeVersions:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckGkeNodeVersions()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR5-005"
