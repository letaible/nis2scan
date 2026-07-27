"""Integration tests for GCP NR3 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr3_bcm import (
    CheckCloudSqlBackups,
    CheckCloudSqlHighAvailability,
    CheckDiskSnapshotSchedules,
    CheckDnsHealthChecks,
    CheckGcsRetentionPolicy,
    CheckGcsVersioning,
    CheckMultiZoneDeployments,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckCloudSqlBackups:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCloudSqlBackups()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-001"


@pytest.mark.integration
class TestCheckGcsVersioning:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckGcsVersioning()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-002"


@pytest.mark.integration
class TestCheckGcsRetentionPolicy:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckGcsRetentionPolicy()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-003"


@pytest.mark.integration
class TestCheckMultiZoneDeployments:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckMultiZoneDeployments()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-004"


@pytest.mark.integration
class TestCheckDiskSnapshotSchedules:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckDiskSnapshotSchedules()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-005"


@pytest.mark.integration
class TestCheckCloudSqlHighAvailability:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCloudSqlHighAvailability()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-006"


@pytest.mark.integration
class TestCheckDnsHealthChecks:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckDnsHealthChecks()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR3-007"
