"""Integration tests for Azure NR3 checks (BCM / Business Continuity).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckBackupVaults:
    """AZ-NR3-001: Azure Backup Vaults with policies."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckBackupVaults

        check = CheckBackupVaults()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-001"


@pytest.mark.integration
class TestCheckSqlBackupRetention:
    """AZ-NR3-002: SQL DB Backup Retention >= 7 days."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckSqlBackupRetention

        check = CheckSqlBackupRetention()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-002"


@pytest.mark.integration
class TestCheckGeoRedundantStorage:
    """AZ-NR3-003: Geo-Redundant Storage."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckGeoRedundantStorage

        check = CheckGeoRedundantStorage()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-003"


@pytest.mark.integration
class TestCheckAvailabilityZones:
    """AZ-NR3-004: Availability Zones for production."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckAvailabilityZones

        check = CheckAvailabilityZones()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-004"


@pytest.mark.integration
class TestCheckSiteRecovery:
    """AZ-NR3-005: Azure Site Recovery configured."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckSiteRecovery

        check = CheckSiteRecovery()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-005"


@pytest.mark.integration
class TestCheckImmutableBlobStorage:
    """AZ-NR3-006: Immutable Blob Storage."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckImmutableBlobStorage

        check = CheckImmutableBlobStorage()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-006"


@pytest.mark.integration
class TestCheckTrafficManagerFrontDoor:
    """AZ-NR3-007: Traffic Manager / Front Door."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr3_bcm import CheckTrafficManagerFrontDoor

        check = CheckTrafficManagerFrontDoor()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR3-007"
