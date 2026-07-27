"""Integration tests for Azure NR8 checks (Kryptographie).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckStorageEncryption:
    """AZ-NR8-001: Storage Account Encryption (CMK)."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckStorageEncryption

        check = CheckStorageEncryption()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-001"


@pytest.mark.integration
class TestCheckDiskEncryption:
    """AZ-NR8-002: Disk Encryption / SSE."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckDiskEncryption

        check = CheckDiskEncryption()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-002"


@pytest.mark.integration
class TestCheckSqlTde:
    """AZ-NR8-003: SQL TDE enabled."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckSqlTde

        check = CheckSqlTde()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-003"


@pytest.mark.integration
class TestCheckKeyVaultRotation:
    """AZ-NR8-004: Key Vault Rotation Policy."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckKeyVaultRotation

        check = CheckKeyVaultRotation()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-004"


@pytest.mark.integration
class TestCheckAppServiceHttps:
    """AZ-NR8-005: App Service HTTPS Only + TLS 1.2+."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckAppServiceHttps

        check = CheckAppServiceHttps()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-005"


@pytest.mark.integration
class TestCheckAppGatewayTls:
    """AZ-NR8-006: Application Gateway TLS Policy."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr8_kryptographie import CheckAppGatewayTls

        check = CheckAppGatewayTls()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR8-006"
