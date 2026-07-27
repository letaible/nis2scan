"""Integration tests for GCP NR8 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr8_kryptographie import (
    CheckCertificateManager,
    CheckCloudSqlSsl,
    CheckCmekEncryption,
    CheckDiskEncryption,
    CheckKmsKeyRotation,
    CheckSslPolicyLoadBalancer,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckKmsKeyRotation:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckKmsKeyRotation()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-001"


@pytest.mark.integration
class TestCheckCmekEncryption:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCmekEncryption()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-002"


@pytest.mark.integration
class TestCheckSslPolicyLoadBalancer:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckSslPolicyLoadBalancer()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-003"


@pytest.mark.integration
class TestCheckCloudSqlSsl:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCloudSqlSsl()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-004"


@pytest.mark.integration
class TestCheckDiskEncryption:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckDiskEncryption()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-005"


@pytest.mark.integration
class TestCheckCertificateManager:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCertificateManager()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR8-006"
