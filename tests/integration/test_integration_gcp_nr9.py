"""Integration tests for GCP NR9 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr9_zugriffskontrolle import (
    CheckIamLeastPrivilege,
    CheckIdentityAwareProxy,
    CheckInactivePrincipals,
    CheckOrgConstraints,
    CheckServiceAccountHygiene,
    CheckStorageBucketPublicAccess,
    CheckVpcFirewallRules,
    CheckVpcServiceControls,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckIamLeastPrivilege:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckIamLeastPrivilege()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-001"


@pytest.mark.integration
class TestCheckServiceAccountHygiene:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckServiceAccountHygiene()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-002"


@pytest.mark.integration
class TestCheckIdentityAwareProxy:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckIdentityAwareProxy()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-003"


@pytest.mark.integration
class TestCheckVpcFirewallRules:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckVpcFirewallRules()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-004"


@pytest.mark.integration
class TestCheckStorageBucketPublicAccess:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckStorageBucketPublicAccess()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-005"


@pytest.mark.integration
class TestCheckOrgConstraints:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckOrgConstraints()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-006"


@pytest.mark.integration
class TestCheckInactivePrincipals:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckInactivePrincipals()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-007"


@pytest.mark.integration
class TestCheckVpcServiceControls:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckVpcServiceControls()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR9-008"
