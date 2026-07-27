"""Integration tests for §30 Abs. 2 Nr. 4 — Phase 6 checks (Supply Chain)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr4_lieferkette import (
    CheckCrossAccountRoles,
    CheckOrganizationsExternalAccounts,
    CheckRamSharingPolicies,
    CheckScpForThirdPartyOus,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR4002RamSharingPolicies:
    """Test RAM Sharing check against real infrastructure.

    Positive-path: CI account likely has no RAM shares → no finding (no external shares).
    The check should at minimum run without errors.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckRamSharingPolicies()
        result = await check.execute(aws_session)
        assert result.errors == []


@pytest.mark.integration
class TestNR4003OrganizationsExternalAccounts:
    """Test Organizations external accounts check against real infrastructure.

    Positive-path: CI account is not an Organizations master → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckOrganizationsExternalAccounts()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_organizations_produces_finding(self, aws_session):
        check = CheckOrganizationsExternalAccounts()
        result = await check.execute(aws_session)
        # CI account has no Organizations → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR4-003"


@pytest.mark.integration
class TestNR4004CrossAccountRoles:
    """Test Cross-Account Roles check against real infrastructure.

    The CI account has the nis2scan-ci OIDC role which trusts GitHub Actions.
    This is technically a cross-account trust (GitHub OIDC provider).
    The check should run without errors.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckCrossAccountRoles()
        result = await check.execute(aws_session)
        assert result.errors == []


@pytest.mark.integration
class TestNR4005ScpForThirdPartyOus:
    """Test SCP for third-party OUs check against real infrastructure.

    Positive-path: CI account has no Organizations → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckScpForThirdPartyOus()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_organizations_produces_finding(self, aws_session):
        check = CheckScpForThirdPartyOus()
        result = await check.execute(aws_session)
        # CI account has no Organizations → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR4-005"
