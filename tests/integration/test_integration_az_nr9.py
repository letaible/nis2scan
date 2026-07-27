"""Integration tests for Azure NR9 checks (Zugriffskontrolle & Asset-Management).

These tests run against a real Azure subscription. If no Azure credentials
are configured, all tests are skipped via the azure_session fixture.
"""

import pytest

from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckConditionalAccess:
    """AZ-NR9-001: Conditional Access Policies."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckConditionalAccess

        check = CheckConditionalAccess()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-001"


@pytest.mark.integration
class TestCheckPim:
    """AZ-NR9-002: Privileged Identity Management."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckPim

        check = CheckPim()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-002"


@pytest.mark.integration
class TestCheckNsgOpenAccess:
    """AZ-NR9-003: NSG rules — no open inbound access."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckNsgOpenAccess

        check = CheckNsgOpenAccess()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-003"


@pytest.mark.integration
class TestCheckStoragePublicAccess:
    """AZ-NR9-004: Storage Account — Private Access Only."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckStoragePublicAccess

        check = CheckStoragePublicAccess()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-004"


@pytest.mark.integration
class TestCheckClassicAdmins:
    """AZ-NR9-005: No classic subscription admins."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckClassicAdmins

        check = CheckClassicAdmins()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-005"


@pytest.mark.integration
class TestCheckGuestAccessRestrictions:
    """AZ-NR9-006: Guest Access Restrictions."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckGuestAccessRestrictions

        check = CheckGuestAccessRestrictions()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-006"


@pytest.mark.integration
class TestCheckStaleServicePrincipals:
    """AZ-NR9-007: Stale Service Principals."""

    @pytest.mark.asyncio
    async def test_check_executes(self, azure_session):
        from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import CheckStaleServicePrincipals

        check = CheckStaleServicePrincipals()
        result = await check.execute(azure_session)
        assert result.check_id == "AZ-NR9-007"
        # Live proof (ADR-0018 delta review, condition Z1): both Graph calls
        # must succeed — any error other than the fail-safe InconclusiveState
        # means the check cannot deliver results, which is exactly the defect
        # class this rework fixes.
        hard_errors = [e for e in result.errors if e.error_type != "InconclusiveState"]
        assert not hard_errors, f"Graph access failed: {hard_errors}"
        # The tenant always contains at least the CI app itself, so the check
        # must state something: a finding or the inconclusive marker.
        assert result.findings or result.errors
