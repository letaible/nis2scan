"""Integration tests for GCP NR7 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr7_cyberhygiene import (
    CheckEssentialContacts,
    CheckOrgSecurityPolicies,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckOrgSecurityPolicies:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckOrgSecurityPolicies()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR7-001"


@pytest.mark.integration
class TestCheckEssentialContacts:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckEssentialContacts()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR7-002"
