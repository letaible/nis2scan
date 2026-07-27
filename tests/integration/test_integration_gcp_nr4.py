"""Integration tests for GCP NR4 checks."""

import pytest

from nis2scan.engine.providers.gcp.checks.nr4_lieferkette import (
    CheckBinaryAuthorization,
    CheckCrossProjectBindings,
    CheckServiceAccountKeys,
    CheckVpcServiceControlsSupplyChain,
    CheckWorkloadIdentity,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestCheckCrossProjectBindings:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckCrossProjectBindings()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR4-001"


@pytest.mark.integration
class TestCheckServiceAccountKeys:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckServiceAccountKeys()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR4-002"


@pytest.mark.integration
class TestCheckWorkloadIdentity:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckWorkloadIdentity()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR4-003"


@pytest.mark.integration
class TestCheckBinaryAuthorization:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckBinaryAuthorization()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR4-004"


@pytest.mark.integration
class TestCheckVpcServiceControlsSupplyChain:
    @pytest.mark.asyncio
    async def test_check_executes(self, gcp_session):
        check = CheckVpcServiceControlsSupplyChain()
        result = await check.execute(gcp_session)
        assert result.check_id == "GCP-NR4-005"
