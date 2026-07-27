"""Integration tests for §30 Abs. 2 Nr. 5 — Phase 6 check (AMI Age)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckAmiAge,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR5005AmiAge:
    """Test AMI Age check against real infrastructure.

    Positive-path: CI account likely has no running EC2 instances → no findings.
    The check should at minimum run without errors.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckAmiAge()
        result = await check.execute(aws_session)
        assert result.errors == []
