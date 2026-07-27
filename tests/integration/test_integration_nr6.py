"""Integration tests for §30 Abs. 2 Nr. 6 — Wirksamkeit checks."""

import pytest

from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import (
    CheckCloudTrailLogIntegrity,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR6001CloudTrailIntegrity:
    """Test CloudTrail operational effectiveness check against real infrastructure.

    Reuses the NR1 CloudTrail trails. The compliant trail (with log validation)
    should be delivering logs recently since it was just created by Terraform.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckCloudTrailLogIntegrity()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_recent_trails_not_flagged(self, aws_session, tf_outputs):
        """Freshly created CloudTrail trails should have recent delivery times."""
        trail_arn = tf_outputs["compliant_trail_arn"]["value"]
        check = CheckCloudTrailLogIntegrity()
        result = await check.execute(aws_session)

        # Freshly created trail should be delivering logs recently
        stale_findings = [f for f in result.findings if f.resource_id == trail_arn and "veraltet" in f.title]
        assert len(stale_findings) == 0
