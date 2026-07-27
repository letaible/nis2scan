"""Integration tests for §30 Abs. 2 Nr. 3 — Business Continuity checks."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckRdsBackupRetention,
    CheckS3Versioning,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR3001RdsBackupRetention:
    """Test RDS backup retention check against real infrastructure.

    Uses existing NR8 RDS instances which have backup_retention_period=0.
    """

    @pytest.mark.asyncio
    async def test_low_retention_detected(self, aws_session, tf_outputs):
        # The NR8 non-compliant RDS has retention=0
        rds_id = tf_outputs["non_compliant_rds_id"]["value"]
        check = CheckRdsBackupRetention()
        result = await check.execute(aws_session)

        assert result.errors == []
        matched = [f for f in result.findings if rds_id in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH


@pytest.mark.integration
class TestNR3002S3Versioning:
    """Test S3 versioning check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        bucket = tf_outputs["non_compliant_s3_versioning_bucket"]["value"]
        check = CheckS3Versioning()
        result = await check.execute(aws_session)

        assert result.errors == []
        matched = [f for f in result.findings if bucket in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        bucket = tf_outputs["compliant_s3_versioning_bucket"]["value"]
        check = CheckS3Versioning()
        result = await check.execute(aws_session)

        assert result.errors == []
        # The compliant bucket now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if bucket in f.resource_id and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0
