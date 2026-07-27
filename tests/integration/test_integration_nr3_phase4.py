"""Integration tests for §30 Abs. 2 Nr. 3 — Phase 4 checks (S3 Object Lock, EBS Snapshots)."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckEbsSnapshotEncryption,
    CheckS3ObjectLock,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR3003S3ObjectLock:
    """Test S3 Object Lock check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        bucket_name = tf_outputs["non_compliant_object_lock_bucket"]["value"]
        check = CheckS3ObjectLock()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == f"arn:aws:s3:::{bucket_name}"]
        assert len(matched) >= 1
        # W4 §30 Nr.3 Batch-Review: Object-Lock-Mangel ist jetzt LOW (nicht HIGH).
        assert matched[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        bucket_name = tf_outputs["compliant_object_lock_bucket"]["value"]
        check = CheckS3ObjectLock()
        result = await check.execute(aws_session)

        # The compliant bucket now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [
            f
            for f in result.findings
            if f.resource_id == f"arn:aws:s3:::{bucket_name}" and f.status == FindingStatus.NON_COMPLIANT
        ]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR3006EbsSnapshotEncryption:
    """Test EBS snapshot encryption check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        volume_id = tf_outputs["non_compliant_snapshot_volume_id"]["value"]
        check = CheckEbsSnapshotEncryption()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if volume_id in f.resource_id]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        volume_id = tf_outputs["compliant_snapshot_volume_id"]["value"]
        check = CheckEbsSnapshotEncryption()
        result = await check.execute(aws_session)

        # The compliant volume has an encrypted snapshot; it now surfaces as
        # COMPLIANT positive evidence (ADR-0006) instead of no finding at all
        # — only assert no Mangel.
        matched = [f for f in result.findings if volume_id in f.resource_id and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0
