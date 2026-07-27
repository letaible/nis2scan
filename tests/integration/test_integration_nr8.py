"""Integration tests for §30 Abs. 2 Nr. 8 — Kryptographie checks."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr8_kryptographie import (
    CheckAcmCertificateExpiry,
    CheckEbsEncryption,
    CheckElbTlsMinVersion,
    CheckKmsKeyRotation,
    CheckRdsEncryption,
    CheckS3DefaultEncryption,
    CheckTlsPolicy,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR8001S3Encryption:
    """AWS auto-encrypts S3 buckets. Test only that the check runs without error.

    Since Jan 2023 AWS applies SSE-S3 by default to every bucket, so every
    bucket in the (shared) CI account — including buckets outside our
    Terraform fixtures — surfaces as COMPLIANT positive evidence (ADR-0006)
    rather than no finding at all. A bucket whose encryption config cannot be
    evaluated (empty Rules/"unknown") raises a CheckError (UnverifiableState,
    W4 §30 Nr.8 Batch-Review) instead of fabricating a finding — tolerated.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckS3DefaultEncryption()
        result = await check.execute(aws_session)
        for err in result.errors:
            assert err.error_type == "UnverifiableState"
        non_compliant = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert non_compliant == []


@pytest.mark.integration
class TestNR8002EbsEncryption:
    """Test EBS volume encryption check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        volume_id = tf_outputs["non_compliant_ebs_volume_id"]["value"]
        check = CheckEbsEncryption()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == volume_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        volume_id = tf_outputs["compliant_ebs_volume_id"]["value"]
        check = CheckEbsEncryption()
        result = await check.execute(aws_session)

        # The compliant volume now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if f.resource_id == volume_id and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR8003RdsEncryption:
    """Test RDS encryption check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        rds_id = tf_outputs["non_compliant_rds_id"]["value"]
        check = CheckRdsEncryption()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if rds_id in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        compliant_rds_id = tf_outputs["compliant_rds_id"]["value"]
        check = CheckRdsEncryption()
        result = await check.execute(aws_session)

        # The compliant RDS instance now surfaces as COMPLIANT positive
        # evidence (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [
            f for f in result.findings if compliant_rds_id in f.resource_id and f.status == FindingStatus.NON_COMPLIANT
        ]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR8004KmsKeyRotation:
    """Test KMS key rotation check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        kms_key_id = tf_outputs["non_compliant_kms_key_id"]["value"]
        check = CheckKmsKeyRotation()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if kms_key_id in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.MEDIUM


@pytest.mark.integration
class TestNR8005TlsPolicy:
    """Test TLS policy check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        alb_arn = tf_outputs["non_compliant_alb_arn"]["value"]
        check = CheckTlsPolicy()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == alb_arn]
        assert len(matched) == 1
        assert matched[0].severity == Severity.MEDIUM


@pytest.mark.integration
class TestNR8007AcmCertificateExpiry:
    """Test ACM certificate expiry check against real infrastructure.

    The NR8 module creates a self-signed cert valid for only 24 hours,
    which should be flagged as expiring within 30 days.
    """

    @pytest.mark.asyncio
    async def test_short_lived_cert_detected(self, aws_session):
        check = CheckAcmCertificateExpiry()
        result = await check.execute(aws_session)

        assert result.errors == []
        # The 24h self-signed cert should be flagged
        assert len(result.findings) >= 1
        # All findings should be HIGH (about to expire) or CRITICAL (already expired)
        for f in result.findings:
            assert f.severity in (Severity.HIGH, Severity.CRITICAL)


@pytest.mark.integration
class TestNR8006ElbTlsMinVersion:
    """Test ELB TLS minimum version check against real infrastructure.

    Reuses the NR8 ALBs: non-compliant ALB uses ELBSecurityPolicy-2016-08
    which allows TLS 1.0/1.1, compliant ALB uses TLS 1.2+ policy.
    """

    @pytest.mark.asyncio
    async def test_non_compliant_detected(self, aws_session, tf_outputs):
        alb_arn = tf_outputs["non_compliant_alb_arn"]["value"]
        check = CheckElbTlsMinVersion()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == alb_arn]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_compliant_not_flagged(self, aws_session, tf_outputs):
        alb_arn = tf_outputs["compliant_alb_arn"]["value"]
        check = CheckElbTlsMinVersion()
        result = await check.execute(aws_session)

        # The compliant ALB now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if f.resource_id == alb_arn and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0
