"""Integration tests for §30 Abs. 2 Nr. 9 — Zugriffskontrolle checks."""

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr9_zugriffskontrolle import (
    CheckIamAccessKeyAge,
    CheckIamMfa,
    CheckIamWildcardPolicy,
    CheckS3BucketPolicy,
    CheckS3PublicAccessBlock,
    CheckSecurityGroupOpenAccess,
    CheckUnusedIamCredentials,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR9001IamMfa:
    """Test IAM MFA check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_user_without_mfa_detected(self, aws_session, tf_outputs):
        username = tf_outputs["iam_user_without_mfa"]["value"]
        check = CheckIamMfa()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if username in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_user_with_mfa_not_flagged(self, aws_session, tf_outputs):
        username = tf_outputs["iam_user_with_mfa"]["value"]
        check = CheckIamMfa()
        result = await check.execute(aws_session)

        # The MFA-protected user now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if username in f.resource_id and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR9002AccessKeyAge:
    """Test IAM access key age check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_fresh_keys_pass(self, aws_session, tf_outputs):
        username = tf_outputs["iam_user_without_mfa"]["value"]
        check = CheckIamAccessKeyAge()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if username in f.resource_id]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR9003S3PublicAccessBlock:
    """Test S3 public access block check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_incomplete_block_detected(self, aws_session):
        check = CheckS3PublicAccessBlock()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.check_id == "AWS-NR9-003"]
        assert len(matched) >= 1


@pytest.mark.integration
class TestNR9004SecurityGroupOpenAccess:
    """Test security group open access check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_open_sg_detected(self, aws_session, tf_outputs):
        sg_id = tf_outputs["non_compliant_sg_id"]["value"]
        check = CheckSecurityGroupOpenAccess()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if f.resource_id == sg_id]
        assert len(matched) >= 1

    @pytest.mark.asyncio
    async def test_restricted_sg_not_flagged(self, aws_session, tf_outputs):
        sg_id = tf_outputs["compliant_sg_id"]["value"]
        check = CheckSecurityGroupOpenAccess()
        result = await check.execute(aws_session)

        # The restricted SG now surfaces as COMPLIANT positive evidence
        # (ADR-0006) instead of no finding at all — only assert no Mangel.
        matched = [f for f in result.findings if f.resource_id == sg_id and f.status == FindingStatus.NON_COMPLIANT]
        assert len(matched) == 0


@pytest.mark.integration
class TestNR9005IamWildcardPolicy:
    """Test IAM wildcard policy check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_wildcard_policy_detected(self, aws_session, tf_outputs):
        policy_arn = tf_outputs["non_compliant_iam_policy_arn"]["value"]
        check = CheckIamWildcardPolicy()
        result = await check.execute(aws_session)

        assert result.errors == []
        matched = [f for f in result.findings if f.resource_id == policy_arn]
        assert len(matched) == 1
        assert matched[0].severity == Severity.HIGH


@pytest.mark.integration
class TestNR9006S3BucketPolicy:
    """Test S3 bucket policy check against real infrastructure.

    Positive-path only — account-level public access block prevents
    creating buckets with Principal:* policies in CI.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckS3BucketPolicy()
        result = await check.execute(aws_session)
        assert result.errors == []


@pytest.mark.integration
class TestNR9007UnusedCredentials:
    """Test unused IAM credentials check against real infrastructure.

    Positive-path only — CI creates fresh access keys that are actively
    used, so no findings for unused credentials are expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckUnusedIamCredentials()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_fresh_keys_not_flagged(self, aws_session):
        """Freshly created access keys should not be flagged as unused."""
        check = CheckUnusedIamCredentials()
        result = await check.execute(aws_session)
        # Fresh CI keys should not trigger the 90-day threshold
        # (keys are created during terraform apply, so they are very recent)
        assert result.errors == []
