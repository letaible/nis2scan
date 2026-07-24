"""Tests for §30 Nr. 8 — Kryptographie AWS checks using moto."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr8_kryptographie import (
    CheckAcmCertificateExpiry,
    CheckEbsEncryption,
    CheckElbTlsMinVersion,
    CheckKmsKeyRotation,
    CheckRdsEncryption,
    CheckS3DefaultEncryption,
    CheckTlsPolicy,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    """Create a test AwsSession wrapping the moto-mocked boto3 session."""
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


LB_ARN = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/app/test-lb/abc123"


def _session_with_fake_elbv2(
    listeners: list[dict],
    ssl_policies_by_name: dict[str, list[dict]] | None = None,
) -> AwsSession:
    """moto's ELBv2 support does not cover DescribeSSLPolicies — stub the elbv2
    client entirely so AWS-NR8-005/-006 tests can control listeners and SSL
    policy responses deterministically (pattern per test_nr5_schwachstellen.py).
    """
    session = _make_session()
    elbv2 = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [{"LoadBalancers": [{"LoadBalancerArn": LB_ARN}]}]
    elbv2.get_paginator.return_value = paginator
    elbv2.describe_listeners.return_value = {"Listeners": listeners}

    def describe_ssl_policies(**kwargs):
        name = kwargs.get("Names", [None])[0]
        return {"SslPolicies": (ssl_policies_by_name or {}).get(name, [])}

    elbv2.describe_ssl_policies.side_effect = describe_ssl_policies

    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == "elbv2":
            return elbv2
        return real_client(service, region=region)

    session.client = client  # type: ignore[method-assign]
    return session


class TestCheckS3DefaultEncryption:
    """Tests for S3 default encryption check."""

    @mock_aws
    def test_bucket_without_encryption_produces_finding(self):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="test-unencrypted",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        # moto creates buckets without encryption by default

        check = CheckS3DefaultEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR8-001"
        assert finding.severity.value == "HIGH"
        assert finding.bsig_30_nr == 8
        assert "S3" in finding.title

    @mock_aws
    def test_encrypted_bucket_no_finding(self):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="test-encrypted",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        s3.put_bucket_encryption(
            Bucket="test-encrypted",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

        check = CheckS3DefaultEncryption()
        result = asyncio.run(check.execute(session))

        # Encrypted bucket yields positive evidence (ADR-0006), no defect
        bucket_findings = [f for f in result.findings if "test-encrypted" in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_no_buckets_no_findings(self):
        session = _make_session()
        check = CheckS3DefaultEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0
        assert len(result.errors) == 0

    @mock_aws
    def test_empty_rules_produces_checkerror_no_finding(self):
        # B-Nr.8-1: GetBucketEncryption succeeded but returned no evaluable
        # rule — must not fabricate a positive finding with a concrete
        # algorithm that was never read.
        session = _make_session()
        real_s3 = session.client("s3")
        real_s3.create_bucket(
            Bucket="test-emptyrules",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )

        real_get_bucket_encryption = real_s3.get_bucket_encryption

        def get_bucket_encryption(**kwargs):
            if kwargs.get("Bucket") == "test-emptyrules":
                return {"ServerSideEncryptionConfiguration": {"Rules": []}}
            return real_get_bucket_encryption(**kwargs)

        real_s3.get_bucket_encryption = get_bucket_encryption  # type: ignore[method-assign]

        real_client = session.client

        def client(service: str, region: str | None = None):
            if service == "s3":
                return real_s3
            return real_client(service, region=region)

        session.client = client  # type: ignore[method-assign]

        check = CheckS3DefaultEncryption()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if "test-emptyrules" in f.resource_id]
        assert bucket_findings == []
        assert any(e.error_type == "UnverifiableState" and "test-emptyrules" in e.message for e in result.errors)

    @mock_aws
    def test_paginated_bucket_list_evaluates_all_pages(self):
        # FIX3: list_buckets() is not guaranteed to return every bucket in a
        # single response (AWS paginates via ContinuationToken). A bare
        # list_buckets() call would silently skip buckets past the first
        # page. moto does not implement ListBuckets ContinuationToken
        # semantics, so the paginator is stubbed directly with two pages.
        session = _make_session()
        real_s3 = session.client("s3")
        real_s3.create_bucket(
            Bucket="bucket-page1",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        real_s3.create_bucket(
            Bucket="bucket-page2",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        real_s3.put_bucket_encryption(
            Bucket="bucket-page2",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = [
            {"Buckets": [{"Name": "bucket-page1"}]},
            {"Buckets": [{"Name": "bucket-page2"}]},
        ]

        real_get_paginator = real_s3.get_paginator

        def get_paginator(operation_name):
            if operation_name == "list_buckets":
                return fake_paginator
            return real_get_paginator(operation_name)

        real_s3.get_paginator = get_paginator  # type: ignore[method-assign]

        real_client = session.client

        def client(service: str, region: str | None = None):
            if service == "s3":
                return real_s3
            return real_client(service, region=region)

        session.client = client  # type: ignore[method-assign]

        check = CheckS3DefaultEncryption()
        result = asyncio.run(check.execute(session))

        unencrypted = [f for f in result.findings if "bucket-page1" in f.resource_id]
        encrypted = [f for f in result.findings if "bucket-page2" in f.resource_id]
        assert len(unencrypted) == 1
        assert unencrypted[0].status == FindingStatus.NON_COMPLIANT
        assert len(encrypted) == 1
        assert encrypted[0].status == FindingStatus.COMPLIANT


class TestCheckEbsEncryption:
    """Tests for EBS volume encryption check."""

    @mock_aws
    def test_unencrypted_volume_produces_finding(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")
        ec2.create_volume(
            AvailabilityZone="eu-central-1a",
            Size=10,
            Encrypted=False,
        )

        check = CheckEbsEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR8-002"
        assert finding.severity.value == "HIGH"
        assert finding.bsig_30_nr == 8

    @mock_aws
    def test_encrypted_volume_produces_positive_evidence(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")
        ec2.create_volume(
            AvailabilityZone="eu-central-1a",
            Size=10,
            Encrypted=True,
        )

        check = CheckEbsEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        assert result.findings[0].status == FindingStatus.COMPLIANT


CERT_ARN = "arn:aws:acm:eu-central-1:123456789012:certificate/abc123"


def _session_with_fake_acm(certificates: dict[str, dict]) -> AwsSession:
    """moto's ACM request_certificate always issues NotAfter = now + 365 days —
    expiry scenarios cannot be controlled through moto. Stub the ACM client
    entirely so AWS-NR8-007 tests can control NotAfter deterministically
    (pattern per _session_with_fake_elbv2 above).
    """
    session = _make_session()
    acm = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [{"CertificateSummaryList": [{"CertificateArn": arn} for arn in certificates]}]
    acm.get_paginator.return_value = paginator

    def describe_certificate(**kwargs):
        return {"Certificate": certificates[kwargs["CertificateArn"]]}

    acm.describe_certificate.side_effect = describe_certificate

    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == "acm":
            return acm
        return real_client(service, region=region)

    session.client = client  # type: ignore[method-assign]
    return session


class TestCheckAcmCertificateExpiry:
    """Tests for the AWS-NR8-007 ACM certificate expiry check."""

    @mock_aws
    def test_long_lived_certificate_produces_positive_evidence(self):
        not_after = datetime.now(UTC) + timedelta(days=90)
        session = _session_with_fake_acm(
            {CERT_ARN: {"NotAfter": not_after, "DomainName": "example.com", "Status": "ISSUED"}}
        )

        result = asyncio.run(CheckAcmCertificateExpiry().execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1
        assert compliant[0].current_state["days_remaining"] >= 89
        assert not result.errors

    @mock_aws
    def test_soon_expiring_certificate_produces_finding(self):
        not_after = datetime.now(UTC) + timedelta(days=10)
        session = _session_with_fake_acm(
            {CERT_ARN: {"NotAfter": not_after, "DomainName": "example.com", "Status": "ISSUED"}}
        )

        result = asyncio.run(CheckAcmCertificateExpiry().execute(session))

        non_compliant = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(non_compliant) == 1
        assert non_compliant[0].severity.value == "HIGH"
        assert not result.errors

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self):
        session = _make_session()
        acm = MagicMock()
        acm.get_paginator.side_effect = RuntimeError("boom")
        real_client = session.client

        def client(service: str, region: str | None = None):
            if service == "acm":
                return acm
            return real_client(service, region=region)

        session.client = client  # type: ignore[method-assign]

        result = asyncio.run(CheckAcmCertificateExpiry().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckRdsEncryption:
    """Tests for RDS storage encryption check."""

    @mock_aws
    def test_unencrypted_rds_produces_finding(self):
        session = _make_session()
        rds = session.client("rds", region="eu-central-1")
        rds.create_db_instance(
            DBInstanceIdentifier="test-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            StorageEncrypted=False,
        )

        check = CheckRdsEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR8-003"
        assert finding.severity.value == "CRITICAL"
        assert finding.bsig_30_nr == 8

    @mock_aws
    def test_no_rds_instances_no_findings(self):
        session = _make_session()
        check = CheckRdsEncryption()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0


class TestCheckKmsKeyRotation:
    """Tests for KMS key rotation check."""

    @mock_aws
    def test_key_without_rotation_produces_finding(self):
        session = _make_session()
        kms = session.client("kms", region="eu-central-1")
        key = kms.create_key(Description="test-key")
        _ = key["KeyMetadata"]["KeyId"]

        # moto keys don't have rotation by default
        check = CheckKmsKeyRotation()
        result = asyncio.run(check.execute(session))

        # Should find the key without rotation
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR8-004"
        assert finding.severity.value == "MEDIUM"

    @mock_aws
    def test_no_keys_no_findings(self):
        session = _make_session()
        check = CheckKmsKeyRotation()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0

    @mock_aws
    def test_asymmetric_key_produces_no_finding(self):
        # AWS-NR8-004 fix: asymmetric (and HMAC) keys do not support automatic
        # rotation the same way symmetric keys do. GetKeyRotationStatus returns
        # KeyRotationEnabled=false for them instead of erroring — evaluating
        # that as a defect would be a false positive. Such keys must be
        # skipped entirely (KeySpec != SYMMETRIC_DEFAULT).
        session = _make_session()
        kms = session.client("kms", region="eu-central-1")
        kms.create_key(Description="asym-key", KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")

        check = CheckKmsKeyRotation()
        result = asyncio.run(check.execute(session))

        assert result.findings == []
        assert result.errors == []

    @mock_aws
    def test_symmetric_key_still_evaluated_alongside_asymmetric(self):
        # Guard against an overly broad filter that would also skip
        # legitimate symmetric keys once an asymmetric key is present.
        session = _make_session()
        kms = session.client("kms", region="eu-central-1")
        kms.create_key(Description="asym-key", KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
        kms.create_key(Description="sym-key")  # defaults to SYMMETRIC_DEFAULT

        check = CheckKmsKeyRotation()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        assert result.findings[0].current_state["key_rotation_enabled"] is False


class TestCheckTlsPolicy:
    """Tests for the AWS-NR8-005 deny-list-based TLS policy check (B-Nr.8-3)."""

    @mock_aws
    def test_policy_not_on_denylist_produces_no_judgement(self):
        # Previously fell into the (buggy) allow-list "else" branch and was
        # flagged as a defect even though it enforces TLS 1.3. The deny-list
        # rewrite must not judge policies it doesn't recognize as insecure.
        session = _session_with_fake_elbv2(
            listeners=[{"Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-TLS13-1-3-2021-06"}],
        )

        check = CheckTlsPolicy()
        result = asyncio.run(check.execute(session))

        assert result.findings == []
        assert result.errors == []

    @mock_aws
    def test_denylisted_policy_produces_finding(self):
        session = _session_with_fake_elbv2(
            listeners=[{"Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-2016-08"}],
        )

        check = CheckTlsPolicy()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.status == FindingStatus.NON_COMPLIANT
        assert finding.check_id == "AWS-NR8-005"
        assert "ELBSecurityPolicy-2016-08" in finding.description


class TestCheckElbTlsMinVersion:
    """Tests for the AWS-NR8-006 protocol-based TLS minimum version check (B-Nr.8-4)."""

    @mock_aws
    def test_nlb_tls_listener_is_evaluated(self):
        # NLB listeners use Protocol="TLS" rather than "HTTPS" — must not be
        # skipped by the listener filter.
        session = _session_with_fake_elbv2(
            listeners=[{"Protocol": "TLS", "SslPolicy": "ELBSecurityPolicy-2016-08"}],
            ssl_policies_by_name={
                "ELBSecurityPolicy-2016-08": [{"SslProtocols": ["TLSv1", "TLSv1.1", "TLSv1.2"]}],
            },
        )

        check = CheckElbTlsMinVersion()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.status == FindingStatus.NON_COMPLIANT
        assert finding.check_id == "AWS-NR8-006"
        assert finding.current_state["ssl_policy"] == "ELBSecurityPolicy-2016-08"

    @mock_aws
    def test_empty_describe_ssl_policies_produces_checkerror(self):
        session = _session_with_fake_elbv2(
            listeners=[{"Protocol": "HTTPS", "SslPolicy": "SomeCustomPolicy"}],
            ssl_policies_by_name={},
        )

        check = CheckElbTlsMinVersion()
        result = asyncio.run(check.execute(session))

        assert result.findings == []
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "UnverifiableState"
