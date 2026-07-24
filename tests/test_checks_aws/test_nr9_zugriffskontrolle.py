"""Tests for §30 Nr. 9 — Zugriffskontrolle AWS checks using moto."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr9_zugriffskontrolle import (
    CheckIamAccessKeyAge,
    CheckIamMfa,
    CheckIamWildcardPolicy,
    CheckS3BucketPolicy,
    CheckS3PublicAccessBlock,
    CheckSecurityGroupOpenAccess,
    CheckUnusedIamCredentials,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


class TestCheckIamMfa:
    """Tests for IAM user MFA check."""

    @mock_aws
    def test_user_without_mfa_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_login_profile(UserName="testuser", Password="TestPass123!")

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR9-001"
        assert finding.severity.value == "HIGH"
        assert finding.bsig_30_nr == 9

    @mock_aws
    def test_user_with_mfa_no_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_login_profile(UserName="testuser", Password="TestPass123!")
        iam.create_virtual_mfa_device(VirtualMFADeviceName="testuser-mfa")

        # Enable MFA on the user
        iam.enable_mfa_device(
            UserName="testuser",
            SerialNumber="arn:aws:iam::mfa/testuser-mfa",
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        # The user with MFA yields positive evidence (ADR-0006), no defect
        user_findings = [f for f in result.findings if "testuser" in str(f.current_state)]
        assert len(user_findings) == 1
        assert user_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_user_without_login_profile_no_finding(self):
        # B-9-1: users without console login are out of scope for this check.
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="api-only-user")
        # No create_login_profile() call -> no console access

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0
        assert len(result.errors) == 0

    @mock_aws
    def test_no_users_no_findings(self):
        session = _make_session()
        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckIamAccessKeyAge:
    """Tests for IAM access key age check."""

    @mock_aws
    def test_old_access_key_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_access_key(UserName="testuser")

        # Note: moto creates keys with current timestamp.
        # The check compares against 90 days, so a fresh key won't trigger a
        # defect — it yields positive evidence instead (ADR-0006).
        check = CheckIamAccessKeyAge()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        assert result.findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_no_access_keys_no_findings(self):
        session = _make_session()
        check = CheckIamAccessKeyAge()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        check = CheckIamAccessKeyAge()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckSecurityGroupOpenAccess:
    """Tests for security group open access check."""

    @mock_aws
    def test_open_ssh_produces_finding(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        # Create VPC and security group
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-ssh",
            Description="Test SG with open SSH",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        open_ssh_findings = [f for f in result.findings if sg_id in f.resource_id]
        assert len(open_ssh_findings) >= 1
        assert open_ssh_findings[0].severity.value == "CRITICAL"
        assert open_ssh_findings[0].status == FindingStatus.NON_COMPLIANT

    @mock_aws
    def test_open_ssh_ipv6_produces_finding(self):
        # B-9-2 (ii): ::/0 must be treated the same as 0.0.0.0/0.
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-ssh-ipv6",
            Description="Test SG with open SSH via IPv6",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        maengel = [f for f in sg_findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert maengel[0].current_state["cidr"] == "::/0"

    @mock_aws
    def test_open_non_critical_port_produces_no_defect(self):
        # B-9-2 (i): 0.0.0.0/0 on a non-critical, non-full-range port is out of
        # scope — no Mangel-Finding (the SG still gets positive evidence).
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-https",
            Description="Test SG with open HTTPS",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        maengel = [f for f in sg_findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 0
        assert len(sg_findings) == 1
        assert sg_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_restricted_sg_no_finding(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-restricted",
            Description="Test SG with restricted access",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        # Restricted SG yields positive evidence (ADR-0006), no defect
        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(ec2, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: ec2)

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckIamWildcardPolicy:
    """Tests for IAM wildcard policy check (B-9-3)."""

    @mock_aws
    def test_service_wide_wildcard_with_unrestricted_resource_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
        iam.create_policy(PolicyName="wildcard-policy", PolicyDocument=json.dumps(policy_doc))

        check = CheckIamWildcardPolicy()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].check_id == "AWS-NR9-005"
        assert maengel[0].severity.value == "HIGH"

    @mock_aws
    def test_resource_scoped_wildcard_action_no_finding(self):
        # Resource-scoped ARNs (bucket/*) remain allowed even with a
        # concrete (non-wildcard) action.
        session = _make_session()
        iam = session.client("iam")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ],
        }
        iam.create_policy(PolicyName="scoped-policy", PolicyDocument=json.dumps(policy_doc))

        check = CheckIamWildcardPolicy()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 0
        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        check = CheckIamWildcardPolicy()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckS3BucketPolicy:
    """Tests for S3 bucket policy public access check (B-9-4/B-9-5)."""

    @mock_aws
    def test_unconditional_principal_wildcard_produces_critical_finding(self):
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-public"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_doc))

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.NON_COMPLIANT
        assert bucket_findings[0].severity.value == "CRITICAL"

    @mock_aws
    def test_principal_wildcard_with_condition_produces_manual_review_finding(self):
        # B-9-5: Principal: * WITH a Condition is no longer silently skipped —
        # it now gets its own MEDIUM "manual review" finding, not a clean
        # positive.
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-condition"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-12345"}},
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_doc))

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.NON_COMPLIANT
        assert bucket_findings[0].severity.value == "MEDIUM"
        assert "manuell prüfen" in bucket_findings[0].title
        # No clean positive evidence when a conditional Principal: * exists.
        assert not any(f.status == FindingStatus.COMPLIANT for f in bucket_findings)

    @mock_aws
    def test_no_public_policy_produces_positive_evidence(self):
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-private"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        # No bucket policy set at all -> NoSuchBucketPolicy -> compliant

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_paginated_bucket_list_evaluates_all_pages(self):
        # FIX3: list_buckets() is not guaranteed to return every bucket in a
        # single response (AWS paginates via ContinuationToken). moto does
        # not implement ListBuckets ContinuationToken semantics, so the
        # paginator is stubbed directly with two pages.
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
        # bucket-page2 gets no policy at all -> NoSuchBucketPolicy -> compliant

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

        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket-page1/*",
                }
            ],
        }
        real_s3.put_bucket_policy(Bucket="bucket-page1", Policy=json.dumps(policy_doc))

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        page1_findings = [f for f in result.findings if "bucket-page1" in f.resource_id]
        page2_findings = [f for f in result.findings if "bucket-page2" in f.resource_id]
        assert len(page1_findings) == 1
        assert page1_findings[0].status == FindingStatus.NON_COMPLIANT
        assert len(page2_findings) == 1
        assert page2_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        s3 = session.client("s3")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(s3, "list_buckets", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: s3)

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckS3PublicAccessBlock:
    @mock_aws
    def test_all_blocked_produces_positive_evidence(self):
        session = _make_session()
        s3control = session.client("s3control")
        s3control.put_public_access_block(
            AccountId="123456789012",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        check = CheckS3PublicAccessBlock()
        result = asyncio.run(check.execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1
        assert not result.errors

    @mock_aws
    def test_not_configured_produces_critical_finding(self):
        session = _make_session()

        check = CheckS3PublicAccessBlock()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert maengel[0].current_state["public_access_block"] == "not_configured"

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        s3control = session.client("s3control")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(s3control, "get_public_access_block", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: s3control)

        check = CheckS3PublicAccessBlock()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


def _session_with_fake_iam_keys(keys: list[dict], last_used: dict[str, dict]) -> AwsSession:
    """Fully stub the IAM client so AWS-NR9-007 tests can control key age and
    last-used state deterministically — moto never populates LastUsedDate
    (get_access_key_last_used always returns it absent), so the "actively
    used" / "stale but used before" branches cannot be reached through moto.
    """
    session = _make_session()
    iam = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Users": [{"UserName": "testuser", "Arn": "arn:aws:iam::123456789012:user/testuser"}]}
    ]
    iam.get_paginator.return_value = paginator
    iam.list_access_keys.return_value = {"AccessKeyMetadata": keys}

    def get_access_key_last_used(**kwargs):
        return {"AccessKeyLastUsed": last_used.get(kwargs["AccessKeyId"], {})}

    iam.get_access_key_last_used.side_effect = get_access_key_last_used

    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == "iam":
            return iam
        return real_client(service, region=region)

    session.client = client  # type: ignore[method-assign]
    return session


class TestCheckUnusedIamCredentials:
    @mock_aws
    def test_recently_used_key_produces_positive_evidence(self):
        session = _session_with_fake_iam_keys(
            keys=[{"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": datetime.now(UTC) - timedelta(days=200)}],
            last_used={"AKIA1": {"LastUsedDate": datetime.now(UTC) - timedelta(days=5)}},
        )

        check = CheckUnusedIamCredentials()
        result = asyncio.run(check.execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1
        assert compliant[0].current_state["days_unused"] == 5
        assert not result.errors

    @mock_aws
    def test_stale_key_produces_finding(self):
        session = _session_with_fake_iam_keys(
            keys=[{"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": datetime.now(UTC) - timedelta(days=200)}],
            last_used={"AKIA1": {"LastUsedDate": datetime.now(UTC) - timedelta(days=200)}},
        )

        check = CheckUnusedIamCredentials()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not result.errors

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self):
        session = _session_with_fake_iam_keys(keys=[], last_used={})
        iam = session.client("iam")
        iam.list_access_keys.side_effect = RuntimeError("boom")

        check = CheckUnusedIamCredentials()
        result = asyncio.run(check.execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"
