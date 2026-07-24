"""Tests for §30 Nr. 3 — BCM AWS checks incl. positive evidence (ADR-0006)."""

import asyncio
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckBackupPlans,
    CheckEbsSnapshotEncryption,
    CheckRdsBackupRetention,
    CheckRdsMultiAz,
    CheckRoute53HealthChecks,
    CheckS3ObjectLock,
    CheckS3Versioning,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


def _stub_bucket_pages(session, s3, pages: list[list[str]]):
    """Route the list_buckets paginator through a fake two-page result.

    moto does not implement ListBuckets ContinuationToken semantics, so the
    paginator is stubbed directly (same pattern as test_nr8_kryptographie).
    All other s3 operations keep hitting the moto-backed client.
    """
    fake_paginator = MagicMock()
    fake_paginator.paginate.return_value = [{"Buckets": [{"Name": name} for name in page]} for page in pages]

    real_get_paginator = s3.get_paginator

    def get_paginator(operation_name):
        if operation_name == "list_buckets":
            return fake_paginator
        return real_get_paginator(operation_name)

    s3.get_paginator = get_paginator

    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == "s3":
            return s3
        return real_client(service, region=region)

    session.client = client


def _create_db(session, db_id: str, retention: int, multi_az: bool = False) -> None:
    rds = session.client("rds")
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="testpass123",
        AllocatedStorage=20,
        BackupRetentionPeriod=retention,
        MultiAZ=multi_az,
    )


class TestCheckRdsBackupRetention:
    @mock_aws
    def test_short_retention_produces_finding(self):
        session = _make_session()
        _create_db(session, "short-retention", retention=1)

        result = asyncio.run(CheckRdsBackupRetention().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_sufficient_retention_produces_positive_evidence(self):
        session = _make_session()
        _create_db(session, "good-retention", retention=14)

        result = asyncio.run(CheckRdsBackupRetention().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["backup_retention_period"] == 14
        assert not _maengel(result)


class TestCheckS3Versioning:
    @mock_aws
    def test_versioned_bucket_produces_positive_evidence(self):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="versioned",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})

        result = asyncio.run(CheckS3Versioning().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert "versioned" in compliant[0].resource_id
        assert not _maengel(result)

    @mock_aws
    def test_unversioned_bucket_produces_finding(self):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="unversioned",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )

        result = asyncio.run(CheckS3Versioning().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_paginated_bucket_list_evaluates_all_pages(self):
        # FIX3: list_buckets() paginates via ContinuationToken — buckets past
        # the first page must not be silently skipped.
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="bucket-page1",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        s3.create_bucket(
            Bucket="bucket-page2",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        s3.put_bucket_versioning(Bucket="bucket-page2", VersioningConfiguration={"Status": "Enabled"})
        _stub_bucket_pages(session, s3, [["bucket-page1"], ["bucket-page2"]])

        result = asyncio.run(CheckS3Versioning().execute(session))

        page1 = [f for f in result.findings if "bucket-page1" in f.resource_id]
        page2 = [f for f in result.findings if "bucket-page2" in f.resource_id]
        assert len(page1) == 1
        assert page1[0].status == FindingStatus.NON_COMPLIANT
        assert len(page2) == 1
        assert page2[0].status == FindingStatus.COMPLIANT


class TestCheckS3ObjectLock:
    @mock_aws
    def test_object_lock_enabled_produces_positive_evidence(self):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="locked",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
            ObjectLockEnabledForBucket=True,
        )

        result = asyncio.run(CheckS3ObjectLock().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["object_lock"] == "Enabled"
        assert not _maengel(result)
        assert not result.errors

    @mock_aws
    def test_api_success_without_enabled_flag_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        # Simulates an API response that succeeds but does not report
        # ObjectLockEnabled=="Enabled" — must be treated as a defect, not
        # as positive evidence (B-Nr.3-2 logic fix).
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="ambiguous",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        monkeypatch.setattr(session, "client", lambda service, region=None: s3)
        monkeypatch.setattr(s3, "get_object_lock_configuration", lambda **kwargs: {"ObjectLockConfiguration": {}})

        result = asyncio.run(CheckS3ObjectLock().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["object_lock"] == "Disabled"
        assert not _compliant(result)
        assert not result.errors

    @mock_aws
    def test_object_lock_not_configured_produces_finding(self):
        # No mocking needed: moto raises ClientError(ObjectLockConfigurationNotFoundError)
        # for buckets created without ObjectLockEnabledForBucket=True.
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="unlocked",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )

        result = asyncio.run(CheckS3ObjectLock().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["object_lock"] == "Disabled"
        assert not _compliant(result)
        assert not result.errors

    @mock_aws
    def test_other_error_produces_check_error_and_no_finding(self, monkeypatch: pytest.MonkeyPatch):
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="broken",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        monkeypatch.setattr(session, "client", lambda service, region=None: s3)

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(s3, "get_object_lock_configuration", _raise)

        result = asyncio.run(CheckS3ObjectLock().execute(session))

        assert not result.findings
        assert len(result.errors) == 1

    @mock_aws
    def test_paginated_bucket_list_evaluates_all_pages(self):
        # FIX3: buckets past the first ListBuckets page must be evaluated too.
        session = _make_session()
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="bucket-page1",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        s3.create_bucket(
            Bucket="bucket-page2",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
            ObjectLockEnabledForBucket=True,
        )
        _stub_bucket_pages(session, s3, [["bucket-page1"], ["bucket-page2"]])

        result = asyncio.run(CheckS3ObjectLock().execute(session))

        page1 = [f for f in result.findings if "bucket-page1" in f.resource_id]
        page2 = [f for f in result.findings if "bucket-page2" in f.resource_id]
        assert len(page1) == 1
        assert page1[0].status == FindingStatus.NON_COMPLIANT
        assert len(page2) == 1
        assert page2[0].status == FindingStatus.COMPLIANT


class TestCheckEbsSnapshotEncryption:
    @mock_aws
    def test_encrypted_snapshot_produces_positive_evidence(self):
        session = _make_session()
        ec2 = session.client("ec2")
        volume = ec2.create_volume(AvailabilityZone="eu-central-1a", Size=10, Encrypted=True)
        ec2.create_snapshot(VolumeId=volume["VolumeId"])

        result = asyncio.run(CheckEbsSnapshotEncryption().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["encrypted"] is True
        assert not _maengel(result)

    @mock_aws
    def test_unencrypted_snapshot_produces_finding(self):
        session = _make_session()
        ec2 = session.client("ec2")
        volume = ec2.create_volume(AvailabilityZone="eu-central-1a", Size=10, Encrypted=False)
        ec2.create_snapshot(VolumeId=volume["VolumeId"])

        result = asyncio.run(CheckEbsSnapshotEncryption().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["encrypted"] is False
        assert not _compliant(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch: pytest.MonkeyPatch):
        session = _make_session()
        ec2 = session.client("ec2")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(ec2, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: ec2)

        result = asyncio.run(CheckEbsSnapshotEncryption().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckRdsMultiAz:
    @mock_aws
    def test_multi_az_produces_positive_evidence(self):
        session = _make_session()
        _create_db(session, "ha-db", retention=7, multi_az=True)

        result = asyncio.run(CheckRdsMultiAz().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["multi_az"] is True
        assert not _maengel(result)

    @mock_aws
    def test_single_az_produces_finding(self):
        session = _make_session()
        _create_db(session, "single-db", retention=7, multi_az=False)

        result = asyncio.run(CheckRdsMultiAz().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckRoute53HealthChecks:
    @mock_aws
    def test_no_health_checks_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckRoute53HealthChecks().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_health_check_produces_positive_evidence(self):
        session = _make_session()
        r53 = session.client("route53", region="us-east-1")
        r53.create_health_check(
            CallerReference="test-ref",
            HealthCheckConfig={
                "Type": "HTTPS",
                "FullyQualifiedDomainName": "example.com",
                "Port": 443,
                "ResourcePath": "/",
            },
        )

        result = asyncio.run(CheckRoute53HealthChecks().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)


class TestCheckBackupPlans:
    @mock_aws
    def test_no_plans_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckBackupPlans().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_backup_plan_produces_positive_evidence(self):
        session = _make_session()
        backup = session.client("backup")
        backup.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "daily",
                "Rules": [
                    {
                        "RuleName": "daily-rule",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": "cron(0 5 * * ? *)",
                    }
                ],
            }
        )

        result = asyncio.run(CheckBackupPlans().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["backup_plans_count"] == 1
        assert not _maengel(result)
