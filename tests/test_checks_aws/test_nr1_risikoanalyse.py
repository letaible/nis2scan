"""Tests for §30 Nr. 1 — Risikoanalyse AWS checks incl. positive evidence (ADR-0006)."""

import asyncio

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import (
    CheckCloudTrail,
    CheckConfigRecorder,
    CheckGuardDutyRiskAnalysis,
    CheckOrganizationsScp,
    CheckSecurityHub,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckCloudTrail:
    @mock_aws
    def test_no_trails_produces_critical_finding(self):
        session = _make_session()
        result = asyncio.run(CheckCloudTrail().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)

    @mock_aws
    def test_healthy_trail_produces_positive_evidence(self):
        session = _make_session()
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="trail-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        ct.create_trail(Name="main-trail", S3BucketName="trail-bucket", EnableLogFileValidation=True)
        ct.start_logging(Name="main-trail")

        result = asyncio.run(CheckCloudTrail().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].status == FindingStatus.COMPLIANT
        assert compliant[0].severity.value == "INFO"
        assert "main-trail" in compliant[0].description
        assert not _maengel(result)

    @mock_aws
    def test_trail_without_validation_no_positive_evidence(self):
        session = _make_session()
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="trail-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        ct.create_trail(Name="weak-trail", S3BucketName="trail-bucket", EnableLogFileValidation=False)
        ct.start_logging(Name="weak-trail")

        result = asyncio.run(CheckCloudTrail().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        ct = session.client("cloudtrail")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(ct, "describe_trails", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: ct)

        result = asyncio.run(CheckCloudTrail().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckConfigRecorder:
    @mock_aws
    def test_no_recorder_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckConfigRecorder().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"

    @mock_aws
    def test_recording_recorder_produces_positive_evidence(self):
        session = _make_session()
        config = session.client("config")
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="config-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/config-role",
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
            }
        )
        config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "config-bucket"})
        config.start_configuration_recorder(ConfigurationRecorderName="default")

        result = asyncio.run(CheckConfigRecorder().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert "default" in compliant[0].description
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        config = session.client("config")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(config, "describe_configuration_recorders", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: config)

        result = asyncio.run(CheckConfigRecorder().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckSecurityHub:
    @mock_aws
    def test_enabled_hub_produces_positive_evidence(self):
        session = _make_session()
        sh = session.client("securityhub")
        sh.enable_security_hub()

        result = asyncio.run(CheckSecurityHub().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        sh = session.client("securityhub")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(sh, "describe_hub", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: sh)

        result = asyncio.run(CheckSecurityHub().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckOrganizationsScp:
    @mock_aws
    def test_org_with_custom_scp_produces_positive_evidence(self):
        session = _make_session()
        org = session.client("organizations")
        org.create_organization(FeatureSet="ALL")
        org.create_policy(
            Name="deny-regions",
            Description="Deny non-EU regions",
            Type="SERVICE_CONTROL_POLICY",
            Content='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
        )

        result = asyncio.run(CheckOrganizationsScp().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert "benutzerdefinierte" in compliant[0].description
        assert not _maengel(result)

    @mock_aws
    def test_org_without_custom_scp_produces_finding(self):
        session = _make_session()
        org = session.client("organizations")
        org.create_organization(FeatureSet="ALL")

        result = asyncio.run(CheckOrganizationsScp().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_no_organization_produces_low_severity_finding(self):
        session = _make_session()

        result = asyncio.run(CheckOrganizationsScp().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "LOW"
        assert "gegenstandslos" in maengel[0].description
        assert not _compliant(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        org = session.client("organizations")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(org, "describe_organization", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: org)

        result = asyncio.run(CheckOrganizationsScp().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckGuardDuty:
    @mock_aws
    def test_no_detector_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckGuardDutyRiskAnalysis().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_enabled_detector_produces_positive_evidence(self):
        session = _make_session()
        gd = session.client("guardduty")
        gd.create_detector(Enable=True)

        result = asyncio.run(CheckGuardDutyRiskAnalysis().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["status"] == "ENABLED"
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        gd = session.client("guardduty")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(gd, "list_detectors", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: gd)

        result = asyncio.run(CheckGuardDutyRiskAnalysis().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"
