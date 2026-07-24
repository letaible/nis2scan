"""Tests for §30 Nr. 10 — MFA & gesicherte Kommunikation AWS checks using moto."""

import asyncio
import json

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import (
    CheckBreakGlassProcedure,
    CheckIamUserMfaEnforcement,
    CheckRootMfa,
    CheckSesSnsTls,
    CheckVpnAdminAccess,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


class TestCheckRootMfa:
    """Tests for root account MFA check."""

    @mock_aws
    def test_root_without_mfa_produces_finding(self):
        session = _make_session()

        check = CheckRootMfa()
        result = asyncio.run(check.execute(session))

        # moto's default account summary has AccountMFAEnabled=0
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR10-001"
        assert finding.severity.value == "CRITICAL"
        assert finding.bsig_30_nr == 10

    @mock_aws
    def test_check_returns_no_errors(self):
        session = _make_session()

        check = CheckRootMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.errors) == 0


class TestCheckIamUserMfaEnforcement:
    """Tests for IAM user MFA enforcement check."""

    @mock_aws
    def test_console_user_without_mfa_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="console-user")
        iam.create_login_profile(UserName="console-user", Password="TestPass123!")

        check = CheckIamUserMfaEnforcement()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR10-002"
        assert finding.severity.value == "CRITICAL"
        assert finding.bsig_30_nr == 10

    @mock_aws
    def test_api_only_user_no_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="api-only-user")
        # No login profile = no console access

        check = CheckIamUserMfaEnforcement()
        result = asyncio.run(check.execute(session))

        # API-only users without console access should not produce findings
        assert len(result.findings) == 0

    @mock_aws
    def test_no_users_no_findings(self):
        session = _make_session()
        check = CheckIamUserMfaEnforcement()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0

    @mock_aws
    def test_no_mfa_finding_text_has_no_legal_citation(self):
        """B-Nr.10-1: the §30-citation sentence was struck, wording must not reappear."""
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="console-user")
        iam.create_login_profile(UserName="console-user", Password="TestPass123!")

        check = CheckIamUserMfaEnforcement()
        result = asyncio.run(check.execute(session))

        finding = result.findings[0]
        assert "verstößt gegen" not in finding.description
        assert "§30 Abs. 2 Nr. 10" not in finding.description
        assert "kein MFA-Gerät konfiguriert" in finding.description

    @mock_aws
    def test_generic_get_login_profile_error_produces_check_error(self):
        """B-Nr.10-1: only NoSuchEntity is skipped; other errors must surface as CheckError."""
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="broken-user")

        def raise_generic(**kwargs):
            raise RuntimeError("transient AWS error")

        iam.get_login_profile = raise_generic  # type: ignore[method-assign]

        real_client = session.client

        def client(service: str, region: str | None = None):
            if service == "iam":
                return iam
            return real_client(service, region=region)

        session.client = client  # type: ignore[method-assign]

        check = CheckIamUserMfaEnforcement()
        result = asyncio.run(check.execute(session))

        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
        assert "transient AWS error" in result.errors[0].message
        assert len(result.findings) == 0


class TestCheckSesSnsTls:
    """Tests for §30 Nr. 10 SNS TLS enforcement check (AWS-NR10-004, Rewidmung B-Nr.10-2/-3)."""

    @mock_aws
    def test_deny_statement_with_secure_transport_false_produces_positive_evidence(self):
        session = _make_session()
        sns = session.client("sns")
        topic = sns.create_topic(Name="secure-topic")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "SNS:Publish",
                    "Resource": topic["TopicArn"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
        sns.set_topic_attributes(TopicArn=topic["TopicArn"], AttributeName="Policy", AttributeValue=json.dumps(policy))

        check = CheckSesSnsTls()
        result = asyncio.run(check.execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(compliant) == 1
        assert not maengel

    @mock_aws
    def test_allow_statement_with_secure_transport_true_produces_finding(self):
        """A mere substring match on aws:SecureTransport is not enforcement (B-Nr.10-3)."""
        session = _make_session()
        sns = session.client("sns")
        topic = sns.create_topic(Name="insecure-topic")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "SNS:Publish",
                    "Resource": topic["TopicArn"],
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        }
        sns.set_topic_attributes(TopicArn=topic["TopicArn"], AttributeName="Policy", AttributeValue=json.dumps(policy))

        check = CheckSesSnsTls()
        result = asyncio.run(check.execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert not compliant

    def test_required_permissions_do_not_include_ses(self):
        assert "ses:GetAccount" not in CheckSesSnsTls.required_permissions


class TestCheckVpnAdminAccess:
    """Tests for AWS-NR10-003 (VPN/Client VPN for admin access)."""

    @mock_aws
    def test_active_gateway_produces_positive_evidence(self):
        session = _make_session()
        ec2 = session.client("ec2")
        ec2.create_vpn_gateway(Type="ipsec.1")

        result = asyncio.run(CheckVpnAdminAccess().execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1
        assert not result.errors

    @mock_aws
    def test_no_vpn_produces_finding(self, monkeypatch):
        # moto has no backend for describe_client_vpn_endpoints — stub only that
        # call (describe_vpn_gateways stays real/moto-backed and returns empty).
        session = _make_session()
        ec2 = session.client("ec2")
        monkeypatch.setattr(ec2, "describe_client_vpn_endpoints", lambda **kwargs: {"ClientVpnEndpoints": []})
        monkeypatch.setattr(session, "client", lambda service, region=None: ec2)

        result = asyncio.run(CheckVpnAdminAccess().execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not result.errors

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        ec2 = session.client("ec2")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(ec2, "describe_vpn_gateways", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: ec2)

        result = asyncio.run(CheckVpnAdminAccess().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckBreakGlassProcedure:
    """Tests for AWS-NR10-005 (break-glass emergency access)."""

    @mock_aws
    def test_break_glass_named_user_produces_positive_evidence(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="break-glass-admin")

        result = asyncio.run(CheckBreakGlassProcedure().execute(session))

        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1
        assert not result.errors

    @mock_aws
    def test_no_break_glass_user_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="regular-user")

        result = asyncio.run(CheckBreakGlassProcedure().execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not result.errors

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_paginator", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        result = asyncio.run(CheckBreakGlassProcedure().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
