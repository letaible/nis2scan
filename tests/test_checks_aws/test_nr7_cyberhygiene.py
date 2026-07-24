"""Tests for §30 Nr. 7 — Cyberhygiene AWS checks incl. positive evidence (ADR-0006)."""

import asyncio

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr7_cyberhygiene import (
    CheckIamPasswordPolicy,
    CheckRootAccessKeys,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session() -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckIamPasswordPolicy:
    @mock_aws
    def test_strong_policy_produces_positive_evidence(self):
        session = _make_session()
        iam = session.client("iam")
        iam.update_account_password_policy(
            MinimumPasswordLength=16,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
        )

        result = asyncio.run(CheckIamPasswordPolicy().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["minimum_password_length"] == 16
        assert not _maengel(result)

    @mock_aws
    def test_weak_policy_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.update_account_password_policy(MinimumPasswordLength=8)

        result = asyncio.run(CheckIamPasswordPolicy().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_no_policy_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckIamPasswordPolicy().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_account_password_policy", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        result = asyncio.run(CheckIamPasswordPolicy().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckRootAccessKeys:
    @mock_aws
    def test_no_root_keys_produces_positive_evidence(self):
        session = _make_session()
        result = asyncio.run(CheckRootAccessKeys().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["root_access_keys_present"] == 0
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        iam = session.client("iam")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(iam, "get_account_summary", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: iam)

        result = asyncio.run(CheckRootAccessKeys().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
