"""Tests for §30 Nr. 6 — Wirksamkeit GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr6_wirksamkeit import (
    CheckAuditLogIntegrity,
    CheckMonitoringDashboards,
    CheckPolicyIntelligence,
    CheckSecurityHealthAnalytics,
)

from .conftest import PROJECT_ID, FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckAuditLogIntegrity:
    @pytest.fixture
    def logging_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        # SDK-Pin-Verifikation 27.07.2026: `google.cloud.logging_v2` never re-exported
        # ConfigServiceV2Client at its top level — the real class lives in the
        # `services.config_service_v2` submodule (see nr2_vorfallsbewaltigung fixture).
        from google.cloud.logging_v2.services import config_service_v2

        client = MagicMock()
        monkeypatch.setattr(config_service_v2, "ConfigServiceV2Client", lambda credentials: client)
        return client

    def test_storage_sink_produces_positive_evidence(self, logging_client: MagicMock):
        logging_client.list_sinks.return_value = [
            SimpleNamespace(destination="storage.googleapis.com/audit-bucket"),
        ]

        result = asyncio.run(CheckAuditLogIntegrity().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_storage_sink_produces_finding(self, logging_client: MagicMock):
        logging_client.list_sinks.return_value = [
            SimpleNamespace(destination="bigquery.googleapis.com/projects/x/datasets/y"),
        ]

        result = asyncio.run(CheckAuditLogIntegrity().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_real_sdk_config_service_v2_client_lives_in_services_submodule(self):
        # Regression guard for mock drift (SDK-Pin-Verifikation 27.07.2026, GCP-NR6-001):
        # `google.cloud.logging_v2.ConfigServiceV2Client` never existed — the real class
        # only lives in `google.cloud.logging_v2.services.config_service_v2`.
        from google.cloud import logging_v2
        from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client

        assert not hasattr(logging_v2, "ConfigServiceV2Client")
        assert ConfigServiceV2Client.__name__ == "ConfigServiceV2Client"


class TestCheckSecurityHealthAnalytics:
    @pytest.fixture
    def scc_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import securitycenter_v1

        client = MagicMock()
        monkeypatch.setattr(securitycenter_v1, "SecurityCenterClient", lambda credentials: client)
        return client

    def test_accessible_scc_produces_positive_evidence(self, scc_client: MagicMock):
        scc_client.list_findings.return_value = iter([SimpleNamespace(name="finding-1")])

        result = asyncio.run(CheckSecurityHealthAnalytics().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_generic_permission_denied_produces_check_error_not_finding(self, scc_client: MagicMock):
        # B-Nr.6-13(ii): a bare "permission denied" is not an unambiguous
        # deactivation signal — it must become a CheckError, not a Mangel.
        scc_client.list_findings.side_effect = RuntimeError("403 permission denied")

        result = asyncio.run(CheckSecurityHealthAnalytics().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1

    def test_access_not_configured_produces_finding(self, scc_client: MagicMock):
        # Unambiguous deactivation signal → still a Mangel finding.
        scc_client.list_findings.side_effect = RuntimeError(
            "PERMISSION_DENIED: Security Center API accessNotConfigured"
        )

        result = asyncio.run(CheckSecurityHealthAnalytics().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
        assert not result.errors

    def test_disabled_scc_finding_does_not_leak_raw_exception_text(self, scc_client: MagicMock):
        # ADR-0011: Google API error messages regularly embed the caller's
        # project NUMBER or principal e-mail — text account_id (which only
        # covers the configured, alphanumeric project ID) does not cover, and
        # pseudonymize.py drops CheckError.message for exactly this reason.
        # current_state must therefore carry only the exception type, never
        # the raw message (audit_evidence already exposes only the type).
        raw_error = (
            "PERMISSION_DENIED: Security Center API has not been used in project 123456789012 before or it is disabled."
        )
        scc_client.list_findings.side_effect = RuntimeError(raw_error)

        result = asyncio.run(CheckSecurityHealthAnalytics().execute(FakeGcpSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state == {"scc_accessible": False, "error_type": "RuntimeError"}
        assert "123456789012" not in str(maengel[0].current_state)

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[maengel[0]])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "123456789012" not in pseudonymized.description
        assert "123456789012" not in str(pseudonymized.current_state)


class TestCheckPolicyIntelligence:
    def _session(self, error_message: str | None) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.locations.return_value.recommenders.return_value
        if error_message is not None:
            chain.recommendations.return_value.list.return_value.execute.side_effect = RuntimeError(error_message)
        else:
            chain.recommendations.return_value.list.return_value.execute.return_value = {"recommendations": []}
        return FakeGcpSession(services={"recommender": svc})

    def test_accessible_recommender_produces_positive_evidence(self):
        result = asyncio.run(CheckPolicyIntelligence().execute(self._session(error_message=None)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_generic_permission_denied_produces_check_error_not_finding(self):
        # B-Nr.6-13(ii): same unified classification as GCP-NR6-002.
        session = self._session(error_message="403 permission denied")

        result = asyncio.run(CheckPolicyIntelligence().execute(session))

        assert not result.findings
        assert len(result.errors) == 1

    def test_access_not_configured_produces_finding(self):
        session = self._session(error_message="PERMISSION_DENIED: Recommender API accessNotConfigured")

        result = asyncio.run(CheckPolicyIntelligence().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
        assert not result.errors

    def test_recommender_parent_uses_global_location_not_wildcard(self):
        # Real-API-verified 27.07.2026 (SDK-Fix-Paket): the Recommender API
        # rejects the "-" location wildcard with 400 "Invalid location: -."
        # (unlike Compute Engine's aggregated_list). google.iam.policy.Recommender
        # is a global-scoped recommender, so "global" is the only correct value.
        session = self._session(error_message=None)
        service = session.service("recommender")
        chain = service.projects.return_value.locations.return_value.recommenders.return_value

        asyncio.run(CheckPolicyIntelligence().execute(session))

        _, kwargs = chain.recommendations.return_value.list.call_args
        assert kwargs["parent"] == (
            f"projects/{PROJECT_ID}/locations/global/recommenders/google.iam.policy.Recommender"
        )


class TestCheckMonitoringDashboards:
    def _session(self, dashboards: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.dashboards.return_value.list.return_value.execute.return_value = {
            "dashboards": [{"name": f"db-{i}"} for i in range(dashboards)]
        }
        return FakeGcpSession(services={"monitoring": svc})

    def test_dashboards_produce_positive_evidence(self):
        result = asyncio.run(CheckMonitoringDashboards().execute(self._session(dashboards=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_dashboards_produces_finding(self):
        result = asyncio.run(CheckMonitoringDashboards().execute(self._session(dashboards=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
