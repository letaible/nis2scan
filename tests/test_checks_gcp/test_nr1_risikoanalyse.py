"""Tests for §30 Nr. 1 — Risikoanalyse GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr1_risikoanalyse import (
    CheckAssetInventory,
    CheckAuditLogConfig,
    CheckOrgPolicies,
    CheckSecurityCommandCenter,
)

from .conftest import FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckSecurityCommandCenter:
    @pytest.fixture
    def scc_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import securitycenter_v1

        client = MagicMock()
        monkeypatch.setattr(securitycenter_v1, "SecurityCenterClient", lambda credentials: client)
        return client

    def test_sources_produce_positive_evidence(self, scc_client: MagicMock):
        scc_client.list_sources.return_value = [SimpleNamespace(name="source-1")]

        result = asyncio.run(CheckSecurityCommandCenter().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_sources_produces_finding(self, scc_client: MagicMock):
        scc_client.list_sources.return_value = []

        result = asyncio.run(CheckSecurityCommandCenter().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, scc_client: MagicMock):
        scc_client.list_sources.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckSecurityCommandCenter().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckOrgPolicies:
    def _session(self, policies: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.policies.return_value.list.return_value.execute.return_value = {
            "policies": [{"name": f"policy-{i}"} for i in range(policies)]
        }
        return FakeGcpSession(services={"orgpolicy": svc})

    def test_policies_produce_positive_evidence(self):
        result = asyncio.run(CheckOrgPolicies().execute(self._session(policies=2)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_policies_produces_finding(self):
        result = asyncio.run(CheckOrgPolicies().execute(self._session(policies=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(policies=0)
        service = session.service("orgpolicy", "v2")
        service.projects.return_value.policies.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckOrgPolicies().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckAuditLogConfig:
    def _session(self, audit_configs: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "auditConfigs": [{"service": "allServices"}] * audit_configs
        }
        return FakeGcpSession(services={"cloudresourcemanager": svc})

    def _session_service_specific_only(self) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "auditConfigs": [{"service": "storage.googleapis.com"}]
        }
        return FakeGcpSession(services={"cloudresourcemanager": svc})

    def test_all_services_audit_config_produces_positive_evidence(self):
        result = asyncio.run(CheckAuditLogConfig().execute(self._session(audit_configs=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_audit_configs_produces_finding(self):
        result = asyncio.run(CheckAuditLogConfig().execute(self._session(audit_configs=0)))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert maengel[0].title == "Audit-Logging nicht konfiguriert"
        assert not _compliant(result)

    def test_service_specific_only_audit_configs_produce_finding(self):
        result = asyncio.run(CheckAuditLogConfig().execute(self._session_service_specific_only()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert maengel[0].title == "Audit-Logs nicht für alle Dienste konfiguriert"
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(audit_configs=0)
        service = session.service("cloudresourcemanager", "v1")
        service.projects.return_value.getIamPolicy.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckAuditLogConfig().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckAssetInventory:
    @pytest.fixture
    def asset_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import asset_v1

        client = MagicMock()
        monkeypatch.setattr(asset_v1, "AssetServiceClient", lambda credentials: client)
        return client

    def test_feeds_produce_positive_evidence(self, asset_client: MagicMock):
        # Real-shape mock (SDK-Fix-Paket 27.07.2026, GCP-NR1-004): list_feeds()
        # returns a ListFeedsResponse with a `feeds` attribute — it is NOT itself
        # iterable, unlike most other List* RPCs in this SDK (see the real-shape
        # guard test below).
        asset_client.list_feeds.return_value = SimpleNamespace(feeds=[SimpleNamespace(name="feed-1")])

        result = asyncio.run(CheckAssetInventory().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_feeds_produces_finding(self, asset_client: MagicMock):
        asset_client.list_feeds.return_value = SimpleNamespace(feeds=[])

        result = asyncio.run(CheckAssetInventory().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, asset_client: MagicMock):
        asset_client.list_feeds.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckAssetInventory().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"

    def test_real_sdk_list_feeds_response_is_not_iterable(self):
        # Real-shape guard (SDK-Fix-Paket 27.07.2026, GCP-NR1-004): the real
        # ListFeedsResponse type must NOT be directly iterable — asserting on the
        # actual generated proto-plus type (no network call) catches drift back
        # to the pre-fix "list(client.list_feeds(...))" pattern.
        from google.cloud.asset_v1.types import asset_service

        response = asset_service.ListFeedsResponse()
        with pytest.raises(TypeError):
            iter(response)
        assert list(response.feeds) == []
