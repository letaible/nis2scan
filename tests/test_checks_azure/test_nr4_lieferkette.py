"""Tests for §30 Nr. 4 — Lieferkette Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr4_lieferkette import (
    CheckGuestUsersConditionalAccess,
    CheckLighthouseDelegations,
    CheckMarketplaceImageTrust,
    CheckPrivateEndpoints,
    CheckServicePrincipalCredentials,
)

from .conftest import FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckLighthouseDelegations:
    def test_no_delegations_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = []
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckLighthouseDelegations().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_delegations_produce_finding(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(name="msp-delegation")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckLighthouseDelegations().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckGuestUsersConditionalAccess:
    def _setup_graph(self, monkeypatch: pytest.MonkeyPatch, guests: bool, ca_for_guests: bool) -> None:
        from nis2scan.engine.providers.azure import graph

        users = [{"id": "u-1", "userType": "Guest"}] if guests else [{"id": "u-1", "userType": "Member"}]
        policies: list[dict] = []
        if ca_for_guests:
            policies = [
                {
                    "state": "enabled",
                    "conditions": {
                        "users": {
                            "includeUsers": ["All"],
                            "includeGroups": [],
                            "includeGuestsOrExternalUsers": None,
                        }
                    },
                }
            ]

        async def fake_get_all(credential, url, timeout=30.0):
            if "conditionalAccess" in url:
                return policies
            return users

        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)

    def test_guests_with_ca_produce_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        self._setup_graph(monkeypatch, guests=True, ca_for_guests=True)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_guests_without_ca_produce_finding(self, monkeypatch: pytest.MonkeyPatch):
        self._setup_graph(monkeypatch, guests=True, ca_for_guests=False)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_no_guests_yields_no_findings(self, monkeypatch: pytest.MonkeyPatch):
        self._setup_graph(monkeypatch, guests=False, ca_for_guests=False)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert not result.findings
        assert not result.errors

    def test_ca_policy_with_only_include_groups_produces_no_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        # A CA policy that targets guests only via group membership must not count as
        # covering guests (B-Nr.4-8) — group membership is not evaluated by this check.
        from nis2scan.engine.providers.azure import graph

        users = [{"id": "u-1", "userType": "Guest"}]
        policies = [
            {
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": [],
                        "includeGroups": ["some-group-id"],
                        "includeGuestsOrExternalUsers": None,
                    }
                },
            }
        ]

        async def fake_get_all(credential, url, timeout=30.0):
            if "conditionalAccess" in url:
                return policies
            return users

        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert not _compliant(result)
        assert len(_maengel(result)) == 1


class TestCheckPrivateEndpoints:
    def test_endpoints_produce_positive_evidence(self):
        client = MagicMock()
        client.private_endpoints.list_by_subscription.return_value = [SimpleNamespace(name="pe-sql")]
        session = FakeAzureSession({"NetworkManagementClient": client})

        result = asyncio.run(CheckPrivateEndpoints().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_endpoints_produces_finding(self):
        client = MagicMock()
        client.private_endpoints.list_by_subscription.return_value = []
        session = FakeAzureSession({"NetworkManagementClient": client})

        result = asyncio.run(CheckPrivateEndpoints().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckServicePrincipalCredentials:
    def _setup_apps(self, monkeypatch: pytest.MonkeyPatch, cred_age_days: int) -> None:
        from nis2scan.engine.providers.azure import graph

        start = (datetime.now(UTC) - timedelta(days=cred_age_days)).isoformat()
        apps = [
            {
                "id": "app-1",
                "displayName": "app-1",
                "passwordCredentials": [{"startDateTime": start}],
            },
        ]

        async def fake_get_all(credential, url, timeout=30.0):
            return apps

        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)

    def test_fresh_credentials_produce_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        self._setup_apps(monkeypatch, cred_age_days=10)
        session = FakeAzureSession()

        result = asyncio.run(CheckServicePrincipalCredentials().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_old_credentials_produce_finding(self, monkeypatch: pytest.MonkeyPatch):
        self._setup_apps(monkeypatch, cred_age_days=200)
        session = FakeAzureSession()

        result = asyncio.run(CheckServicePrincipalCredentials().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckMarketplaceImageTrust:
    def _compute_client(self, publisher: str) -> MagicMock:
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [
            SimpleNamespace(
                name="vm-1",
                storage_profile=SimpleNamespace(image_reference=SimpleNamespace(publisher=publisher)),
            ),
        ]
        return client

    def test_trusted_publisher_produces_positive_evidence(self):
        session = FakeAzureSession({"ComputeManagementClient": self._compute_client("Canonical")})

        result = asyncio.run(CheckMarketplaceImageTrust().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_untrusted_publisher_produces_finding(self):
        session = FakeAzureSession({"ComputeManagementClient": self._compute_client("shady-images-inc")})

        result = asyncio.run(CheckMarketplaceImageTrust().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_untrusted_vm_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: vm_summary interpolates VM names into the description;
        # resource_id/account_id here only cover the subscription.
        session = FakeAzureSession({"ComputeManagementClient": self._compute_client("shady-images-inc")})

        result = asyncio.run(CheckMarketplaceImageTrust().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["untrusted_vm_name"] == ["vm-1"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "vm-1" not in pseudonymized.description
        assert pseudonymized.current_state["untrusted_vm_name"][0].startswith("pseu_")
