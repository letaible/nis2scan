"""Tests for §30 Nr. 1 — Risikoanalyse Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import (
    CheckActivityLogRetention,
    CheckAzurePolicyAssignments,
    CheckDefenderForCloud,
    CheckManagementGroups,
    CheckSentinelWorkspace,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class _PricingList:
    """azure-mgmt-security 6.x returns this wrapper, not an iterable pager.

    No ``__iter__`` on purpose: that is what made ``list(pricings.list())``
    raise for every user of 0.2.0 while the list-based fixtures below stayed
    green. Keep the shape, or this regression can return unnoticed.
    """

    def __init__(self, value):
        self.value = value


class TestCheckDefenderForCloud:
    def test_wrapper_model_response_is_evaluated_not_errored(self):
        # Regression (30.07.2026): with the real SDK shape the check errored
        # out entirely and delivered no verdict for §30 Nr. 1.
        client = MagicMock()
        client.pricings.list.return_value = _PricingList(
            [
                SimpleNamespace(name="VirtualMachines", pricing_tier="Standard"),
                SimpleNamespace(name="StorageAccounts", pricing_tier="Free"),
            ]
        )
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderForCloud().execute(session))

        assert not result.errors, f"Check darf nicht fehlschlagen: {[e.message for e in result.errors]}"
        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "StorageAccounts" in maengel[0].current_state["free_tier_plans"]

    def test_standard_tier_produces_positive_evidence(self):
        client = MagicMock()
        client.pricings.list.return_value = [
            SimpleNamespace(name="VirtualMachines", pricing_tier="Standard"),
            SimpleNamespace(name="StorageAccounts", pricing_tier="Standard"),
        ]
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderForCloud().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].account_id == SUB_ID
        assert not _maengel(result)
        assert not result.errors

    def test_free_tier_produces_finding(self):
        client = MagicMock()
        client.pricings.list.return_value = [
            SimpleNamespace(name="VirtualMachines", pricing_tier="Free"),
        ]
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderForCloud().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_recorded_no_evidence(self):
        client = MagicMock()
        client.pricings.list.side_effect = RuntimeError("boom")
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderForCloud().execute(session))

        assert len(result.errors) == 1
        assert not result.findings


class TestCheckAzurePolicyAssignments:
    def test_custom_assignment_produces_positive_evidence(self):
        client = MagicMock()
        client.policy_assignments.list.return_value = [
            SimpleNamespace(
                display_name="CIS Benchmark",
                policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/abc",
            ),
        ]
        session = FakeAzureSession({"PolicyClient": client})

        result = asyncio.run(CheckAzurePolicyAssignments().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_policy_assignments"] == 1
        assert not _maengel(result)

    def test_no_custom_assignments_produces_finding(self):
        client = MagicMock()
        client.policy_assignments.list.return_value = [
            SimpleNamespace(display_name="ASC Default", policy_definition_id=None),
        ]
        session = FakeAzureSession({"PolicyClient": client})

        result = asyncio.run(CheckAzurePolicyAssignments().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_initiative_assignment_produces_positive_evidence(self):
        client = MagicMock()
        client.policy_assignments.list.return_value = [
            SimpleNamespace(
                display_name="CIS Benchmark Initiative",
                policy_definition_id="/providers/Microsoft.Authorization/policySetDefinitions/abc",
            ),
        ]
        session = FakeAzureSession({"PolicyClient": client})

        result = asyncio.run(CheckAzurePolicyAssignments().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_policy_assignments"] == 1
        assert not _maengel(result)


class TestCheckManagementGroups:
    @pytest.fixture
    def mgmt_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        import azure.mgmt.managementgroups as mg_module

        client = MagicMock()
        monkeypatch.setattr(mg_module, "ManagementGroupsMgmtClient", lambda credential: client)
        return client

    def test_custom_group_produces_positive_evidence(self, mgmt_client: MagicMock):
        mgmt_client.management_groups.list.return_value = [
            SimpleNamespace(display_name="Tenant Root Group"),
            SimpleNamespace(display_name="Production"),
        ]
        session = FakeAzureSession()

        result = asyncio.run(CheckManagementGroups().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_management_groups"] == 1
        assert not _maengel(result)

    def test_only_root_group_produces_finding(self, mgmt_client: MagicMock):
        mgmt_client.management_groups.list.return_value = [
            SimpleNamespace(display_name="Tenant Root Group"),
        ]
        session = FakeAzureSession()

        result = asyncio.run(CheckManagementGroups().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "LOW"
        assert "gegenstandslos" in maengel[0].description
        assert not _compliant(result)


class TestCheckActivityLogRetention:
    def test_diagnostic_setting_produces_positive_evidence(self):
        client = MagicMock()
        client.diagnostic_settings.list.return_value = [SimpleNamespace(name="export-to-la")]
        session = FakeAzureSession({"MonitorManagementClient": client})

        result = asyncio.run(CheckActivityLogRetention().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)

    def test_no_settings_produces_finding(self):
        client = MagicMock()
        client.diagnostic_settings.list.return_value = []
        session = FakeAzureSession({"MonitorManagementClient": client})

        result = asyncio.run(CheckActivityLogRetention().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)


class TestCheckSentinelWorkspace:
    def test_active_workspace_produces_positive_evidence(self):
        client = MagicMock()
        client.workspaces.list.return_value = [SimpleNamespace(provisioning_state="Succeeded")]
        session = FakeAzureSession({"LogAnalyticsManagementClient": client})

        result = asyncio.run(CheckSentinelWorkspace().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)

    def test_no_workspace_produces_finding(self):
        client = MagicMock()
        client.workspaces.list.return_value = []
        session = FakeAzureSession({"LogAnalyticsManagementClient": client})

        result = asyncio.run(CheckSentinelWorkspace().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
