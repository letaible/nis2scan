"""Tests for §30 Nr. 6 — Wirksamkeit Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import (
    CheckDefenderSecureScore,
    CheckDiagnosticSettings,
    CheckLogRetention,
    CheckPolicyComplianceState,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckDefenderSecureScore:
    def _client(self, current: int, maximum: int) -> MagicMock:
        client = MagicMock()
        client.secure_scores.list.return_value = [
            SimpleNamespace(current_score=current, max_score=maximum),
        ]
        return client

    def test_high_score_produces_positive_evidence(self):
        session = FakeAzureSession({"SecurityCenter": self._client(45, 50)})

        result = asyncio.run(CheckDefenderSecureScore().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["percentage"] == 90.0
        assert not _maengel(result)

    def test_low_score_produces_finding(self):
        session = FakeAzureSession({"SecurityCenter": self._client(20, 50)})

        result = asyncio.run(CheckDefenderSecureScore().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_empty_scores_produces_check_error_no_finding(self):
        # B-Nr.6-7: an empty secure_scores.list() used to silently produce zero
        # findings — it must now surface as a CheckError, not stay quiet.
        client = MagicMock()
        client.secure_scores.list.return_value = []
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderSecureScore().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "NoSecureScoreData"

    def test_incomplete_score_produces_check_error_no_finding(self):
        # B-Nr.6-7: current_score/max_score None used to be defaulted to 0/1,
        # fabricating a 0% Mangel-Finding instead of reporting "unknown".
        client = MagicMock()
        client.secure_scores.list.return_value = [
            SimpleNamespace(current_score=None, max_score=50),
        ]
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderSecureScore().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "IncompleteSecureScore"


class TestCheckPolicyComplianceState:
    @pytest.fixture
    def policy_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        import azure.mgmt.policyinsights as pi_module

        client = MagicMock()
        monkeypatch.setattr(pi_module, "PolicyInsightsClient", lambda credential, sub_id: client)
        return client

    def test_all_compliant_produces_positive_evidence(self, policy_client: MagicMock):
        policy_client.policy_states.list_query_results_for_subscription.return_value = [
            SimpleNamespace(compliance_state="Compliant"),
        ]
        session = FakeAzureSession()

        result = asyncio.run(CheckPolicyComplianceState().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_non_compliant_produces_finding(self, policy_client: MagicMock):
        policy_client.policy_states.list_query_results_for_subscription.return_value = [
            SimpleNamespace(compliance_state="NonCompliant"),
        ]
        session = FakeAzureSession()

        result = asyncio.run(CheckPolicyComplianceState().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_empty_results_produces_medium_finding(self, policy_client: MagicMock):
        # B-Nr.6-8(i): an empty result set matched neither branch before — it was
        # a silent gap, not a MEDIUM "no data" finding.
        policy_client.policy_states.list_query_results_for_subscription.return_value = []
        session = FakeAzureSession()

        result = asyncio.run(CheckPolicyComplianceState().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "Keine Policy-Compliance-Daten vorhanden"
        assert maengel[0].severity == Severity.MEDIUM
        assert not _compliant(result)


class TestCheckLogRetention:
    def _client(self, retention: int) -> MagicMock:
        client = MagicMock()
        client.workspaces.list.return_value = [
            SimpleNamespace(
                name="ws1",
                retention_in_days=retention,
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws1",
            ),
        ]
        return client

    def test_long_retention_produces_positive_evidence(self):
        session = FakeAzureSession({"LogAnalyticsManagementClient": self._client(400)})

        result = asyncio.run(CheckLogRetention().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_short_retention_produces_finding(self):
        session = FakeAzureSession({"LogAnalyticsManagementClient": self._client(30)})

        result = asyncio.run(CheckLogRetention().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckDiagnosticSettings:
    def _session(self, has_settings: bool) -> FakeAzureSession:
        resource_client = MagicMock()
        resource_client.resources.list.return_value = [
            SimpleNamespace(
                name="kv1",
                type="Microsoft.KeyVault/vaults",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            ),
        ]
        monitor_client = MagicMock()
        monitor_client.diagnostic_settings.list.return_value = [SimpleNamespace(name="diag")] if has_settings else []
        return FakeAzureSession(
            {"ResourceManagementClient": resource_client, "MonitorManagementClient": monitor_client}
        )

    def test_all_with_settings_produces_positive_evidence(self):
        result = asyncio.run(CheckDiagnosticSettings().execute(self._session(has_settings=True)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_missing_settings_produces_finding(self):
        result = asyncio.run(CheckDiagnosticSettings().execute(self._session(has_settings=False)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_resource_without_diag_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: resource_summary interpolates critical-resource names
        # (Key Vaults, SQL servers, storage accounts, NSGs) into the
        # description; resource_id/account_id here only cover the subscription.
        resource_client = MagicMock()
        resource_client.resources.list.return_value = [
            SimpleNamespace(
                name="kv-secrets-prod",
                type="Microsoft.KeyVault/vaults",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-secrets-prod",
            ),
        ]
        monitor_client = MagicMock()
        monitor_client.diagnostic_settings.list.return_value = []
        session = FakeAzureSession(
            {"ResourceManagementClient": resource_client, "MonitorManagementClient": monitor_client}
        )

        result = asyncio.run(CheckDiagnosticSettings().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["resource_without_diag_name"] == ["kv-secrets-prod"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "kv-secrets-prod" not in pseudonymized.description
        assert pseudonymized.current_state["resource_without_diag_name"][0].startswith("pseu_")

    def test_partial_query_failure_produces_check_error_no_positive_evidence(self):
        # B-Nr.6-10: a failed diagnostic_settings.list() call for one resource used
        # to be swallowed silently (`except Exception: pass`) while the other
        # resource's success still counted toward "all resources verified".
        resource_client = MagicMock()
        resource_client.resources.list.return_value = [
            SimpleNamespace(
                name="kv1",
                type="Microsoft.KeyVault/vaults",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            ),
            SimpleNamespace(
                name="kv2",
                type="Microsoft.KeyVault/vaults",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv2",
            ),
        ]
        monitor_client = MagicMock()
        monitor_client.diagnostic_settings.list.side_effect = [
            RuntimeError("transient failure"),
            [SimpleNamespace(name="diag")],
        ]
        session = FakeAzureSession(
            {"ResourceManagementClient": resource_client, "MonitorManagementClient": monitor_client}
        )

        result = asyncio.run(CheckDiagnosticSettings().execute(session))

        assert not _compliant(result)
        assert not _maengel(result)
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "DiagnosticSettingsQueryFailed"
