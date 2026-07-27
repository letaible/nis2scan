"""Tests for §30 Nr. 5 — Schwachstellenmanagement Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import (
    CheckAppServiceRuntime,
    CheckContainerRegistryScan,
    CheckDefenderVulnAssessment,
    CheckSqlVulnAssessment,
    CheckUpdateManagement,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckDefenderVulnAssessment:
    def _client(self, tier: str) -> MagicMock:
        client = MagicMock()
        client.pricings.list.return_value = [SimpleNamespace(name="VirtualMachines", pricing_tier=tier)]
        return client

    def test_standard_tier_produces_positive_evidence(self):
        session = FakeAzureSession({"SecurityCenter": self._client("Standard")})

        result = asyncio.run(CheckDefenderVulnAssessment().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_free_tier_produces_finding(self):
        session = FakeAzureSession({"SecurityCenter": self._client("Free")})

        result = asyncio.run(CheckDefenderVulnAssessment().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckUpdateManagement:
    def test_maintenance_config_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(name="patch-window")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckUpdateManagement().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_config_produces_finding(self):
        client = MagicMock()
        client.resources.list.return_value = []
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckUpdateManagement().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckContainerRegistryScan:
    def _client(self, sku: str) -> MagicMock:
        client = MagicMock()
        client.registries.list.return_value = [
            SimpleNamespace(
                name="acr1",
                sku=SimpleNamespace(name=sku),
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr1",
            ),
        ]
        return client

    def test_standard_sku_produces_positive_evidence(self):
        session = FakeAzureSession({"ContainerRegistryManagementClient": self._client("Standard")})

        result = asyncio.run(CheckContainerRegistryScan().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_basic_sku_produces_finding(self):
        session = FakeAzureSession({"ContainerRegistryManagementClient": self._client("Basic")})

        result = asyncio.run(CheckContainerRegistryScan().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckAppServiceRuntime:
    def _client(self, linux_fx: str) -> MagicMock:
        client = MagicMock()
        client.web_apps.list.return_value = [
            SimpleNamespace(
                name="app1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
                site_config=SimpleNamespace(linux_fx_version=linux_fx, net_framework_version=""),
            ),
        ]
        return client

    def test_current_runtime_produces_positive_evidence(self):
        session = FakeAzureSession({"WebSiteManagementClient": self._client("PYTHON|3.12")})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_outdated_runtime_produces_finding(self):
        session = FakeAzureSession({"WebSiteManagementClient": self._client("PYTHON|3.8")})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_dotnetcore_31_produces_finding(self):
        # B-Nr.5-12a/c: DOTNETCORE family was added to OUTDATED_RUNTIMES.
        session = FakeAzureSession({"WebSiteManagementClient": self._client("DOTNETCORE|3.1")})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_classic_dotnet_framework_is_not_judged(self):
        # B-Nr.5-20: netFrameworkVersion reports only the CLR version — v4.0 is
        # the normal value of a CURRENT .NET Framework 4.8 app. No finding, no error.
        client = MagicMock()
        client.web_apps.list.return_value = [
            SimpleNamespace(
                name="winapp",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Web/sites/winapp",
                site_config=SimpleNamespace(linux_fx_version="", net_framework_version="v4.0"),
            ),
        ]
        session = FakeAzureSession({"WebSiteManagementClient": client})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert not result.findings
        assert not result.errors

    def test_unknown_runtime_family_produces_no_finding_no_error(self):
        # B-Nr.5-12b: unrecognized runtime prefixes (DOCKER, COMPOSE, ...) are
        # not in OUTDATED_RUNTIMES and must be skipped — no finding, no error.
        session = FakeAzureSession({"WebSiteManagementClient": self._client("DOCKER|myimage:tag")})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert not result.findings
        assert not result.errors

    def test_empty_site_config_falls_back_to_get_configuration(self):
        # B-Nr.5-12f: the Azure list API often leaves siteConfig empty — the
        # check must fetch get_configuration() before giving up on the app.
        client = MagicMock()
        client.web_apps.list.return_value = [
            SimpleNamespace(
                name="app1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
                site_config=None,
            ),
        ]
        client.web_apps.get_configuration.return_value = SimpleNamespace(
            linux_fx_version="PYTHON|3.12", net_framework_version=""
        )
        session = FakeAzureSession({"WebSiteManagementClient": client})

        result = asyncio.run(CheckAppServiceRuntime().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)
        client.web_apps.get_configuration.assert_called_once_with("rg", "app1")


class TestCheckSqlVulnAssessment:
    def _client(self, va_configured: bool) -> MagicMock:
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv1", id=server_id, location="westeurope"),
        ]
        client.server_vulnerability_assessments.list_by_server.return_value = (
            [SimpleNamespace(name="default")] if va_configured else []
        )
        return client

    def test_va_enabled_produces_positive_evidence(self):
        session = FakeAzureSession({"SqlManagementClient": self._client(va_configured=True)})

        result = asyncio.run(CheckSqlVulnAssessment().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_va_missing_produces_finding(self):
        session = FakeAzureSession({"SqlManagementClient": self._client(va_configured=False)})

        result = asyncio.run(CheckSqlVulnAssessment().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_va_query_exception_produces_check_error(self):
        # B-Nr.5-13: a failed VA lookup must surface as a CheckError, not a
        # silent `except Exception: pass`.
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv1", id=server_id, location="westeurope"),
        ]
        client.server_vulnerability_assessments.list_by_server.side_effect = RuntimeError("boom")
        session = FakeAzureSession({"SqlManagementClient": client})

        result = asyncio.run(CheckSqlVulnAssessment().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert "srv1" in result.errors[0].message

    def test_resource_group_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: rg_name is interpolated into the remediation az-CLI
        # command; resource_id's tail is the server name, never the (mid-path)
        # resource group. Uses a >=3-char rg name — _collect_identifiers drops
        # shorter values (_MIN_IDENTIFIER_LEN), so the generic "rg" fixture
        # elsewhere in this file would not exercise the fix.
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-produktion/providers/Microsoft.Sql/servers/srv1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv1", id=server_id, location="westeurope"),
        ]
        client.server_vulnerability_assessments.list_by_server.return_value = []
        session = FakeAzureSession({"SqlManagementClient": client})

        result = asyncio.run(CheckSqlVulnAssessment().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["resource_group_name"] == "rg-produktion"

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "rg-produktion" not in pseudonymized.remediation
        assert pseudonymized.current_state["resource_group_name"].startswith("pseu_")
