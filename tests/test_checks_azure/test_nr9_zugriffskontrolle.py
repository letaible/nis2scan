"""Tests for §30 Nr. 9 — Zugriffskontrolle Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import (
    CheckClassicAdmins,
    CheckConditionalAccess,
    CheckGuestAccessRestrictions,
    CheckNsgOpenAccess,
    CheckPim,
    CheckStaleServicePrincipals,
    CheckStoragePublicAccess,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


@pytest.fixture
def graph_router(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """URL-routing fake for the Graph REST helper (graph_get_all / graph_get).

    Tests register wire-format (camelCase) fixture data by URL substring in
    `.collections` (for graph_get_all) or `.objects` (for graph_get); the fakes
    below dispatch on the first substring found in the requested URL — same
    pattern as TestCheckStaleServicePrincipals's own `_setup`.
    """
    from nis2scan.engine.providers.azure import graph

    router = SimpleNamespace(collections={}, objects={})

    async def fake_get_all(credential, url, timeout=30.0):
        for substring, value in router.collections.items():
            if substring in url:
                return value
        raise AssertionError(f"No graph_get_all route registered for URL: {url}")

    async def fake_get(credential, url, timeout=30.0):
        for substring, value in router.objects.items():
            if substring in url:
                return value
        raise AssertionError(f"No graph_get route registered for URL: {url}")

    monkeypatch.setattr(graph, "graph_get_all", fake_get_all)
    monkeypatch.setattr(graph, "graph_get", fake_get)

    return router


class TestCheckConditionalAccess:
    def test_enabled_policy_produces_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = [{"state": "enabled"}]
        result = asyncio.run(CheckConditionalAccess().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_policies_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = []
        result = asyncio.run(CheckConditionalAccess().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_report_only_policy_produces_finding_not_positive_evidence(self, graph_router: SimpleNamespace):
        # B-9-6: enabledForReportingButNotEnforced does not enforce access, so it
        # must not count as positive evidence.
        graph_router.collections["conditionalAccess"] = [{"state": "enabledForReportingButNotEnforced"}]
        result = asyncio.run(CheckConditionalAccess().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        assert "Report-only" in maengel[0].description


class TestCheckPim:
    def test_eligible_assignments_produce_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["roleEligibilityScheduleInstances"] = [{"id": "pim-1"}]
        result = asyncio.run(CheckPim().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_pim_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["roleEligibilityScheduleInstances"] = []
        result = asyncio.run(CheckPim().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckNsgOpenAccess:
    def _client(self, source_prefix: str) -> MagicMock:
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            SimpleNamespace(
                name="nsg1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                security_rules=[
                    SimpleNamespace(
                        name="rule1",
                        direction="Inbound",
                        access="Allow",
                        source_address_prefix=source_prefix,
                        destination_port_range="443",
                        protocol="Tcp",
                    ),
                ],
            ),
        ]
        return client

    def test_restricted_nsg_produces_positive_evidence(self):
        session = FakeAzureSession({"NetworkManagementClient": self._client("10.0.0.0/8")})

        result = asyncio.run(CheckNsgOpenAccess().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_open_nsg_produces_finding(self):
        session = FakeAzureSession({"NetworkManagementClient": self._client("0.0.0.0/0")})

        result = asyncio.run(CheckNsgOpenAccess().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def _client_with_plural_prefixes(self, source_prefixes: list[str]) -> MagicMock:
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            SimpleNamespace(
                name="nsg1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                security_rules=[
                    SimpleNamespace(
                        name="rule1",
                        direction="Inbound",
                        access="Allow",
                        source_address_prefix=None,
                        source_address_prefixes=source_prefixes,
                        destination_port_range="443",
                        protocol="Tcp",
                    ),
                ],
            ),
        ]
        return client

    def test_open_source_in_plural_field_produces_finding(self):
        # B-9-7: source_address_prefixes (list) must be checked too, not just
        # the singular source_address_prefix.
        session = FakeAzureSession(
            {"NetworkManagementClient": self._client_with_plural_prefixes(["10.0.0.0/8", "0.0.0.0/0"])}
        )

        result = asyncio.run(CheckNsgOpenAccess().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def _client_with_rule_name(self, rule_name: str) -> MagicMock:
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            SimpleNamespace(
                name="nsg1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                security_rules=[
                    SimpleNamespace(
                        name=rule_name,
                        direction="Inbound",
                        access="Allow",
                        source_address_prefix="0.0.0.0/0",
                        destination_port_range="3389",
                        protocol="Tcp",
                    ),
                ],
            ),
        ]
        return client

    def test_open_inbound_rule_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: rule_summary interpolates customer-chosen NSG rule names
        # into the description; the "open_inbound_rules" list carries them
        # nested in dicts ({"name": ..., "port": ..., "protocol": ...}) which
        # _collect_identifiers never inspects.
        session = FakeAzureSession({"NetworkManagementClient": self._client_with_rule_name("allow-rdp-internet")})

        result = asyncio.run(CheckNsgOpenAccess().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["open_inbound_rule_name"] == ["allow-rdp-internet"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "allow-rdp-internet" not in pseudonymized.description
        assert pseudonymized.current_state["open_inbound_rule_name"][0].startswith("pseu_")
        # The dict list is rewritten too — _replace_in_state traverses nested
        # structures for replacement even though collection never does.
        assert pseudonymized.current_state["open_inbound_rules"][0]["name"].startswith("pseu_")


class TestCheckStoragePublicAccess:
    def _client(self, public: bool) -> MagicMock:
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            SimpleNamespace(
                name="st1",
                public_network_access="Enabled" if public else "Disabled",
                network_rule_set=SimpleNamespace(default_action="Allow" if public else "Deny"),
            ),
        ]
        return client

    def test_private_account_produces_positive_evidence(self):
        session = FakeAzureSession({"StorageManagementClient": self._client(public=False)})

        result = asyncio.run(CheckStoragePublicAccess().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_public_account_produces_finding(self):
        session = FakeAzureSession({"StorageManagementClient": self._client(public=True)})

        result = asyncio.run(CheckStoragePublicAccess().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_public_account_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: the description joins the first 5 public account names
        # into a single string; resource_id/account_id here only cover the
        # subscription.
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            SimpleNamespace(
                name="pubfinance01",
                public_network_access="Enabled",
                network_rule_set=SimpleNamespace(default_action="Allow"),
            ),
        ]
        session = FakeAzureSession({"StorageManagementClient": client})

        result = asyncio.run(CheckStoragePublicAccess().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["public_account_name"] == ["pubfinance01"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "pubfinance01" not in pseudonymized.description
        assert pseudonymized.current_state["public_account_name"][0].startswith("pseu_")


class TestCheckClassicAdmins:
    def _client(self, co_admins: int) -> MagicMock:
        client = MagicMock()
        admins = [SimpleNamespace(role="ServiceAdministrator")]
        admins += [SimpleNamespace(role="CoAdministrator") for _ in range(co_admins)]
        client.classic_administrators.list.return_value = admins
        return client

    def test_no_co_admins_produces_positive_evidence(self):
        session = FakeAzureSession({"AuthorizationManagementClient": self._client(0)})

        result = asyncio.run(CheckClassicAdmins().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_co_admins_produce_finding(self):
        session = FakeAzureSession({"AuthorizationManagementClient": self._client(2)})

        result = asyncio.run(CheckClassicAdmins().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckGuestAccessRestrictions:
    RESTRICTED_ROLE = "2af84b1e-32c8-42b7-82bc-daa82404023b"

    def _setup(self, graph_router: SimpleNamespace, role_id: str) -> None:
        graph_router.objects["authorizationPolicy"] = {"guestUserRoleId": role_id}

    def test_restricted_role_produces_positive_evidence(self, graph_router: SimpleNamespace):
        self._setup(graph_router, self.RESTRICTED_ROLE)

        result = asyncio.run(CheckGuestAccessRestrictions().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_permissive_role_produces_finding(self, graph_router: SimpleNamespace):
        self._setup(graph_router, CheckGuestAccessRestrictions.PERMISSIVE_GUEST_ROLE)

        result = asyncio.run(CheckGuestAccessRestrictions().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckStaleServicePrincipals:
    MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    MS_FIRST_PARTY_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"

    def _setup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sps: list[dict],
        activities: list[dict],
    ) -> None:
        from nis2scan.engine.providers.azure import graph

        async def fake_get_all(credential, url, timeout=30.0):
            if "servicePrincipalSignInActivities" in url:
                return activities
            return sps

        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)

    @staticmethod
    def _activity(app_id: str, days_ago: int) -> dict:
        last = (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()
        return {"appId": app_id, "lastSignInActivity": {"lastSignInDateTime": last}}

    def test_active_sps_produce_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(
            monkeypatch,
            sps=[{"appId": "app-1", "appOwnerOrganizationId": None}],
            activities=[self._activity("app-1", days_ago=5)],
        )

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_stale_sp_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(
            monkeypatch,
            sps=[{"appId": "app-1", "appOwnerOrganizationId": None}],
            activities=[self._activity("app-1", days_ago=200)],
        )

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_unknown_sign_in_yields_no_evidence(self, monkeypatch: pytest.MonkeyPatch):
        # ADR-0016: SPs without a report entry are unknown — no positive evidence.
        self._setup(
            monkeypatch,
            sps=[{"appId": "app-1", "appOwnerOrganizationId": None}],
            activities=[],
        )

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert not result.findings

    def test_unknown_sign_in_produces_check_error(self, monkeypatch: pytest.MonkeyPatch):
        # B-9-8: unknown_count > 0 must surface as an InconclusiveState CheckError,
        # not stay silent.
        self._setup(
            monkeypatch,
            sps=[{"appId": "app-1", "appOwnerOrganizationId": None}],
            activities=[],
        )

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert len(result.errors) == 1
        assert result.errors[0].error_type == "InconclusiveState"

    def test_microsoft_first_party_apps_are_excluded(self, monkeypatch: pytest.MonkeyPatch):
        # MS-owned SPs (both Microsoft tenants, legal review B1) without
        # sign-in data must not trigger InconclusiveState.
        self._setup(
            monkeypatch,
            sps=[
                {"appId": "ms-app", "appOwnerOrganizationId": self.MS_TENANT},
                {"appId": "ms-app-2", "appOwnerOrganizationId": self.MS_FIRST_PARTY_TENANT},
                {"appId": "app-1", "appOwnerOrganizationId": None},
            ],
            activities=[self._activity("app-1", days_ago=5)],
        )

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not result.errors

    def test_graph_error_produces_check_error(self, monkeypatch: pytest.MonkeyPatch):
        from nis2scan.engine.providers.azure import graph

        async def failing_get_all(credential, url, timeout=30.0):
            raise RuntimeError("Graph 403: AuditLog.Read.All fehlt")

        monkeypatch.setattr(graph, "graph_get_all", failing_get_all)

        result = asyncio.run(CheckStaleServicePrincipals().execute(FakeAzureSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
