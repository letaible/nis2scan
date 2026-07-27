"""Tests for §30 Nr. 10 — MFA & Kommunikation Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import (
    GLOBAL_ADMIN_ROLE_ID,
    CheckBreakGlassAccounts,
    CheckMfaAllUsers,
    CheckO365TlsEnforcement,
    CheckPhishingResistantMfa,
    CheckVpnBastion,
)

from .conftest import FakeAzureSession


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
    pattern as TestCheckStaleServicePrincipals's own `_setup` in
    test_nr9_zugriffskontrolle.py.
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


def _mfa_policy(include_users: list[str], controls: list[str], exclude_users: list[str] | None = None) -> dict:
    return {
        "state": "enabled",
        "grantControls": {"builtInControls": controls},
        "conditions": {
            "users": {"includeUsers": include_users, "excludeUsers": exclude_users or []},
            "applications": {"includeApplications": ["All"]},
        },
    }


class TestCheckMfaAllUsers:
    def test_mfa_for_all_produces_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"])]
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_mfa_policy_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = []
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)

    def test_mfa_for_all_with_exceptions_produces_positive_evidence_with_caveat(self, graph_router: SimpleNamespace):
        """B-Nr.10-6: exclude_users must not silently flip to full compliance."""
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"], exclude_users=["bg-1", "bg-2"])]
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert "2 ausgenommenen Objekten" in compliant[0].description
        assert "organisatorisch zu begründen" in compliant[0].description
        assert compliant[0].expected_state == "Conditional Access Policy mit MFA für alle Benutzer"


class TestCheckPhishingResistantMfa:
    def _setup(self, graph_router: SimpleNamespace, fido2_state: str) -> None:
        graph_router.objects["authenticationMethodsPolicy"] = {
            "authenticationMethodConfigurations": [{"id": "Fido2", "state": fido2_state}]
        }

    def test_fido2_enabled_produces_positive_evidence(self, graph_router: SimpleNamespace):
        self._setup(graph_router, "enabled")

        result = asyncio.run(CheckPhishingResistantMfa().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_fido2_disabled_produces_finding(self, graph_router: SimpleNamespace):
        self._setup(graph_router, "disabled")

        result = asyncio.run(CheckPhishingResistantMfa().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckVpnBastion:
    def _session(
        self,
        has_bastion: bool,
        resource_groups: list[str] | None = None,
        gateways_by_rg: dict[str, list] | None = None,
    ) -> FakeAzureSession:
        # virtual_network_gateways has no subscription-wide list_all() — gateways are
        # only listable per resource group, hence resource_groups.list() + a per-RG
        # list(rg_name) fake below (mirrors the real CheckVpnBastion.execute()).
        gateways_by_rg = gateways_by_rg or {}
        network_client = MagicMock()
        network_client.virtual_network_gateways.list.side_effect = lambda rg_name: gateways_by_rg.get(rg_name, [])
        resource_client = MagicMock()
        resource_client.resource_groups.list.return_value = [SimpleNamespace(name=rg) for rg in (resource_groups or [])]
        resource_client.resources.list.return_value = [SimpleNamespace(name="bastion-1")] if has_bastion else []
        return FakeAzureSession(
            {"NetworkManagementClient": network_client, "ResourceManagementClient": resource_client}
        )

    def test_bastion_produces_positive_evidence(self):
        result = asyncio.run(CheckVpnBastion().execute(self._session(has_bastion=True)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_nothing_produces_finding(self):
        result = asyncio.run(CheckVpnBastion().execute(self._session(has_bastion=False)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_vpn_gateway_in_resource_group_produces_positive_evidence(self):
        # B-fix (SDK-Pin-Verifikation 27.07.2026): list_all() never existed — gateways
        # must be discovered per resource group.
        session = self._session(
            has_bastion=False,
            resource_groups=["rg1", "rg2"],
            gateways_by_rg={"rg1": [SimpleNamespace(name="gw1")]},
        )

        result = asyncio.run(CheckVpnBastion().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["vpn_gateways"] == 1
        assert not _maengel(result)

    def test_resource_group_query_failure_produces_check_error_but_keeps_other_gateways(self):
        # Code-Health-Guideline: one failing resource group must never silently skip
        # the rest — it becomes a CheckError, while gateways from other resource
        # groups still count.
        def list_side_effect(rg_name):
            if rg_name == "rg-broken":
                raise RuntimeError("transient failure")
            return [SimpleNamespace(name="gw1")] if rg_name == "rg-ok" else []

        network_client = MagicMock()
        network_client.virtual_network_gateways.list.side_effect = list_side_effect
        resource_client = MagicMock()
        resource_client.resource_groups.list.return_value = [
            SimpleNamespace(name="rg-broken"),
            SimpleNamespace(name="rg-ok"),
        ]
        resource_client.resources.list.return_value = []
        session = FakeAzureSession(
            {"NetworkManagementClient": network_client, "ResourceManagementClient": resource_client}
        )

        result = asyncio.run(CheckVpnBastion().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "VpnGatewayQueryFailed"

    def test_partial_rg_failure_without_gateways_emits_no_negative_finding(self):
        # Fail-safe (ADR-0016, legal review 27.07.2026): if some resource-group
        # queries failed and no gateway was found in the REST, the check must
        # NOT claim "weder VPN Gateway noch Bastion Host" for the whole
        # subscription — the failed groups are unknown territory. Only the
        # CheckError is emitted (same pattern as AZ-NR6-004).
        def list_side_effect(rg_name):
            if rg_name == "rg-broken":
                raise RuntimeError("transient failure")
            return []

        network_client = MagicMock()
        network_client.virtual_network_gateways.list.side_effect = list_side_effect
        resource_client = MagicMock()
        resource_client.resource_groups.list.return_value = [
            SimpleNamespace(name="rg-broken"),
            SimpleNamespace(name="rg-empty"),
        ]
        resource_client.resources.list.return_value = []
        session = FakeAzureSession(
            {"NetworkManagementClient": network_client, "ResourceManagementClient": resource_client}
        )

        result = asyncio.run(CheckVpnBastion().execute(session))

        assert not _maengel(result)
        assert not _compliant(result)
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "VpnGatewayQueryFailed"

    def test_real_sdk_virtual_network_gateways_operations_has_no_list_all(self):
        # Regression guard for mock drift (SDK-Pin-Verifikation 27.07.2026): the real
        # azure-mgmt-network VirtualNetworkGatewaysOperations has never had a
        # subscription-wide list_all() — only list(resource_group_name).
        import inspect

        from azure.mgmt.network.operations import VirtualNetworkGatewaysOperations

        assert not hasattr(VirtualNetworkGatewaysOperations, "list_all")
        sig = inspect.signature(VirtualNetworkGatewaysOperations.list)
        assert "resource_group_name" in sig.parameters


class TestCheckO365TlsEnforcement:
    def test_o365_policy_produces_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"])]
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_o365_policy_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = []
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckBreakGlassAccounts:
    def _setup(self, graph_router: SimpleNamespace, break_glass_count: int, total_admins: int | None = None) -> None:
        """Wire up `break_glass_count` permanent Global Admins excluded from CA policies.

        `total_admins` (default: max(break_glass_count, 1)) lets a test model extra
        Global Admins that are NOT CA-excluded, i.e. not break-glass accounts.
        """
        total = total_admins if total_admins is not None else max(break_glass_count, 1)
        principal_ids = [f"bg-user-{i}" for i in range(total)]
        graph_router.collections["roleAssignments"] = [
            {"roleDefinitionId": GLOBAL_ADMIN_ROLE_ID, "principalId": pid} for pid in principal_ids
        ]
        excluded = principal_ids[:break_glass_count]
        graph_router.collections["conditionalAccess"] = [{"conditions": {"users": {"excludeUsers": excluded}}}]

    def test_two_break_glass_accounts_produce_positive_evidence(self, graph_router: SimpleNamespace):
        """B-Nr.10-9: Option A counts CA-excluded permanent Global Admins; >=2 is compliant."""
        self._setup(graph_router, break_glass_count=2)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert compliant[0].expected_state == (
            "Mindestens zwei Break-Glass-Konten (permanente Global-Admin-Rolle mit CA-Ausschluss)"
        )

    def test_one_break_glass_account_produces_medium_finding(self, graph_router: SimpleNamespace):
        """B-Nr.10-9: exactly one CA-excluded permanent Global Admin is a MEDIUM defect."""
        self._setup(graph_router, break_glass_count=1)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not _compliant(result)

    def test_no_break_glass_produces_finding(self, graph_router: SimpleNamespace):
        self._setup(graph_router, break_glass_count=0)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not _compliant(result)
