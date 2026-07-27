"""Tests for §30 Nr. 3 — BCM Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr3_bcm import (
    CheckAvailabilityZones,
    CheckBackupVaults,
    CheckGeoRedundantStorage,
    CheckImmutableBlobStorage,
    CheckSiteRecovery,
    CheckSqlBackupRetention,
    CheckTrafficManagerFrontDoor,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


_VAULT_ID = f"/subscriptions/{SUB_ID}/resourceGroups/rg-1/providers/Microsoft.RecoveryServices/vaults/vault-1"


class TestCheckBackupVaults:
    @pytest.fixture
    def backup_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        import azure.mgmt.recoveryservicesbackup as rsb_module

        client = MagicMock()
        monkeypatch.setattr(rsb_module, "RecoveryServicesBackupClient", lambda credential, sub_id: client)
        return client

    def test_vault_with_policy_produces_positive_evidence(self, backup_client: MagicMock):
        rs_client = MagicMock()
        rs_client.vaults.list_by_subscription_id.return_value = [
            SimpleNamespace(name="vault-1", id=_VAULT_ID),
        ]
        backup_client.backup_policies.list.return_value = [SimpleNamespace(name="daily")]
        session = FakeAzureSession({"RecoveryServicesClient": rs_client})

        result = asyncio.run(CheckBackupVaults().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["vaults_without_policies"] == 0
        assert not _maengel(result)

    def test_vault_without_policy_produces_finding(self, backup_client: MagicMock):
        rs_client = MagicMock()
        rs_client.vaults.list_by_subscription_id.return_value = [
            SimpleNamespace(name="vault-1", id=_VAULT_ID),
        ]
        backup_client.backup_policies.list.return_value = []
        session = FakeAzureSession({"RecoveryServicesClient": rs_client})

        result = asyncio.run(CheckBackupVaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_no_vaults_produces_finding(self, backup_client: MagicMock):
        rs_client = MagicMock()
        rs_client.vaults.list_by_subscription_id.return_value = []
        session = FakeAzureSession({"RecoveryServicesClient": rs_client})

        result = asyncio.run(CheckBackupVaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_unverifiable_policies_yield_no_evidence(self, backup_client: MagicMock):
        # ADR-0016: if policy listing fails, the state is unknown — no evidence.
        # B-Nr.3-7: the failure must still surface as a CheckError, not be swallowed.
        rs_client = MagicMock()
        rs_client.vaults.list_by_subscription_id.return_value = [
            SimpleNamespace(name="vault-1", id=_VAULT_ID),
        ]
        backup_client.backup_policies.list.side_effect = RuntimeError("denied")
        session = FakeAzureSession({"RecoveryServicesClient": rs_client})

        result = asyncio.run(CheckBackupVaults().execute(session))

        assert not result.findings
        assert len(result.errors) == 1

    def test_vault_without_policy_name_is_pseudonymized_on_extern_export(self, backup_client: MagicMock):
        # ADR-0011: the description joins vault names into a single string;
        # resource_id/account_id here only cover the subscription. The key
        # was renamed from "vaults_without_policies" (no deny-list suffix) to
        # "vault_without_policy_name" so the names get collected and scrubbed.
        rs_client = MagicMock()
        rs_client.vaults.list_by_subscription_id.return_value = [
            SimpleNamespace(name="vault-prod-backups", id=_VAULT_ID),
        ]
        backup_client.backup_policies.list.return_value = []
        session = FakeAzureSession({"RecoveryServicesClient": rs_client})

        result = asyncio.run(CheckBackupVaults().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["vault_without_policy_name"] == ["vault-prod-backups"]
        assert "vaults_without_policies" not in finding.current_state

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "vault-prod-backups" not in pseudonymized.description
        assert all(v.startswith("pseu_") for v in pseudonymized.current_state["vault_without_policy_name"])


class TestCheckSqlBackupRetention:
    def _sql_client(self, retention_days: int) -> MagicMock:
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-1/providers/Microsoft.Sql/servers/srv-1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv-1", id=server_id, location="westeurope"),
        ]
        client.databases.list_by_server.return_value = [
            SimpleNamespace(name="appdb", id=f"{server_id}/databases/appdb"),
        ]
        client.backup_short_term_retention_policies.list_by_database.return_value = [
            SimpleNamespace(retention_days=retention_days),
        ]
        return client

    def test_sufficient_retention_produces_positive_evidence(self):
        session = FakeAzureSession({"SqlManagementClient": self._sql_client(14)})

        result = asyncio.run(CheckSqlBackupRetention().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["retention_days"] == 14
        assert not _maengel(result)

    def test_short_retention_produces_finding(self):
        session = FakeAzureSession({"SqlManagementClient": self._sql_client(3)})

        result = asyncio.run(CheckSqlBackupRetention().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_sufficient_retention_server_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: the description interpolates server.name directly;
        # resource_id's tail is only the database name (db.id ends in
        # /databases/<name>), never the server name.
        session = FakeAzureSession({"SqlManagementClient": self._sql_client(14)})

        result = asyncio.run(CheckSqlBackupRetention().execute(session))
        finding = _compliant(result)[0]

        assert finding.current_state["server_name"] == "srv-1"

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "srv-1" not in pseudonymized.description
        assert pseudonymized.current_state["server_name"].startswith("pseu_")

    def test_short_retention_server_and_rg_name_are_pseudonymized_on_extern_export(self):
        # rg_name additionally leaks via the remediation az-CLI command.
        session = FakeAzureSession({"SqlManagementClient": self._sql_client(3)})

        result = asyncio.run(CheckSqlBackupRetention().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["server_name"] == "srv-1"
        assert finding.current_state["resource_group_name"] == "rg-1"

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "srv-1" not in pseudonymized.description
        assert "srv-1" not in pseudonymized.remediation
        assert "rg-1" not in pseudonymized.remediation


class TestCheckGeoRedundantStorage:
    def _storage_client(self, sku: str) -> MagicMock:
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            SimpleNamespace(name="stacc1", sku=SimpleNamespace(name=sku)),
        ]
        return client

    def test_grs_produces_positive_evidence(self):
        session = FakeAzureSession({"StorageManagementClient": self._storage_client("Standard_GRS")})

        result = asyncio.run(CheckGeoRedundantStorage().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_lrs_produces_finding(self):
        session = FakeAzureSession({"StorageManagementClient": self._storage_client("Standard_LRS")})

        result = asyncio.run(CheckGeoRedundantStorage().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_non_geo_redundant_account_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: the description joins account names into a single string,
        # and current_state["non_geo_redundant_accounts"] carries them nested
        # in dicts ({"name": ..., "sku": ...}) — _collect_identifiers never
        # looks inside dict values, so a plain-string-list suffix key is
        # needed alongside the existing dict list.
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            SimpleNamespace(name="stacc-finance", sku=SimpleNamespace(name="Standard_LRS")),
        ]
        session = FakeAzureSession({"StorageManagementClient": client})

        result = asyncio.run(CheckGeoRedundantStorage().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["non_geo_redundant_account_name"] == ["stacc-finance"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "stacc-finance" not in pseudonymized.description
        assert "stacc-finance" not in str(pseudonymized.current_state)
        assert pseudonymized.current_state["non_geo_redundant_account_name"][0].startswith("pseu_")
        # The dict list is rewritten too — _replace_in_state traverses nested
        # structures for replacement even though collection never does.
        assert pseudonymized.current_state["non_geo_redundant_accounts"][0]["name"].startswith("pseu_")


class TestCheckAvailabilityZones:
    def test_zoned_vms_produce_positive_evidence(self):
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [
            SimpleNamespace(name="vm-1", zones=["1"]),
        ]
        session = FakeAzureSession({"ComputeManagementClient": client})

        result = asyncio.run(CheckAvailabilityZones().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_unzoned_vm_produces_finding(self):
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [
            SimpleNamespace(name="vm-1", zones=None),
        ]
        session = FakeAzureSession({"ComputeManagementClient": client})

        result = asyncio.run(CheckAvailabilityZones().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSiteRecovery:
    def test_active_vault_produces_positive_evidence(self):
        client = MagicMock()
        client.vaults.list_by_subscription_id.return_value = [
            SimpleNamespace(properties=SimpleNamespace(provisioning_state="Succeeded")),
        ]
        session = FakeAzureSession({"RecoveryServicesClient": client})

        result = asyncio.run(CheckSiteRecovery().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_vaults_produces_finding(self):
        client = MagicMock()
        client.vaults.list_by_subscription_id.return_value = []
        session = FakeAzureSession({"RecoveryServicesClient": client})

        result = asyncio.run(CheckSiteRecovery().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckImmutableBlobStorage:
    def _client(self, immutable: bool) -> MagicMock:
        account_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/st1"
        client = MagicMock()
        client.storage_accounts.list.return_value = [SimpleNamespace(name="st1", id=account_id)]
        client.blob_containers.list.return_value = [
            SimpleNamespace(
                immutability_policy=SimpleNamespace(state="Locked") if immutable else None,
                immutable_storage_with_versioning=None,
            ),
        ]
        return client

    def test_immutable_container_produces_positive_evidence(self):
        session = FakeAzureSession({"StorageManagementClient": self._client(immutable=True)})

        result = asyncio.run(CheckImmutableBlobStorage().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_immutable_container_produces_finding(self):
        session = FakeAzureSession({"StorageManagementClient": self._client(immutable=False)})

        result = asyncio.run(CheckImmutableBlobStorage().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_all_account_queries_failing_yields_errors_no_finding(self):
        # ADR-0016 fail-safe (B-Nr.3-9): if every account's container listing
        # fails, the state is unknown for the whole subscription — errors must
        # be recorded but no Mangel-Finding may be fabricated from zero data.
        account_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/st1"
        client = MagicMock()
        client.storage_accounts.list.return_value = [SimpleNamespace(name="st1", id=account_id)]
        client.blob_containers.list.side_effect = RuntimeError("access denied")
        session = FakeAzureSession({"StorageManagementClient": client})

        result = asyncio.run(CheckImmutableBlobStorage().execute(session))

        assert not result.findings
        assert len(result.errors) == 1


class TestCheckTrafficManagerFrontDoor:
    def test_traffic_manager_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = [
            SimpleNamespace(type="Microsoft.Network/trafficManagerProfiles"),
        ]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckTrafficManagerFrontDoor().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_redundancy_produces_finding(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(type="Microsoft.Compute/virtualMachines")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckTrafficManagerFrontDoor().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
