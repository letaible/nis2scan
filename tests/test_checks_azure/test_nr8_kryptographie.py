"""Tests for §30 Nr. 8 — Kryptographie Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from enum import Enum
from types import SimpleNamespace
from unittest.mock import MagicMock

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr8_kryptographie import (
    CheckAppGatewayTls,
    CheckAppServiceHttps,
    CheckDiskEncryption,
    CheckKeyVaultRotation,
    CheckSqlTde,
    CheckStorageEncryption,
)

from .conftest import SUB_ID, FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckStorageEncryption:
    def _client(self, key_source: str) -> MagicMock:
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            SimpleNamespace(name="st1", encryption=SimpleNamespace(key_source=key_source)),
        ]
        return client

    def test_cmk_produces_positive_evidence(self):
        session = FakeAzureSession({"StorageManagementClient": self._client("Microsoft.Keyvault")})

        result = asyncio.run(CheckStorageEncryption().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_platform_keys_produce_finding(self):
        session = FakeAzureSession({"StorageManagementClient": self._client("Microsoft.Storage")})

        result = asyncio.run(CheckStorageEncryption().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_cmk_missing_account_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: the description lists platform-managed-key account names
        # (live-verified 27.07.2026 against a real EXTERN report); resource_id/
        # account_id here only cover the subscription.
        session = FakeAzureSession({"StorageManagementClient": self._client("Microsoft.Storage")})

        result = asyncio.run(CheckStorageEncryption().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["cmk_missing_account_name"] == ["st1"]

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "st1" not in pseudonymized.description
        assert pseudonymized.current_state["cmk_missing_account_name"][0].startswith("pseu_")


class TestCheckDiskEncryption:
    def _client(self, encrypted: bool) -> MagicMock:
        client = MagicMock()
        client.disks.list.return_value = [
            SimpleNamespace(
                name="disk1",
                encryption=SimpleNamespace(type="EncryptionAtRestWithPlatformKey") if encrypted else None,
            ),
        ]
        return client

    def test_encrypted_disks_produce_positive_evidence(self):
        session = FakeAzureSession({"ComputeManagementClient": self._client(encrypted=True)})

        result = asyncio.run(CheckDiskEncryption().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_unencrypted_disk_produces_finding(self):
        session = FakeAzureSession({"ComputeManagementClient": self._client(encrypted=False)})

        result = asyncio.run(CheckDiskEncryption().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSqlTde:
    def _client(self, tde_state: str) -> MagicMock:
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv1", id=server_id, location="westeurope"),
        ]
        client.databases.list_by_server.return_value = [
            SimpleNamespace(name="appdb", id=f"{server_id}/databases/appdb"),
        ]
        client.transparent_data_encryptions.get.return_value = SimpleNamespace(state=tde_state)
        return client

    def test_enum_valued_tde_state_is_read_correctly(self):
        """Auflage 1 (Rechts-Review 30.07.2026): the real SDK may return
        tde.state as a (str, Enum) member whose str() is "TdeState.ENABLED".
        Without enum_value_lower the enabled state would read as a defect and
        the disabled state would never be flagged. StrEnum is deliberately NOT
        used — it would return the plain value and not reproduce the trap."""

        class _TdeState(str, Enum):  # noqa: UP042
            ENABLED = "Enabled"
            DISABLED = "Disabled"

        session = FakeAzureSession({"SqlManagementClient": self._client(_TdeState.ENABLED)})
        result = asyncio.run(CheckSqlTde().execute(session))
        assert len(_compliant(result)) == 1, f"enum-valued enabled TDE misread: {result.findings}"
        assert not _maengel(result)
        # The report must show the canonical value, never "TdeState.ENABLED".
        assert _compliant(result)[0].current_state["tde_state"] == "Enabled"

        session = FakeAzureSession({"SqlManagementClient": self._client(_TdeState.DISABLED)})
        result = asyncio.run(CheckSqlTde().execute(session))
        assert len(_maengel(result)) == 1, f"enum-valued disabled TDE not flagged: {result.findings}"
        assert not _compliant(result)

    def test_tde_enabled_produces_positive_evidence(self):
        session = FakeAzureSession({"SqlManagementClient": self._client("Enabled")})

        result = asyncio.run(CheckSqlTde().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_tde_disabled_produces_finding(self):
        session = FakeAzureSession({"SqlManagementClient": self._client("Disabled")})

        result = asyncio.run(CheckSqlTde().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def _client_with_rg(self, tde_state: str, rg_name: str) -> MagicMock:
        server_id = f"/subscriptions/{SUB_ID}/resourceGroups/{rg_name}/providers/Microsoft.Sql/servers/srv1"
        client = MagicMock()
        client.servers.list.return_value = [
            SimpleNamespace(name="srv1", id=server_id, location="westeurope"),
        ]
        client.databases.list_by_server.return_value = [
            SimpleNamespace(name="appdb", id=f"{server_id}/databases/appdb"),
        ]
        client.transparent_data_encryptions.get.return_value = SimpleNamespace(state=tde_state)
        return client

    def test_tde_enabled_server_name_is_pseudonymized_on_extern_export(self):
        # ADR-0011: the description interpolates server.name directly;
        # resource_id's tail is only the database name.
        session = FakeAzureSession({"SqlManagementClient": self._client_with_rg("Enabled", "rg-crypto")})

        result = asyncio.run(CheckSqlTde().execute(session))
        finding = _compliant(result)[0]

        assert finding.current_state["server_name"] == "srv1"

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "srv1" not in pseudonymized.description
        assert pseudonymized.current_state["server_name"].startswith("pseu_")

    def test_tde_disabled_server_and_rg_name_are_pseudonymized_on_extern_export(self):
        # rg_name additionally leaks via the remediation az-CLI command. Uses
        # a >=3-char rg name — _collect_identifiers drops shorter values.
        session = FakeAzureSession({"SqlManagementClient": self._client_with_rg("Disabled", "rg-crypto")})

        result = asyncio.run(CheckSqlTde().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["server_name"] == "srv1"
        assert finding.current_state["resource_group_name"] == "rg-crypto"

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]
        assert "srv1" not in pseudonymized.description
        assert "srv1" not in pseudonymized.remediation
        assert "rg-crypto" not in pseudonymized.remediation


class TestCheckKeyVaultRotation:
    def _client(self, protected: bool) -> MagicMock:
        vault_id = f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
        client = MagicMock()
        client.vaults.list.return_value = [
            SimpleNamespace(name="kv1", id=vault_id, location="westeurope"),
        ]
        client.vaults.get.return_value = SimpleNamespace(
            properties=SimpleNamespace(
                enable_soft_delete=protected,
                enable_purge_protection=protected,
            )
        )
        return client

    def test_protected_vault_produces_positive_evidence(self):
        session = FakeAzureSession({"KeyVaultManagementClient": self._client(protected=True)})

        result = asyncio.run(CheckKeyVaultRotation().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_unprotected_vault_produces_finding(self):
        session = FakeAzureSession({"KeyVaultManagementClient": self._client(protected=False)})

        result = asyncio.run(CheckKeyVaultRotation().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckAppServiceHttps:
    def _client(self, https_only: bool, min_tls: str) -> MagicMock:
        client = MagicMock()
        client.web_apps.list.return_value = [
            SimpleNamespace(
                name="app1",
                https_only=https_only,
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
                site_config=SimpleNamespace(min_tls_version=min_tls),
            ),
        ]
        return client

    def test_enforced_https_produces_positive_evidence(self):
        session = FakeAzureSession({"WebSiteManagementClient": self._client(True, "1.2")})

        result = asyncio.run(CheckAppServiceHttps().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_missing_https_produces_finding(self):
        session = FakeAzureSession({"WebSiteManagementClient": self._client(False, "1.0")})

        result = asyncio.run(CheckAppServiceHttps().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def _client_with_empty_site_config(
        self,
        https_only: bool,
        get_configuration_result: str | None = None,
        get_configuration_error: Exception | None = None,
    ) -> MagicMock:
        # Simulates web_apps.list() not populating site_config (B-Nr.8-9) —
        # the check must fall back to get_configuration().
        client = MagicMock()
        client.web_apps.list.return_value = [
            SimpleNamespace(
                name="app1",
                https_only=https_only,
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
                site_config=None,
            ),
        ]
        if get_configuration_error is not None:
            client.web_apps.get_configuration.side_effect = get_configuration_error
        else:
            client.web_apps.get_configuration.return_value = SimpleNamespace(min_tls_version=get_configuration_result)
        return client

    def test_site_config_empty_get_configuration_tls10_produces_finding(self):
        session = FakeAzureSession(
            {"WebSiteManagementClient": self._client_with_empty_site_config(True, get_configuration_result="1.0")}
        )

        result = asyncio.run(CheckAppServiceHttps().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
        assert "1.0" in _maengel(result)[0].description

    def test_site_config_empty_get_configuration_tls12_produces_positive_evidence(self):
        session = FakeAzureSession(
            {"WebSiteManagementClient": self._client_with_empty_site_config(True, get_configuration_result="1.2")}
        )

        result = asyncio.run(CheckAppServiceHttps().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_tls_unreadable_with_https_only_produces_https_only_evidence_and_checkerror(self):
        session = FakeAzureSession(
            {
                "WebSiteManagementClient": self._client_with_empty_site_config(
                    True, get_configuration_error=Exception("boom")
                )
            }
        )

        result = asyncio.run(CheckAppServiceHttps().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        # Only the verified HTTPS-Only fact is attested — no TLS>=1.2 claim.
        assert compliant[0].audit_evidence == "web_apps: app1 https_only=true; min_tls_version nicht auslesbar"
        assert "TLS" not in compliant[0].expected_state or "nicht verifiziert" in compliant[0].expected_state
        assert any(e.error_type == "UnverifiableState" for e in result.errors)


class TestCheckAppGatewayTls:
    def _client(self, min_version: str | None) -> MagicMock:
        client = MagicMock()
        client.application_gateways.list_all.return_value = [
            SimpleNamespace(
                name="agw1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw1",
                ssl_policy=SimpleNamespace(min_protocol_version=min_version) if min_version else None,
            ),
        ]
        return client

    def test_enum_valued_min_protocol_version_tls10_is_flagged(self):
        """Auflage 3 (Rechts-Review 30.07.2026): the DIRECT min_protocol_version
        path is the silent-failure variant. Under enum drift str() yields the
        member NAME ("ApplicationGatewaySslProtocol.TLS_V1_0", underscores), so
        the "TLSv1_0" substring test misses and a gateway still on TLS 1.0
        would be declared compliant — a false negative in the dangerous
        direction, unlike the predefined path which fails loudly."""

        class _SslProtocol(str, Enum):  # noqa: UP042
            TLS_V1_0 = "TLSv1_0"

        session = FakeAzureSession({"NetworkManagementClient": self._client(_SslProtocol.TLS_V1_0)})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        assert len(_maengel(result)) == 1, f"enum-valued TLS 1.0 gateway not flagged: {result.findings}"
        assert not _compliant(result)
        # The report must carry the canonical value, not the member name.
        assert _maengel(result)[0].current_state["min_protocol_version"] == "TLSv1_0"

    def _client_predefined(self, policy_name: str) -> MagicMock:
        client = MagicMock()
        client.application_gateways.list_all.return_value = [
            SimpleNamespace(
                name="agw1",
                location="westeurope",
                id=f"/subscriptions/{SUB_ID}/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw1",
                ssl_policy=SimpleNamespace(
                    min_protocol_version=None,
                    policy_type="Predefined",
                    policy_name=policy_name,
                ),
            ),
        ]
        return client

    def test_enum_valued_predefined_policy_is_resolved(self):
        """Auflage 2 (Rechts-Review 30.07.2026): policy_type/policy_name may
        arrive as (str, Enum) members. With a raw str() the type check would
        fail and the predefined-policy TLS lookup would miss, turning a
        resolvable policy into an unverifiable one."""

        class _PolicyType(str, Enum):  # noqa: UP042
            PREDEFINED = "Predefined"

        class _PolicyName(str, Enum):  # noqa: UP042
            OLD = "AppGwSslPolicy20150501"

        client = self._client_predefined(_PolicyName.OLD)
        client.application_gateways.list_all.return_value[0].ssl_policy.policy_type = _PolicyType.PREDEFINED
        session = FakeAzureSession({"NetworkManagementClient": client})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        # AppGwSslPolicy20150501 maps to TLSv1_0 -> must be flagged, and the
        # policy must NOT end up as an unresolvable/unverifiable state.
        assert len(_maengel(result)) == 1, (
            f"enum-valued predefined policy not resolved: {result.findings}, {result.errors}"
        )
        assert not any("UnverifiableState" in (e.error_type or "") for e in result.errors)

    def test_tls12_produces_positive_evidence(self):
        session = FakeAzureSession({"NetworkManagementClient": self._client("TLSv1_2")})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_tls10_produces_finding(self):
        session = FakeAzureSession({"NetworkManagementClient": self._client("TLSv1_0")})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_no_policy_produces_finding(self):
        session = FakeAzureSession({"NetworkManagementClient": self._client(None)})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_predefined_policy_20150501_produces_finding(self):
        # B-Nr.8-10: min_protocol_version is unset but policy_type=Predefined
        # with policy_name=AppGwSslPolicy20150501 maps to TLSv1_0 -> Mangel.
        session = FakeAzureSession({"NetworkManagementClient": self._client_predefined("AppGwSslPolicy20150501")})

        result = asyncio.run(CheckAppGatewayTls().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
        assert "TLSv1_0" in _maengel(result)[0].current_state["min_protocol_version"]
