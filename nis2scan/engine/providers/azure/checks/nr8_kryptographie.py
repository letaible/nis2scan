"""§30 Abs. 2 Nr. 8 — Kryptographie checks for Azure.

Checks Storage Encryption, Disk Encryption, SQL TDE, Key Vault,
App Service HTTPS/TLS, and Application Gateway TLS Policy.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity
from nis2scan.engine.providers.azure.sdk_values import enum_value, enum_value_lower

logger = structlog.get_logger()

BSIG_30_NR = 8
BSIG_30_TEXT = "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"


class CheckStorageEncryption(BaseCheck):
    """Check that Storage Accounts use Customer-Managed Keys (CMK)."""

    check_id = "AZ-NR8-001"
    title = "Storage Account Verschlüsselung (CMK bevorzugt)"
    description = "Prüft ob Azure Storage Accounts kundenverwaltete Schlüssel (CMK) verwenden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Storage/storageAccounts/read"]
    pruefgrenzen = (
        "Storage-Verschlüsselung ist in Azure immer aktiv; bewertet wird nur, ob "
        "kundenverwaltete Schlüssel (CMK) genutzt werden. Fehlendes CMK ist eine "
        "Härtungsempfehlung, kein Verschlüsselungsmangel. Subscriptions ohne Storage "
        "Accounts liefern kein Ergebnis (Nicht anwendbar)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.storage import StorageManagementClient

                storage_client = session.get_client(StorageManagementClient, sub_id)
                accounts = list(storage_client.storage_accounts.list())

                platform_managed = []
                for account in accounts:
                    key_source = None
                    if account.encryption:
                        key_source = account.encryption.key_source
                    if key_source != "Microsoft.Keyvault":
                        platform_managed.append({"name": account.name, "key_source": str(key_source)})

                if accounts and not platform_managed:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Storage Accounts mit CMK-Verschlüsselung",
                            description=(
                                f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} "
                                f"verwenden kundenverwaltete Schlüssel (CMK)."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={"cmk_accounts": len(accounts), "platform_managed_accounts": 0},
                            expected_state="Alle Storage Accounts mit Customer-Managed Keys (CMK)",
                            audit_evidence=(f"storage_accounts.list() returned {len(accounts)} accounts, all CMK"),
                            iso27001_control="A.8.24 Verwendung von Kryptographie",
                        )
                    )
                elif platform_managed:
                    names = ", ".join(a["name"] for a in platform_managed)
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Storage Accounts ohne CMK-Verschlüsselung",
                            description=(
                                f"Subscription {sub_id} hat Storage Accounts mit "
                                f"plattformverwalteten Schlüsseln: {names}. "
                                "CMK bietet mehr Kontrolle über die Verschlüsselungsschlüssel."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.24 Verwendung von Kryptographie",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={
                                "platform_managed_accounts": len(platform_managed),
                                # names above is interpolated into the description;
                                # resource_id/account_id here only cover the
                                # subscription. Suffix key (ADR-0011) so the storage
                                # account names get pseudonymized (live-verified
                                # 2026-07-27 against a real EXTERN report).
                                "cmk_missing_account_name": [a["name"] for a in platform_managed],
                            },
                            expected_state="Alle Storage Accounts mit Customer-Managed Keys (CMK)",
                            remediation=(
                                "Konfigurieren Sie CMK-Verschlüsselung: "
                                "az storage account update --name <acc> --resource-group <rg> "
                                "--encryption-key-source Microsoft.Keyvault "
                                "--encryption-key-vault <vault-uri> --encryption-key-name <key>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"storage_accounts.list() returned {len(accounts)} accounts, "
                                f"{len(platform_managed)} with platform-managed keys"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckDiskEncryption(BaseCheck):
    """Check that managed disks are encrypted."""

    check_id = "AZ-NR8-002"
    title = "Disk Encryption / SSE"
    description = "Prüft ob verwaltete Disks verschlüsselt sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Compute/disks/read"]
    pruefgrenzen = (
        "Prüft nur die Disk-Verschlüsselungsart (SSE/ADE/CMK). Schlüsselverwahrung und "
        "-prozesse werden nicht bewertet. Subscriptions ohne Managed Disks liefern kein "
        "Ergebnis (Nicht anwendbar)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.compute import ComputeManagementClient

                compute_client = session.get_client(ComputeManagementClient, sub_id)
                disks = list(compute_client.disks.list())

                unencrypted_disks = []
                for disk in disks:
                    if not disk.encryption or not disk.encryption.type:
                        unencrypted_disks.append(disk.name)

                if disks and not unencrypted_disks:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Alle Disks verschlüsselt",
                            description=(
                                f"Alle {len(disks)} Managed Disks in Subscription {sub_id} sind verschlüsselt."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/disks",
                            account_id=sub_id,
                            current_state={"encrypted_disks": len(disks), "unencrypted_disks": 0},
                            expected_state="Alle Managed Disks verschlüsselt (SSE oder CMK)",
                            audit_evidence=f"disks.list() returned {len(disks)} disks, all encrypted",
                            iso27001_control="A.8.24 Verwendung von Kryptographie",
                        )
                    )
                elif unencrypted_disks:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Nicht verschlüsselte Disks",
                            description=(
                                f"Subscription {sub_id} hat {len(unencrypted_disks)} "
                                "Disks ohne Verschlüsselung. Alle Datenträger müssen verschlüsselt sein."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.24 Verwendung von Kryptographie",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/disks",
                            account_id=sub_id,
                            current_state={"unencrypted_disks": len(unencrypted_disks)},
                            expected_state="Alle Managed Disks verschlüsselt (SSE oder CMK)",
                            remediation=(
                                "Aktivieren Sie Disk-Verschlüsselung: "
                                "az disk update --name <disk> --resource-group <rg> "
                                "--encryption-type EncryptionAtRestWithPlatformKey"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"disks.list() returned {len(disks)} disks, {len(unencrypted_disks)} without encryption"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSqlTde(BaseCheck):
    """Check that SQL Transparent Data Encryption (TDE) is enabled."""

    check_id = "AZ-NR8-003"
    title = "SQL TDE aktiviert"
    description = "Prüft ob Transparent Data Encryption (TDE) für Azure SQL-Datenbanken aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
    ]
    pruefgrenzen = (
        "Prüft nur das TDE-Flag der SQL-Datenbanken. Verschlüsselung in Transit "
        "und Always Encrypted werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.sql import SqlManagementClient  # type: ignore[import-untyped, unused-ignore]

                sql_client = session.get_client(SqlManagementClient, sub_id)
                servers = list(sql_client.servers.list())

                for server in servers:
                    rg_name = server.id.split("/resourceGroups/")[1].split("/")[0]
                    databases = list(sql_client.databases.list_by_server(rg_name, server.name))

                    for db in databases:
                        if db.name == "master":
                            continue
                        try:
                            tde = sql_client.transparent_data_encryptions.get(rg_name, server.name, db.name, "current")
                            if tde.state and enum_value_lower(tde.state) == "enabled":
                                findings.append(
                                    compliant_finding(
                                        self,
                                        title="SQL TDE aktiviert",
                                        description=(
                                            f"Datenbank {db.name} auf Server {server.name} hat "
                                            f"Transparent Data Encryption aktiviert."
                                        ),
                                        region=server.location or "global",
                                        resource_id=db.id or f"{server.id}/databases/{db.name}",
                                        resource_type="Microsoft.Sql/servers/databases",
                                        account_id=sub_id,
                                        current_state={
                                            "tde_state": str(tde.state),
                                            # server.name is interpolated into the
                                            # description above; resource_id's tail is
                                            # only the database name. Suffix key
                                            # (ADR-0011) so the server name gets
                                            # pseudonymized too.
                                            "server_name": server.name,
                                        },
                                        expected_state="TDE aktiviert für alle Datenbanken",
                                        audit_evidence=f"transparent_data_encryptions.get(): state={tde.state}",
                                        iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    )
                                )
                            elif tde.state and enum_value_lower(tde.state) != "enabled":
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title="SQL TDE nicht aktiviert",
                                        description=(
                                            f"Datenbank {db.name} auf Server {server.name} in "
                                            f"Subscription {sub_id} hat TDE "
                                            "nicht aktiviert."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control="A.8.24 Verwendung von Kryptographie",
                                        severity=Severity.HIGH,
                                        provider=CloudProvider.AZURE,
                                        region=server.location or "global",
                                        resource_id=db.id or f"{server.id}/databases/{db.name}",
                                        resource_type="Microsoft.Sql/servers/databases",
                                        account_id=sub_id,
                                        current_state={
                                            "tde_state": str(tde.state),
                                            # server.name (description) and rg_name
                                            # (remediation az-CLI command) are both
                                            # freestanding tokens, not covered by
                                            # resource_id's tail (database name) or
                                            # account_id (sub_id) — suffix keys per
                                            # ADR-0011 so both get pseudonymized.
                                            "server_name": server.name,
                                            "resource_group_name": rg_name,
                                        },
                                        expected_state="TDE aktiviert für alle Datenbanken",
                                        remediation=(
                                            "Aktivieren Sie TDE: az sql db tde set "
                                            f"--resource-group {rg_name} --server {server.name} "
                                            f"--database {db.name} --status Enabled"
                                        ),
                                        remediation_effort="LOW",
                                        audit_evidence=f"transparent_data_encryptions.get(): state={tde.state}",
                                    )
                                )
                            else:
                                errors.append(
                                    CheckError(
                                        check_id=self.check_id,
                                        error_type="UnverifiableState",
                                        message=(
                                            f"TDE-Status unbekannt für Datenbank {db.name} auf Server {server.name}"
                                        ),
                                        region=server.location or "global",
                                    )
                                )
                        except Exception as exc:
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type=type(exc).__name__,
                                    message=(
                                        f"TDE-Status für Datenbank {db.name} auf Server {server.name} "
                                        f"nicht abrufbar: {exc}"
                                    ),
                                    region=server.location or "global",
                                )
                            )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckKeyVaultRotation(BaseCheck):
    """Check that Key Vaults have soft-delete and purge protection enabled."""

    check_id = "AZ-NR8-004"
    title = "Key Vault Soft-Delete und Purge Protection"
    description = (
        "Prüft ob Key Vaults Soft-Delete und Purge Protection aktiviert haben "
        "als Grundlage für sicheres Schlüssel-Management."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.KeyVault/vaults/read"]
    pruefgrenzen = (
        "Prüft nur Soft-Delete und Purge Protection der Key Vaults als Basisschutz gegen "
        "unwiderruflichen Schlüsselverlust. Rotations-Policies einzelner Schlüssel, Secrets "
        "und Zertifikate im Vault sowie externe Schlüssel werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.keyvault import KeyVaultManagementClient

                kv_client = session.get_client(KeyVaultManagementClient, sub_id)
                vaults = list(kv_client.vaults.list())

                for vault in vaults:
                    issues = []
                    rg_name = vault.id.split("/resourceGroups/")[1].split("/")[0]
                    try:
                        full_vault = kv_client.vaults.get(rg_name, vault.name)
                        props = full_vault.properties

                        if not props.enable_soft_delete:
                            issues.append("Soft-Delete deaktiviert")
                        if not props.enable_purge_protection:
                            issues.append("Purge Protection deaktiviert")

                        if not issues:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Key Vault mit Schutzfunktionen",
                                    description=(
                                        f"Key Vault {vault.name} hat Soft-Delete und Purge Protection aktiviert."
                                    ),
                                    region=vault.location or "global",
                                    resource_id=vault.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.KeyVault/vaults",
                                    account_id=sub_id,
                                    current_state={"soft_delete": True, "purge_protection": True},
                                    expected_state="Soft-Delete und Purge Protection aktiviert",
                                    audit_evidence="vaults.get(): soft-delete and purge protection enabled",
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="Key Vault ohne Schutzfunktionen",
                                    description=(
                                        f"Key Vault {vault.name} in Subscription {sub_id}: "
                                        f"{', '.join(issues)}. Ohne diese Funktionen können Schlüssel "
                                        "unwiderruflich gelöscht werden."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.AZURE,
                                    region=vault.location or "global",
                                    resource_id=vault.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.KeyVault/vaults",
                                    account_id=sub_id,
                                    current_state={
                                        "soft_delete": bool(props.enable_soft_delete),
                                        "purge_protection": bool(props.enable_purge_protection),
                                    },
                                    expected_state="Soft-Delete und Purge Protection aktiviert",
                                    remediation=(
                                        "Aktivieren Sie Soft-Delete und Purge Protection: "
                                        f"az keyvault update --name {vault.name} "
                                        "--enable-soft-delete true --enable-purge-protection true"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=f"vaults.get(): issues={issues}",
                                )
                            )
                    except Exception as exc:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type=type(exc).__name__,
                                message=f"Key-Vault-Status für {vault.name} nicht abrufbar: {exc}",
                                region=vault.location or "global",
                            )
                        )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckAppServiceHttps(BaseCheck):
    """Check that App Services enforce HTTPS and TLS 1.2+."""

    check_id = "AZ-NR8-005"
    title = "App Service HTTPS Only + TLS 1.2+"
    description = "Prüft ob App Services HTTPS-Only erzwingen und mindestens TLS 1.2 verwenden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Web/sites/read",
        "Microsoft.Web/sites/config/read",
    ]
    pruefgrenzen = (
        "Prüft nur App-Service-Konfiguration (HTTPS-Only, TLS-Mindestversion). "
        "Endpunkte außerhalb von App Service sind nicht erfasst."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.web import WebSiteManagementClient

                web_client = session.get_client(WebSiteManagementClient, sub_id)
                apps = list(web_client.web_apps.list())

                for app in apps:
                    issues = []

                    if not app.https_only:
                        issues.append("HTTPS-Only nicht aktiviert")

                    # The Azure list API frequently leaves siteConfig empty — fall back
                    # to get_configuration() before giving up on TLS evaluation
                    # (Batch-5-Muster, siehe CheckAppServiceRuntime in nr5_schwachstellen.py).
                    min_tls_version = app.site_config.min_tls_version if app.site_config else None
                    if not min_tls_version:
                        try:
                            rg_name = app.id.split("/resourceGroups/")[1].split("/")[0]
                            full_config = web_client.web_apps.get_configuration(rg_name, app.name)
                            min_tls_version = full_config.min_tls_version
                        except Exception as config_exc:
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type=type(config_exc).__name__,
                                    message=(
                                        f"Konfiguration für App Service '{app.name}' nicht abrufbar — "
                                        f"TLS-Mindestversion nicht bewertbar: {config_exc}"
                                    ),
                                    region=app.location or "global",
                                )
                            )
                            min_tls_version = None

                    tls_known = False
                    tls_ok = False
                    if min_tls_version:
                        try:
                            version_tuple = tuple(map(int, str(min_tls_version).split(".")))
                            tls_known = True
                            tls_ok = not (version_tuple < (1, 2))
                        except ValueError:
                            tls_known = False

                    if not tls_known:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type="UnverifiableState",
                                message=f"TLS-Mindestversion nicht auslesbar für App {app.name}",
                                region=app.location or "global",
                            )
                        )
                    elif not tls_ok:
                        issues.append(f"TLS-Version {min_tls_version} < 1.2")

                    if tls_known:
                        # TLS status was actually read — a full HTTPS+TLS judgement is possible.
                        if not issues:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="App Service mit HTTPS/TLS-Enforcement",
                                    description=(f"App Service {app.name} erzwingt HTTPS-Only und TLS >= 1.2."),
                                    region=app.location or "global",
                                    resource_id=app.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.Web/sites",
                                    account_id=sub_id,
                                    current_state={
                                        "https_only": bool(app.https_only),
                                        "min_tls_version": str(min_tls_version),
                                    },
                                    expected_state="HTTPS-Only aktiviert und TLS ≥ 1.2",
                                    audit_evidence=(
                                        f"web_apps: {app.name} https_only={bool(app.https_only)}, "
                                        f"min_tls_version={min_tls_version}"
                                    ),
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="App Service ohne HTTPS/TLS-Enforcement",
                                    description=(
                                        f"App Service {app.name} in Subscription {sub_id}: {', '.join(issues)}."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AZURE,
                                    region=app.location or "global",
                                    resource_id=app.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.Web/sites",
                                    account_id=sub_id,
                                    current_state={
                                        "https_only": bool(app.https_only),
                                        "min_tls_version": str(min_tls_version),
                                    },
                                    expected_state="HTTPS-Only aktiviert und TLS ≥ 1.2",
                                    remediation=(
                                        f"az webapp update --name {app.name} "
                                        "--resource-group <rg> --set httpsOnly=true && "
                                        f"az webapp config set --name {app.name} "
                                        "--resource-group <rg> --min-tls-version 1.2"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=f"web_apps: {issues}",
                                )
                            )
                    elif app.https_only:
                        # TLS minimum version could not be determined at all — never
                        # fabricate a TLS >= 1.2 claim. Only the verified HTTPS-Only
                        # fact is attested here (B-Nr.8-9).
                        findings.append(
                            compliant_finding(
                                self,
                                title="App Service mit HTTPS-Only (TLS-Version nicht auslesbar)",
                                description=(
                                    f"App Service {app.name} erzwingt HTTPS-Only. Die TLS-Mindestversion "
                                    "konnte nicht ausgelesen werden und wird daher nicht bestätigt."
                                ),
                                region=app.location or "global",
                                resource_id=app.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Web/sites",
                                account_id=sub_id,
                                current_state={"https_only": True, "min_tls_version": "unknown"},
                                expected_state=(
                                    "HTTPS-Only aktiviert (TLS-Mindestversion konnte nicht verifiziert werden)"
                                ),
                                audit_evidence=(
                                    f"web_apps: {app.name} https_only=true; min_tls_version nicht auslesbar"
                                ),
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="App Service ohne HTTPS-Only (TLS-Version nicht auslesbar)",
                                description=(
                                    f"App Service {app.name} in Subscription {sub_id} erzwingt kein "
                                    "HTTPS-Only. Die TLS-Mindestversion konnte zusätzlich nicht ausgelesen "
                                    "werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region=app.location or "global",
                                resource_id=app.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Web/sites",
                                account_id=sub_id,
                                current_state={"https_only": False, "min_tls_version": "unknown"},
                                expected_state=(
                                    "HTTPS-Only aktiviert (TLS-Mindestversion konnte nicht verifiziert werden)"
                                ),
                                remediation=(
                                    f"az webapp update --name {app.name} --resource-group <rg> --set httpsOnly=true"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"web_apps: {app.name} https_only=false; min_tls_version nicht auslesbar"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckAppGatewayTls(BaseCheck):
    """Check that Application Gateways enforce TLS 1.2+."""

    check_id = "AZ-NR8-006"
    title = "Application Gateway TLS Policy"
    description = "Prüft ob Application Gateways eine TLS-Policy mit mindestens TLS 1.2 verwenden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Network/applicationGateways/read"]
    pruefgrenzen = (
        "Prüft nur die TLS-Policy der Application Gateways. Eigene Cipher-Suites werden nicht inhaltlich zerlegt."
    )

    # Predefined Azure App Gateway SSL policies do not always report
    # min_protocol_version directly — their minimum TLS version is derived
    # from the well-known policy_name instead (B-Nr.8-10).
    PREDEFINED_POLICY_MIN_TLS = {
        "AppGwSslPolicy20150501": "TLSv1_0",
        "AppGwSslPolicy20170401": "TLSv1_1",
        "AppGwSslPolicy20170401S": "TLSv1_2",
        "AppGwSslPolicy20220101": "TLSv1_2",
        "AppGwSslPolicy20220101S": "TLSv1_2",
    }

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.network import NetworkManagementClient

                network_client = session.get_client(NetworkManagementClient, sub_id)
                gateways = list(network_client.application_gateways.list_all())

                for gw in gateways:
                    ssl_policy = gw.ssl_policy
                    if not ssl_policy:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Application Gateway ohne TLS-Policy",
                                description=(
                                    f"Application Gateway {gw.name} in "
                                    f"Subscription {sub_id} hat keine "
                                    "explizite TLS-Policy konfiguriert."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region=gw.location or "global",
                                resource_id=gw.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Network/applicationGateways",
                                account_id=sub_id,
                                current_state={"ssl_policy": None},
                                expected_state="Explizite TLS-Policy mit mindestens TLSv1_2",
                                remediation=(
                                    "Konfigurieren Sie eine TLS-Policy: "
                                    f"az network application-gateway ssl-policy set "
                                    f"--gateway-name {gw.name} --resource-group <rg> "
                                    "--min-protocol-version TLSv1_2"
                                ),
                                remediation_effort="LOW",
                                audit_evidence="No SSL policy configured on application gateway",
                            )
                        )
                        continue

                    min_version = ssl_policy.min_protocol_version
                    if not min_version and enum_value(getattr(ssl_policy, "policy_type", "")) == "Predefined":
                        min_version = self.PREDEFINED_POLICY_MIN_TLS.get(
                            enum_value(getattr(ssl_policy, "policy_name", ""))
                        )

                    if not min_version:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type="UnverifiableState",
                                message=f"TLS-Mindestversion nicht auslesbar für Application Gateway {gw.name}",
                                region=gw.location or "global",
                            )
                        )
                        continue

                    min_version = str(min_version)
                    if "TLSv1_0" not in min_version and "TLSv1_1" not in min_version:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Application Gateway mit sicherer TLS-Policy",
                                description=(
                                    f"Application Gateway {gw.name} erzwingt mindestens TLS-Version {min_version}."
                                ),
                                region=gw.location or "global",
                                resource_id=gw.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Network/applicationGateways",
                                account_id=sub_id,
                                current_state={"min_protocol_version": min_version},
                                expected_state="TLS-Policy mit mindestens TLSv1_2",
                                audit_evidence=f"ssl_policy.min_protocol_version={min_version}",
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Application Gateway mit veralteter TLS-Version",
                                description=(
                                    f"Application Gateway {gw.name} in "
                                    f"Subscription {sub_id} erlaubt "
                                    f"TLS-Version {min_version}. TLS 1.0/1.1 gilt als unsicher "
                                    "(vgl. BSI TR-02102-2)."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region=gw.location or "global",
                                resource_id=gw.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Network/applicationGateways",
                                account_id=sub_id,
                                current_state={"min_protocol_version": min_version},
                                expected_state="TLS-Policy mit mindestens TLSv1_2",
                                remediation=(
                                    "Aktualisieren Sie die TLS-Policy: "
                                    f"az network application-gateway ssl-policy set "
                                    f"--gateway-name {gw.name} --resource-group <rg> "
                                    "--min-protocol-version TLSv1_2 --policy-type Predefined "
                                    "--name AppGwSslPolicy20220101"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"ssl_policy.min_protocol_version={min_version}",
                            )
                        )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
