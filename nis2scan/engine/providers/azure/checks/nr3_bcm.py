"""§30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs (BCM) checks for Azure.

Checks Backup Vaults, SQL Backup Retention, Geo-Redundant Storage, Availability Zones,
Site Recovery, Immutable Blob Storage, and Traffic Manager / Front Door.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 3
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 3 BSIG — Aufrechterhaltung des Betriebs, wie Backup-Management "
    "und Wiederherstellung nach einem Notfall, und Krisenmanagement"
)


class CheckBackupVaults(BaseCheck):
    """Check that Azure Backup Vaults with backup policies exist."""

    check_id = "AZ-NR3-001"
    title = "Azure Backup Vaults mit Policies"
    description = "Prüft ob Azure Recovery Services Vaults mit Backup-Policies konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.RecoveryServices/vaults/read",
        "Microsoft.RecoveryServices/vaults/backupPolicies/read",
    ]
    pruefgrenzen = (
        "Prüft nur Recovery-Services-Vaults und deren Policies. Backup-Erfolg, "
        "Abdeckung aller kritischen Ressourcen und Restore-Tests werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.recoveryservices import RecoveryServicesClient

                rs_client = session.get_client(RecoveryServicesClient, sub_id)
                vaults = list(rs_client.vaults.list_by_subscription_id())

                if not vaults:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Backup Vaults konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat keine Recovery Services Vaults. "
                                "Ohne Backup-Infrastruktur ist keine Wiederherstellung nach einem Notfall möglich."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.13 Informationssicherung",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.RecoveryServices/vaults",
                            account_id=sub_id,
                            current_state={"recovery_services_vaults": 0},
                            expected_state="Mindestens ein Recovery Services Vault mit Backup-Policies",
                            remediation=(
                                "Erstellen Sie einen Recovery Services Vault: "
                                "az backup vault create --resource-group <rg> --name <vault-name> --location <loc>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="vaults.list_by_subscription_id() returned 0 vaults",
                        )
                    )
                else:
                    # Check if vaults have backup policies
                    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

                    vaults_without_policies = []
                    vaults_checked = 0
                    for vault in vaults:
                        try:
                            backup_client = RecoveryServicesBackupClient(session.credential, sub_id)
                            rg_name = vault.id.split("/resourceGroups/")[1].split("/")[0]
                            policies = list(
                                backup_client.backup_policies.list(vault_name=vault.name, resource_group_name=rg_name)
                            )
                            vaults_checked += 1
                            if not policies:
                                vaults_without_policies.append(vault.name)
                        except Exception as exc:
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type=type(exc).__name__,
                                    message=str(exc),
                                    region="global",
                                )
                            )

                    if vaults_checked and not vaults_without_policies:
                        # Positive evidence only for vaults we could verify (ADR-0016)
                        findings.append(
                            compliant_finding(
                                self,
                                title="Backup Vaults mit Policies",
                                description=(
                                    f"Subscription {sub_id} hat {len(vaults)} Recovery Services "
                                    f"Vault(s); alle geprüften Vaults haben Backup-Policies."
                                ),
                                region="global",
                                resource_id=f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.RecoveryServices/vaults",
                                account_id=sub_id,
                                current_state={
                                    "recovery_services_vaults": len(vaults),
                                    "vaults_checked": vaults_checked,
                                    "vaults_without_policies": 0,
                                },
                                expected_state="Mindestens ein Recovery Services Vault mit Backup-Policies",
                                audit_evidence=(
                                    f"Found {len(vaults)} vault(s), {vaults_checked} checked, all with policies"
                                ),
                                iso27001_control="A.8.13 Informationssicherung",
                            )
                        )
                    elif vaults_without_policies:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Backup Vaults ohne Policies",
                                description=(
                                    f"Subscription {sub_id} hat Vaults ohne Backup-Policies: "
                                    f"{', '.join(vaults_without_policies)}. "
                                    "Ohne Policies werden keine Backups erstellt."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.13 Informationssicherung",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region="global",
                                resource_id=f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.RecoveryServices/vaults",
                                account_id=sub_id,
                                current_state={
                                    # Key renamed to a Deny-List suffix (ADR-0011):
                                    # the list carries customer-chosen vault names,
                                    # interpolated into the description above.
                                    # Deliberately SINGULAR ("_name", not "_names") —
                                    # the deny-list regex requires the key to END in
                                    # _name, so a later "grammar fix" to the plural
                                    # would silently reopen the leak (see the
                                    # GCP-NR4-001 external_member_email precedent).
                                    "vault_without_policy_name": vaults_without_policies,
                                },
                                expected_state="Alle Backup Vaults mit mindestens einer Backup-Policy",
                                remediation=(
                                    "Erstellen Sie Backup-Policies für Ihre Vaults: "
                                    "az backup policy create --vault-name <vault> --resource-group <rg> "
                                    "--name <policy-name> --policy <policy-json>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(
                                    f"Found {len(vaults)} vaults, {len(vaults_without_policies)} without policies"
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


class CheckSqlBackupRetention(BaseCheck):
    """Check that SQL Database backup retention is at least 7 days."""

    check_id = "AZ-NR3-002"
    title = "SQL DB Backup Retention ≥7 Tage"
    description = "Prüft ob Azure SQL Datenbanken eine Backup-Aufbewahrung von mindestens 7 Tagen haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read",
    ]
    pruefgrenzen = (
        "Prüft nur die konfigurierte Retention der SQL-Datenbank-Backups. Wiederherstellbarkeit wird nicht getestet."
    )

    MIN_RETENTION_DAYS = 7

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
                            policies = list(
                                sql_client.backup_short_term_retention_policies.list_by_database(
                                    rg_name, server.name, db.name
                                )
                            )
                            for policy in policies:
                                if policy.retention_days is None:
                                    errors.append(
                                        CheckError(
                                            check_id=self.check_id,
                                            error_type="RetentionUnknown",
                                            message=f"Retention für Datenbank {db.name} nicht ermittelbar",
                                            region=server.location or "global",
                                        )
                                    )
                                elif policy.retention_days >= self.MIN_RETENTION_DAYS:
                                    findings.append(
                                        compliant_finding(
                                            self,
                                            title="SQL Backup Retention ausreichend",
                                            description=(
                                                f"Datenbank {db.name} auf Server {server.name} hat "
                                                f"{policy.retention_days} Tage Backup-Aufbewahrung "
                                                f"(Minimum: {self.MIN_RETENTION_DAYS})."
                                            ),
                                            region=server.location or "global",
                                            resource_id=db.id or f"{server.id}/databases/{db.name}",
                                            resource_type="Microsoft.Sql/servers/databases",
                                            account_id=sub_id,
                                            current_state={
                                                "retention_days": policy.retention_days,
                                                # server.name is interpolated into the
                                                # description above; resource_id's tail
                                                # is only the database name, so the
                                                # server name needs its own suffix key
                                                # (ADR-0011).
                                                "server_name": server.name,
                                            },
                                            expected_state=f"Backup-Retention ≥ {self.MIN_RETENTION_DAYS} Tage",
                                            audit_evidence=(
                                                f"backup_short_term_retention_policies: "
                                                f"retention_days={policy.retention_days}"
                                            ),
                                            iso27001_control="A.8.13 Informationssicherung",
                                        )
                                    )
                                else:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title="SQL Backup Retention zu kurz",
                                            description=(
                                                f"Datenbank {db.name} auf Server {server.name} in "
                                                f"Subscription {sub_id} hat nur "
                                                f"{policy.retention_days} Tage Backup-Aufbewahrung."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control="A.8.13 Informationssicherung",
                                            severity=Severity.HIGH,
                                            provider=CloudProvider.AZURE,
                                            region=server.location or "global",
                                            resource_id=db.id or f"{server.id}/databases/{db.name}",
                                            resource_type="Microsoft.Sql/servers/databases",
                                            account_id=sub_id,
                                            current_state={
                                                "retention_days": policy.retention_days,
                                                # server.name (description) and rg_name
                                                # (remediation az-CLI command) are both
                                                # freestanding tokens, not covered by
                                                # resource_id's tail (database name) or
                                                # account_id (sub_id) — suffix keys per
                                                # ADR-0011 so both get pseudonymized.
                                                "server_name": server.name,
                                                "resource_group_name": rg_name,
                                            },
                                            expected_state=f"Backup-Retention ≥ {self.MIN_RETENTION_DAYS} Tage",
                                            remediation=(
                                                "Erhöhen Sie die Backup-Aufbewahrung: "
                                                f"az sql db str-policy set --resource-group {rg_name} "
                                                f"--server {server.name} --name {db.name} "
                                                f"--retention-days {self.MIN_RETENTION_DAYS}"
                                            ),
                                            remediation_effort="LOW",
                                            audit_evidence=(
                                                f"backup_short_term_retention_policies: "
                                                f"retention_days={policy.retention_days}"
                                            ),
                                        )
                                    )
                        except Exception as exc:
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type=type(exc).__name__,
                                    message=str(exc),
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


class CheckGeoRedundantStorage(BaseCheck):
    """Check that Storage Accounts use geo-redundant replication."""

    check_id = "AZ-NR3-003"
    title = "Geo-redundanter Speicher (GRS)"
    description = "Prüft ob Azure Storage Accounts geo-redundante Replikation verwenden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Storage/storageAccounts/read"]
    pruefgrenzen = (
        "Prüft nur die Redundanz-SKU der Storage Accounts. Ob GRS für die jeweilige "
        "Datenklasse erforderlich ist, ist eine organisatorische Entscheidung."
    )

    GEO_REDUNDANT_SKUS = {"Standard_GRS", "Standard_RAGRS", "Standard_GZRS", "Standard_RAGZRS"}

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.storage import StorageManagementClient

                storage_client = session.get_client(StorageManagementClient, sub_id)
                accounts = list(storage_client.storage_accounts.list())

                non_geo_accounts = []
                for account in accounts:
                    sku_name = account.sku.name if account.sku else "Unknown"
                    if sku_name not in self.GEO_REDUNDANT_SKUS:
                        non_geo_accounts.append({"name": account.name, "sku": sku_name})

                if accounts and not non_geo_accounts:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Storage Accounts geo-redundant",
                            description=(
                                f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} "
                                f"verwenden geo-redundante Replikation."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={"geo_redundant_accounts": len(accounts)},
                            expected_state="Alle Storage Accounts mit GRS, RAGRS, GZRS oder RAGZRS",
                            audit_evidence=(
                                f"storage_accounts.list() returned {len(accounts)} accounts, all geo-redundant"
                            ),
                            iso27001_control="A.8.13 Informationssicherung",
                        )
                    )
                elif non_geo_accounts:
                    account_names = ", ".join(a["name"] for a in non_geo_accounts)
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Storage Accounts ohne Geo-Redundanz",
                            description=(
                                f"Subscription {sub_id} hat Storage Accounts ohne "
                                f"geo-redundante Replikation: {account_names}. "
                                "Ohne Geo-Redundanz droht Datenverlust bei regionalem Ausfall."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.13 Informationssicherung",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={
                                "non_geo_redundant_accounts": [
                                    {"name": a["name"], "sku": a["sku"]} for a in non_geo_accounts
                                ],
                                # Additional suffix-key with a plain string list
                                # (ADR-0011): _collect_identifiers only picks up
                                # strings/lists-of-strings under a _name/_id/_arn/
                                # _email key, never the names nested inside the
                                # dicts above. _replace_in_state still rewrites the
                                # dicts too, once these names are in the mapping.
                                "non_geo_redundant_account_name": [a["name"] for a in non_geo_accounts],
                            },
                            expected_state="Alle Storage Accounts mit GRS, RAGRS, GZRS oder RAGZRS",
                            remediation=(
                                "Ändern Sie die Replikation auf geo-redundant: "
                                "az storage account update --name <account> --resource-group <rg> "
                                "--sku Standard_GRS"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"storage_accounts.list() returned {len(accounts)} accounts, "
                                f"{len(non_geo_accounts)} without geo-redundancy"
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


class CheckAvailabilityZones(BaseCheck):
    """Check that VMs are deployed to Availability Zones."""

    check_id = "AZ-NR3-004"
    title = "Availability Zones für Produktion"
    description = "Prüft ob VMs in Availability Zones bereitgestellt sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Compute/virtualMachines/read"]
    pruefgrenzen = (
        "Prüft nur, ob VMs Availability Zones nutzen. Welche VMs produktionskritisch "
        "sind, kann der Scan nicht wissen — die Bewertung gilt allen VMs."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.compute import ComputeManagementClient

                compute_client = session.get_client(ComputeManagementClient, sub_id)
                vms = list(compute_client.virtual_machines.list_all())

                vms_without_zones = [vm.name for vm in vms if not vm.zones]

                if vms and not vms_without_zones:
                    findings.append(
                        compliant_finding(
                            self,
                            title="VMs in Availability Zones",
                            description=(
                                f"Alle {len(vms)} VMs in Subscription {sub_id} sind Availability Zones zugewiesen."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/virtualMachines",
                            account_id=sub_id,
                            current_state={"total_vms": len(vms), "vms_without_zones": 0},
                            expected_state="Alle Produktions-VMs in Availability Zones",
                            audit_evidence=(f"virtual_machines.list_all() returned {len(vms)} VMs, all zone-assigned"),
                            iso27001_control="A.5.29 Informationssicherheit bei Störungen, A.8.14 Redundanz",
                        )
                    )
                elif vms and vms_without_zones:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="VMs ohne Availability Zones",
                            description=(
                                f"Subscription {sub_id} hat {len(vms_without_zones)} "
                                f"von {len(vms)} VMs ohne Availability-Zone-Zuweisung. "
                                "Ohne Zonen-Verteilung fehlt Ausfallsicherheit bei Rechenzentrumsausfall."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.29 Informationssicherheit bei Störungen, A.8.14 Redundanz",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/virtualMachines",
                            account_id=sub_id,
                            current_state={
                                "total_vms": len(vms),
                                "vms_without_zones": len(vms_without_zones),
                            },
                            expected_state="Alle Produktions-VMs in Availability Zones",
                            remediation=(
                                "Stellen Sie VMs in Availability Zones bereit. Bestehende VMs müssen "
                                "neu erstellt werden: az vm create --zone 1 --name <vm> ..."
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=(
                                f"virtual_machines.list_all() returned {len(vms)} VMs, "
                                f"{len(vms_without_zones)} without zone assignment"
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


class CheckSiteRecovery(BaseCheck):
    """Check that Azure Site Recovery is configured for disaster recovery."""

    check_id = "AZ-NR3-005"
    title = "Recovery-Services-Vault für DR vorhanden"
    description = "Prüft ob aktive Recovery Services Vaults existieren (Voraussetzung für Azure Site Recovery)."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.RecoveryServices/vaults/read"]
    pruefgrenzen = (
        "Prüft nur die Existenz aktiver Recovery-Services-Vaults; ob Site-Recovery-Replikation "
        "eingerichtet ist, wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.recoveryservices import RecoveryServicesClient

                rs_client = session.get_client(RecoveryServicesClient, sub_id)
                vaults = list(rs_client.vaults.list_by_subscription_id())

                # Check for vaults that have site recovery (replication) capability
                asr_vaults = [v for v in vaults if v.properties and v.properties.provisioning_state == "Succeeded"]

                if asr_vaults:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Aktiver Recovery Services Vault vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(asr_vaults)} aktive Recovery "
                                f"Services Vault(s) — Voraussetzung für Azure Site Recovery."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.RecoveryServices/vaults",
                            account_id=sub_id,
                            current_state={"active_recovery_vaults": len(asr_vaults)},
                            expected_state="Mindestens ein aktiver Recovery Services Vault",
                            audit_evidence=(
                                f"vaults.list_by_subscription_id() returned {len(asr_vaults)} active vault(s)"
                            ),
                            iso27001_control="A.5.30 IKT-Bereitschaft für Business Continuity",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein aktiver Recovery Services Vault",
                            description=(
                                f"Subscription {sub_id} hat keine aktiven Recovery Services Vaults. "
                                "Ohne Vault fehlt die Voraussetzung für Azure Site Recovery."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.30 IKT-Bereitschaft für Business Continuity",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.RecoveryServices/vaults",
                            account_id=sub_id,
                            current_state={"recovery_services_vaults": len(vaults)},
                            expected_state="Mindestens ein aktiver Recovery Services Vault",
                            remediation=(
                                "Konfigurieren Sie Azure Site Recovery: "
                                "az backup vault create --resource-group <rg> --name <vault> --location <loc> && "
                                "Richten Sie Replikation für kritische VMs ein."
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=f"vaults.list_by_subscription_id() returned {len(vaults)} vaults",
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


class CheckImmutableBlobStorage(BaseCheck):
    """Check that immutable blob storage is configured for ransomware protection."""

    check_id = "AZ-NR3-006"
    title = "Immutable Blob Storage"
    description = "Prüft ob Immutable Blob Storage für Ransomware-Schutz konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    ]
    pruefgrenzen = (
        "Prüft nur Immutability-Policies auf Blob-Containern. Fehlende Unveränderlichkeit "
        "ist nur für entsprechende Aufbewahrungsanforderungen ein Mangel."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.storage import StorageManagementClient

                storage_client = session.get_client(StorageManagementClient, sub_id)
                accounts = list(storage_client.storage_accounts.list())
                total_accounts = len(accounts)

                if not accounts:
                    continue

                has_immutable = False
                accounts_checked = 0
                for account in accounts:
                    try:
                        rg_name = account.id.split("/resourceGroups/")[1].split("/")[0]
                        containers = list(storage_client.blob_containers.list(rg_name, account.name))
                        accounts_checked += 1
                        for container in containers:
                            # False-positive fix (real-ARM-verified 27.07.2026):
                            # Azure returns immutable_storage_with_versioning as
                            # {"enabled": false} on EVERY container, configured or
                            # not — a bare truthiness test declared any container
                            # compliant. Both signals must prove an ACTIVE state:
                            # a versioning-immutability explicitly enabled, or an
                            # immutability policy with a real retention period
                            # that is LOCKED. An Unlocked policy is revocable by
                            # anyone with sufficient storage permissions and thus
                            # no safeguard in the ransomware threat model this
                            # check addresses (legal review 28.07.2026, Auflage 1
                            # — strict variant chosen over documenting Unlocked
                            # as sufficient).
                            iswv = container.immutable_storage_with_versioning
                            policy = container.immutability_policy
                            if (iswv is not None and getattr(iswv, "enabled", False)) or (
                                policy is not None
                                and (getattr(policy, "immutability_period_since_creation_in_days", 0) or 0) > 0
                                and getattr(policy, "state", "") == "Locked"
                            ):
                                has_immutable = True
                                break
                        if has_immutable:
                            break
                    except Exception as exc:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type=type(exc).__name__,
                                message=str(exc),
                                region="global",
                            )
                        )

                if has_immutable:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Immutable Blob Storage konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat mindestens einen Blob-Container mit "
                                f"Immutability-Policy — unveränderliche Speicherung ist "
                                f"grundsätzlich eingerichtet; ob Backup-Daten darin liegen, ist "
                                f"organisatorisch nachzuweisen."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts/blobServices/containers",
                            account_id=sub_id,
                            current_state={"immutable_containers_found": True},
                            expected_state="Mindestens ein Container mit Immutability-Policy",
                            audit_evidence=(
                                f"Checked {accounts_checked} storage account(s), immutable container found"
                            ),
                            iso27001_control="A.8.13 Informationssicherung",
                        )
                    )
                elif accounts_checked > 0:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Immutable Blob Storage",
                            description=(
                                f"Subscription {sub_id} hat in den geprüften Storage Accounts keine "
                                "Container mit Immutability-Policies. Ohne unveränderlichen Speicher "
                                "sind Backups nicht vor Ransomware-Verschlüsselung geschützt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.13 Informationssicherung",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts/blobServices/containers",
                            account_id=sub_id,
                            current_state={"immutable_containers": 0},
                            expected_state="Mindestens ein Container mit Immutability-Policy",
                            remediation=(
                                "Aktivieren Sie Immutable Blob Storage: "
                                "az storage container immutability-policy create "
                                "--account-name <acc> --container-name <container> --period 365"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"Checked {accounts_checked} of {total_accounts} storage accounts, "
                                f"no immutable containers found"
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


class CheckTrafficManagerFrontDoor(BaseCheck):
    """Check that Traffic Manager or Front Door exists for redundancy."""

    check_id = "AZ-NR3-007"
    title = "Traffic Manager / Front Door"
    description = "Prüft ob Azure Traffic Manager oder Front Door für Traffic-Redundanz vorhanden ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Network/trafficManagerProfiles/read",
        "Microsoft.Network/frontDoors/read",
    ]
    pruefgrenzen = (
        "Prüft nur die Existenz von Traffic Manager/Front Door. Andere "
        "Lastverteilungs- oder Failover-Lösungen werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource.resources import ResourceManagementClient

                resource_client = session.get_client(ResourceManagementClient, sub_id)
                redundancy_types = {
                    "Microsoft.Network/trafficManagerProfiles",
                    "Microsoft.Network/frontDoors",
                    "Microsoft.Cdn/profiles",
                }

                found_resources = []
                for resource in resource_client.resources.list():
                    if resource.type in redundancy_types:
                        found_resources.append(resource.type)

                if found_resources:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Traffic-Redundanz konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat {len(found_resources)} Ressource(n) "
                                f"für Traffic-Redundanz (Traffic Manager, Front Door oder CDN)."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/trafficManagerProfiles",
                            account_id=sub_id,
                            current_state={"redundancy_resources": len(found_resources)},
                            expected_state="Traffic Manager, Front Door oder CDN für Traffic-Redundanz",
                            audit_evidence=(f"resources.list() returned {len(found_resources)} redundancy resource(s)"),
                            iso27001_control="A.8.14 Redundanz von Informationsverarbeitungseinrichtungen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Traffic Manager / Front Door",
                            description=(
                                f"Subscription {sub_id} hat weder Traffic Manager, "
                                "Front Door noch CDN konfiguriert. Ohne Traffic-Redundanz fehlt "
                                "die Lastverteilung über mehrere Regionen."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.14 Redundanz von Informationsverarbeitungseinrichtungen",
                            severity=Severity.LOW,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/trafficManagerProfiles",
                            account_id=sub_id,
                            current_state={"traffic_manager": 0, "front_door": 0, "cdn": 0},
                            expected_state="Traffic Manager, Front Door oder CDN für Traffic-Redundanz",
                            remediation=(
                                "Erstellen Sie ein Traffic Manager-Profil: "
                                "az network traffic-manager profile create --name <tm> "
                                "--resource-group <rg> --routing-method Performance"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="resources.list() returned no Traffic Manager, Front Door, or CDN resources",
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
