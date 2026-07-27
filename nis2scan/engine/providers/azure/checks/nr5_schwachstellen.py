"""§30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for Azure.

Checks Defender Vulnerability Assessment, Update Management, Container Registry Scan,
App Service Runtime, and SQL Vulnerability Assessment.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 5
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und "
    "Wartung von informationstechnischen Systemen, Komponenten und Prozessen, "
    "einschließlich Management und Offenlegung von Schwachstellen"
)

# Outdated runtimes for App Service check. Stand der Liste: Mapping-Release 2026.07.
# Bei jedem Mapping-Release gegen die unterstützten App-Service-Stacks (z. B. via
# `az webapp list-runtimes` oder die Azure-App-Service-Dokumentation) aktualisieren.
OUTDATED_RUNTIMES = {
    "DOTNET": ["3.1", "5.0", "6.0", "7."],
    "DOTNETCORE": ["2.", "3.", "5.", "6.", "7."],
    "NODE": ["12", "14", "16", "18"],
    "PYTHON": ["3.7", "3.8", "3.9"],
    "JAVA": ["8", "11"],
    "PHP": ["7.4", "8.0", "8.1"],
}


class CheckDefenderVulnAssessment(BaseCheck):
    """Check that Defender for Cloud vulnerability assessment is enabled."""

    check_id = "AZ-NR5-001"
    title = "Defender for Cloud — Vulnerability Assessment"
    description = "Prüft ob Defender for Cloud Schwachstellenbewertung aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Security/pricings/read",
    ]
    pruefgrenzen = (
        "Prüft nur, ob der Defender-for-Servers-Plan (VirtualMachines) auf einem "
        "kostenpflichtigen Tarif steht. Ob die Schwachstellenbewertung auf den "
        "einzelnen VMs bereitgestellt ist und Ergebnisse liefert, wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.security import SecurityCenter

                security_client = session.get_client(SecurityCenter, sub_id)
                pricings = list(security_client.pricings.list())

                # Check if VirtualMachines plan is enabled (required for VA)
                vm_plan = next((p for p in pricings if p.name == "VirtualMachines"), None)

                if vm_plan and vm_plan.pricing_tier != "Free":
                    findings.append(
                        compliant_finding(
                            self,
                            title="Defender Vulnerability Assessment aktiviert",
                            description=(
                                f"Subscription {sub_id} hat Defender for Servers "
                                f"({vm_plan.pricing_tier}-Tier) aktiviert — die Schwachstellenbewertung "
                                f"für VMs steht damit bereit."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/pricings",
                            account_id=sub_id,
                            current_state={"virtual_machines_plan": vm_plan.pricing_tier},
                            expected_state="Defender for Servers (Standard-Tier) mit Vulnerability Assessment",
                            audit_evidence=f"pricings.list(): VirtualMachines plan tier={vm_plan.pricing_tier}",
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Defender Vulnerability Assessment nicht aktiviert",
                            description=(
                                f"Subscription {sub_id} hat Defender for Servers nicht "
                                "aktiviert. Ohne Vulnerability Assessment werden Schwachstellen in "
                                "VMs nicht automatisch erkannt. Sofern die Subscription keine "
                                "virtuellen Maschinen betreibt, hat dieser Befund vorsorglichen Charakter."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/pricings",
                            account_id=sub_id,
                            current_state={"virtual_machines_plan": vm_plan.pricing_tier if vm_plan else "not found"},
                            expected_state="Defender for Servers (Standard-Tier) mit Vulnerability Assessment",
                            remediation=(
                                "Aktivieren Sie Defender for Servers: "
                                "az security pricing create --name VirtualMachines --tier Standard"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"pricings.list(): VirtualMachines plan "
                                f"tier={vm_plan.pricing_tier if vm_plan else 'missing'}"
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


class CheckUpdateManagement(BaseCheck):
    """Check that Update Management Center is configured."""

    check_id = "AZ-NR5-002"
    title = "Update Management Center konfiguriert"
    description = "Prüft ob Azure Update Management Center für Patch-Management konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Maintenance/maintenanceConfigurations/read"]
    pruefgrenzen = (
        "Prüft nur, ob Maintenance-Konfigurationen in der Subscription existieren. "
        "Deren Geltungsbereich (maintenanceScope, z. B. InGuestPatch), die Zuordnung "
        "zu VMs und die tatsächliche Patch-Installation werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource.resources import ResourceManagementClient

                resource_client = session.get_client(ResourceManagementClient, sub_id)
                maintenance_configs = [
                    r
                    for r in resource_client.resources.list(
                        filter="resourceType eq 'Microsoft.Maintenance/maintenanceConfigurations'"
                    )
                ]

                if maintenance_configs:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Update Management konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat {len(maintenance_configs)} "
                                f"Maintenance-Konfiguration(en). Ob diese Gast-OS-Patching "
                                f"(InGuestPatch) abdecken und VMs zugeordnet sind, ist gesondert "
                                f"nachzuweisen."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Maintenance/maintenanceConfigurations",
                            account_id=sub_id,
                            current_state={"maintenance_configurations": len(maintenance_configs)},
                            expected_state="Mindestens eine Maintenance-Konfiguration für Patch-Management",
                            audit_evidence=(
                                f"resources.list() returned {len(maintenance_configs)} maintenanceConfigurations"
                            ),
                            iso27001_control=(
                                "A.8.8 Management technischer Schwachstellen, A.8.9 Konfigurationsmanagement"
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Update Management konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat keine Maintenance-Konfigurationen. "
                                "Ohne Update Management werden Sicherheitspatches nicht systematisch "
                                "eingespielt. Sofern die Subscription keine virtuellen Maschinen "
                                "betreibt, hat dieser Befund vorsorglichen Charakter."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=(
                                "A.8.8 Management technischer Schwachstellen, A.8.9 Konfigurationsmanagement"
                            ),
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Maintenance/maintenanceConfigurations",
                            account_id=sub_id,
                            current_state={"maintenance_configurations": 0},
                            expected_state="Mindestens eine Maintenance-Konfiguration für Patch-Management",
                            remediation=(
                                "Konfigurieren Sie Update Management Center im Azure Portal oder via CLI: "
                                "az maintenance configuration create --resource-group <rg> "
                                "--name <config-name> --maintenance-scope InGuestPatch"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="resources.list() returned 0 maintenanceConfigurations",
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


class CheckContainerRegistryScan(BaseCheck):
    """Check that Container Registry image scanning is enabled."""

    check_id = "AZ-NR5-003"
    title = "Container Registry Image Scan"
    description = "Prüft die SKU-Stufe von Azure Container Registries als Indiz für die Scan-Fähigkeit."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.ContainerRegistry/registries/read"]
    pruefgrenzen = (
        "Prüft nur die SKU-Stufe der Registry als technisches Indiz. Ob ein "
        "Schwachstellen-Scan-Dienst (z. B. Microsoft Defender for Containers) tatsächlich "
        "aktiviert ist, wird nicht geprüft; Registries außerhalb von ACR werden nicht erfasst."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.containerregistry import ContainerRegistryManagementClient

                acr_client = session.get_client(ContainerRegistryManagementClient, sub_id)
                registries = list(acr_client.registries.list())

                for registry in registries:
                    # Check if registry uses Premium SKU (required for advanced scanning)
                    sku_name = registry.sku.name if registry.sku else "Unknown"
                    if sku_name in ("Premium", "Standard"):
                        findings.append(
                            compliant_finding(
                                self,
                                title="Container Registry mit Scan-fähiger SKU",
                                description=(
                                    f"Container Registry {registry.name} verwendet SKU {sku_name} — "
                                    f"Schwachstellen-Scans für Images sind möglich."
                                ),
                                region=registry.location or "global",
                                resource_id=registry.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.ContainerRegistry/registries",
                                account_id=sub_id,
                                current_state={"sku": sku_name},
                                expected_state=("Container Registry mit Standard- oder Premium-SKU"),
                                audit_evidence=f"registries.list(): {registry.name} sku={sku_name}",
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Container Registry mit Basic-SKU",
                                description=(
                                    f"Container Registry {registry.name} in "
                                    f"Subscription {sub_id} verwendet SKU {sku_name}."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AZURE,
                                region=registry.location or "global",
                                resource_id=registry.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.ContainerRegistry/registries",
                                account_id=sub_id,
                                current_state={"sku": sku_name},
                                expected_state="Container Registry mit Standard- oder Premium-SKU",
                                remediation=(
                                    "Upgraden Sie die Registry-SKU: "
                                    f"az acr update --name {registry.name} --sku Standard"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=f"registries.list(): {registry.name} sku={sku_name}",
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


class CheckAppServiceRuntime(BaseCheck):
    """Check that App Service runtimes are up to date."""

    check_id = "AZ-NR5-004"
    title = "App Service Runtime aktuell"
    description = "Prüft ob App Service Laufzeitumgebungen aktuell sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Web/sites/read",
        "Microsoft.Web/sites/config/read",
    ]
    pruefgrenzen = (
        "Prüft App-Service-Runtimes gegen eine im Tool gepflegte Liste veralteter "
        "Versionen — neue Deprecations erfordern ein Tool-Update. Apps ohne "
        "identifizierbare verwaltete Runtime (z. B. Custom-Container) werden nicht bewertet. "
        "Windows-Apps mit klassischem .NET Framework werden nicht bewertet, da die API "
        "(netFrameworkVersion) nur die CLR-Version (v2.0/v4.0) meldet und keine Aussage "
        "über die konkrete Framework-Version (z. B. 4.8) erlaubt."
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
                    site_config = app.site_config
                    linux_fx = (site_config.linux_fx_version or "") if site_config else ""
                    net_version = (site_config.net_framework_version or "") if site_config else ""

                    # The Azure list API frequently leaves siteConfig empty — fall back
                    # to get_configuration() before giving up on this app (B-Nr.5-12f).
                    if not linux_fx and not net_version:
                        try:
                            rg_name = app.id.split("/resourceGroups/")[1].split("/")[0]
                            full_config = web_client.web_apps.get_configuration(rg_name, app.name)
                            linux_fx = full_config.linux_fx_version or ""
                            net_version = full_config.net_framework_version or ""
                        except Exception as config_exc:
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type=type(config_exc).__name__,
                                    message=(
                                        f"Konfiguration für App Service '{app.name}' nicht abrufbar — "
                                        f"Runtime nicht bewertbar: {config_exc}"
                                    ),
                                    region=app.location or "global",
                                )
                            )
                            continue

                    runtime_info = None
                    is_outdated = False
                    runtime_known = False

                    if linux_fx:
                        # Format: RUNTIME|VERSION e.g. "PYTHON|3.9"
                        parts = linux_fx.split("|")
                        if len(parts) == 2:
                            runtime, version = parts[0].upper(), parts[1]
                            if runtime in OUTDATED_RUNTIMES:
                                # Only judge runtime families the tool tracks — unknown
                                # prefixes (DOCKER, COMPOSE, ...) are skipped: no
                                # finding, no error (B-Nr.5-12b).
                                runtime_known = True
                                runtime_info = f"{runtime} {version}"
                                outdated_versions = OUTDATED_RUNTIMES[runtime]
                                if any(version.startswith(v) for v in outdated_versions):
                                    is_outdated = True
                    # Classic .NET Framework apps (netFrameworkVersion) are NOT judged:
                    # the API reports only the CLR version (v2.0/v4.0) — v4.0 is the
                    # normal value of a current .NET Framework 4.8 app, so no statement
                    # about the actual framework version is possible (B-Nr.5-20).

                    if not runtime_known:
                        continue

                    if not is_outdated:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Web App ohne bekannte Runtime-Veraltung",
                                description=(
                                    f"App Service {app.name} verwendet die Runtime '{runtime_info}', "
                                    f"die zum Prüfstand des Tools nicht als veraltet bekannt ist "
                                    f"(Stand Mapping 2026.07)."
                                ),
                                region=app.location or "global",
                                resource_id=app.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Web/sites",
                                account_id=sub_id,
                                current_state={"runtime": runtime_info},
                                expected_state="Aktuelle, unterstützte Laufzeitversion",
                                audit_evidence=(
                                    f"web_apps: {app.name} runtime '{runtime_info}' not in "
                                    f"outdated-runtimes list (Stand Mapping 2026.07)"
                                ),
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Veraltete App Service Runtime",
                                description=(
                                    f"App Service {app.name} in Subscription {sub_id} "
                                    f"verwendet veraltete Runtime {runtime_info}."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AZURE,
                                region=app.location or "global",
                                resource_id=app.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Web/sites",
                                account_id=sub_id,
                                current_state={"runtime": runtime_info},
                                expected_state="Aktuelle, unterstützte Laufzeitversion",
                                remediation=(
                                    f"Aktualisieren Sie die Runtime für {app.name}: "
                                    "az webapp config set --linux-fx-version '<RUNTIME>|<VERSION>' "
                                    f"--name {app.name} --resource-group <rg>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=f"web_apps.list(): {app.name} runtime={runtime_info}",
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


class CheckSqlVulnAssessment(BaseCheck):
    """Check that SQL Server vulnerability assessment is enabled."""

    check_id = "AZ-NR5-005"
    title = "SQL Vulnerability Assessment aktiviert"
    description = "Prüft ob SQL Server Vulnerability Assessment für automatische Schwachstellenerkennung aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/vulnerabilityAssessments/read",
    ]
    pruefgrenzen = (
        "Prüft nur, ob SQL Vulnerability Assessment aktiviert ist. Befunde und deren Behebung werden nicht bewertet."
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
                    try:
                        va_list = list(sql_client.server_vulnerability_assessments.list_by_server(rg_name, server.name))
                        if va_list:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="SQL Vulnerability Assessment aktiviert",
                                    description=(f"SQL Server {server.name} hat Vulnerability Assessment aktiviert."),
                                    region=server.location or "global",
                                    resource_id=server.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.Sql/servers",
                                    account_id=sub_id,
                                    current_state={"vulnerability_assessment": "configured"},
                                    expected_state="Vulnerability Assessment aktiviert mit periodischen Scans",
                                    audit_evidence=(
                                        f"server_vulnerability_assessments.list_by_server(): "
                                        f"{len(va_list)} assessment(s) for {server.name}"
                                    ),
                                    iso27001_control="A.8.8 Management technischer Schwachstellen",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="SQL Vulnerability Assessment nicht aktiviert",
                                    description=(
                                        f"SQL Server {server.name} in Subscription {sub_id} "
                                        "hat Vulnerability Assessment nicht aktiviert."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.8 Management technischer Schwachstellen",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AZURE,
                                    region=server.location or "global",
                                    resource_id=server.id or f"/subscriptions/{sub_id}",
                                    resource_type="Microsoft.Sql/servers",
                                    account_id=sub_id,
                                    current_state={
                                        "vulnerability_assessment": "not configured",
                                        # rg_name is interpolated into the remediation
                                        # az-CLI command; resource_id's tail is the
                                        # server name, never the (mid-path) resource
                                        # group, so it needs its own suffix key
                                        # (ADR-0011).
                                        "resource_group_name": rg_name,
                                    },
                                    expected_state="Vulnerability Assessment aktiviert mit periodischen Scans",
                                    remediation=(
                                        "Aktivieren Sie Vulnerability Assessment: "
                                        f"az sql server va-setting update --resource-group {rg_name} "
                                        f"--server-name {server.name} --storage-account <storage>"
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(
                                        f"server_vulnerability_assessments.list_by_server(): "
                                        f"0 assessments for {server.name}"
                                    ),
                                )
                            )
                    except Exception as exc:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type=type(exc).__name__,
                                message=(
                                    f"Vulnerability-Assessment-Abfrage für SQL Server "
                                    f"'{server.name}' fehlgeschlagen: {exc}"
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
