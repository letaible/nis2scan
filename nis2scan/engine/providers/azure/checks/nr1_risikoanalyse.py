"""§30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for Azure.

Checks Defender for Cloud, Azure Policy, Management Groups, Activity Logs, and Sentinel.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity
from nis2scan.engine.providers.azure.sdk_values import sdk_list

logger = structlog.get_logger()

BSIG_30_NR = 1
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
)


class CheckDefenderForCloud(BaseCheck):
    """Check that Microsoft Defender for Cloud is enabled across subscriptions."""

    check_id = "AZ-NR1-001"
    title = "Defender for Cloud aktiviert"
    description = "Prüft ob Microsoft Defender for Cloud in allen Subscriptions aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Security/pricings/read"]
    pruefgrenzen = (
        "Prüft nur, ob Defender-for-Cloud-Pläne aktiviert sind. Nicht geprüft wird, "
        "ob die Empfehlungen bearbeitet werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.security import SecurityCenter

                client = session.get_client(SecurityCenter, sub_id)
                # sdk_list, nicht list(): azure-mgmt-security 6.x liefert hier
                # ein PricingList-Modell ohne __iter__ (siehe sdk_values.py).
                pricings = sdk_list(client.pricings.list())

                free_tier_plans = [p for p in pricings if p.pricing_tier == "Free"]
                if pricings and not free_tier_plans:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Defender for Cloud aktiviert",
                            description=(
                                f"Subscription {sub_id} hat alle {len(pricings)} Defender-Pläne "
                                f"im Standard-Tier aktiviert."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/pricings",
                            account_id=sub_id,
                            current_state={"standard_tier_plans": len(pricings), "free_tier_plans": 0},
                            expected_state="Alle Defender-Pläne auf Standard-Tier",
                            audit_evidence=f"pricings.list() returned {len(pricings)} plans, 0 Free-Tier",
                            iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                        )
                    )
                elif free_tier_plans:
                    plan_names = ", ".join(p.name for p in free_tier_plans)
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Defender-Pläne nicht aktiviert",
                            description=(
                                f"Subscription {sub_id} hat Defender-Pläne "
                                f"im Free-Tier: {plan_names}. Ohne Defender fehlt die "
                                "zentrale Sicherheitsbewertung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/pricings",
                            account_id=sub_id,
                            current_state={"free_tier_plans": plan_names},
                            expected_state="Alle Defender-Pläne auf Standard-Tier",
                            remediation=(
                                "Aktivieren Sie Defender for Cloud Standard-Tier: "
                                "az security pricing create --name VirtualMachines --tier Standard"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"pricings.list() returned {len(free_tier_plans)} Free-Tier plans",
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


class CheckAzurePolicyAssignments(BaseCheck):
    """Check that Azure Policy assignments exist for governance."""

    check_id = "AZ-NR1-002"
    title = "Azure Policy Assignments vorhanden"
    description = "Prüft ob Azure Policy Assignments für die Durchsetzung von Sicherheitsstandards existieren."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Authorization/policyAssignments/read"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Policy-Zuweisungen. Inhalt und Angemessenheit der Policies werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource.policy import PolicyClient

                client = session.get_client(PolicyClient, sub_id)
                assignments = list(client.policy_assignments.list())

                # Filter out built-in ASC/Defender assignments — look for custom ones.
                # Custom policies can be assigned either as a single policy definition
                # or as an initiative (policy set definition).
                custom_assignments = [
                    a
                    for a in assignments
                    if not (a.display_name or "").startswith("ASC ")
                    and a.policy_definition_id
                    and (
                        "/providers/Microsoft.Authorization/policyDefinitions/" in (a.policy_definition_id or "")
                        or "/providers/Microsoft.Authorization/policySetDefinitions/" in (a.policy_definition_id or "")
                    )
                ]

                if custom_assignments:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Azure Policy Assignments vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(custom_assignments)} "
                                f"benutzerdefinierte Azure Policy Assignments."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Authorization/policyAssignments",
                            account_id=sub_id,
                            current_state={"custom_policy_assignments": len(custom_assignments)},
                            expected_state="Mindestens eine benutzerdefinierte Policy Assignment",
                            audit_evidence=(
                                f"policy_assignments.list() returned {len(assignments)} total, "
                                f"{len(custom_assignments)} custom"
                            ),
                            iso27001_control="A.5.1, A.5.2 Informationssicherheitsrichtlinien",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine benutzerdefinierten Policy Assignments",
                            description=(
                                f"Subscription {sub_id} hat keine benutzerdefinierten "
                                "Azure Policy Assignments. Ohne Policies werden Sicherheitsstandards "
                                "nicht automatisch durchgesetzt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.1, A.5.2 Informationssicherheitsrichtlinien",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Authorization/policyAssignments",
                            account_id=sub_id,
                            current_state={"custom_policy_assignments": 0},
                            expected_state="Mindestens eine benutzerdefinierte Policy Assignment",
                            remediation=(
                                "Erstellen Sie Azure Policy Assignments für CIS Benchmark oder "
                                "ISO 27001: az policy assignment create --name 'cis-benchmark' "
                                "--policy-set-definition 'CIS Microsoft Azure Foundations'"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=f"policy_assignments.list() returned {len(assignments)} total, 0 custom",
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


class CheckManagementGroups(BaseCheck):
    """Check that Azure Management Groups are configured for governance."""

    check_id = "AZ-NR1-003"
    title = "Management Groups konfiguriert"
    description = "Prüft ob Azure Management Groups für organisationsweite Governance konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Management/managementGroups/read"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Management Groups. Ob die Hierarchie sinnvoll "
        "strukturiert ist, wird nicht bewertet. Bei Einzel-Subscription-Konstellationen wird "
        "ein Hinweis mit niedriger Schwere ausgegeben; die Anwendbarkeit ist organisatorisch "
        "zu bewerten."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from azure.mgmt.managementgroups import ManagementGroupsMgmtClient

            client = ManagementGroupsMgmtClient(session.credential)
            groups = list(client.management_groups.list())

            # The root tenant group always exists — check for custom groups
            custom_groups = [g for g in groups if g.display_name != "Tenant Root Group"]

            if custom_groups:
                findings.append(
                    compliant_finding(
                        self,
                        title="Management Groups konfiguriert",
                        description=(
                            f"Es sind {len(custom_groups)} benutzerdefinierte Management Groups "
                            f"für organisationsweite Governance konfiguriert."
                        ),
                        region="global",
                        resource_id="/providers/Microsoft.Management/managementGroups",
                        resource_type="Microsoft.Management/managementGroups",
                        account_id=session.subscription_id,
                        current_state={"custom_management_groups": len(custom_groups)},
                        expected_state="Mindestens eine benutzerdefinierte Management Group",
                        audit_evidence=(
                            f"management_groups.list() returned {len(groups)} total, {len(custom_groups)} custom"
                        ),
                        iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine benutzerdefinierten Management Groups",
                        description=(
                            "Es sind keine benutzerdefinierten Management Groups konfiguriert. "
                            "Ohne Management Groups fehlt die hierarchische Klammer für "
                            "subscriptionübergreifende Governance. Nutzt Ihre Einrichtung nur eine "
                            "einzelne Subscription, kann dieser Punkt gegenstandslos sein; die "
                            "Anwendbarkeit ist organisatorisch zu bewerten."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                        severity=Severity.LOW,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/providers/Microsoft.Management/managementGroups",
                        resource_type="Microsoft.Management/managementGroups",
                        account_id=session.subscription_id,
                        current_state={"custom_management_groups": 0},
                        expected_state="Mindestens eine benutzerdefinierte Management Group",
                        remediation=(
                            "Erstellen Sie Management Groups für Ihre Organisation: "
                            "az account management-group create --name 'Production' "
                            "--display-name 'Production Workloads'"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=f"management_groups.list() returned {len(groups)} total, 0 custom",
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


class CheckActivityLogRetention(BaseCheck):
    """Check that a Diagnostic Setting for Activity Log export exists."""

    check_id = "AZ-NR1-004"
    title = "Activity Log Export konfiguriert"
    description = "Prüft ob für Activity Logs ein Export (Diagnostic Setting) konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Insights/diagnosticSettings/read"]
    pruefgrenzen = (
        "Prüft nur, ob ein Activity-Log-Export (Diagnostic Setting) konfiguriert ist. "
        "Vollständigkeit der Kategorien und Auswertung der Logs werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.monitor import MonitorManagementClient

                client = session.get_client(MonitorManagementClient, sub_id)
                resource_uri = f"/subscriptions/{sub_id}"
                settings = list(client.diagnostic_settings.list(resource_uri=resource_uri))

                if settings:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Activity Log Export konfiguriert",
                            description=(
                                f"Subscription {sub_id} exportiert Activity Logs über "
                                f"{len(settings)} Diagnostic Setting(s)."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/diagnosticSettings",
                            account_id=sub_id,
                            current_state={"diagnostic_settings": len(settings)},
                            expected_state="Diagnostic Setting für Activity Logs vorhanden",
                            audit_evidence=f"diagnostic_settings.list() returned {len(settings)} setting(s)",
                            iso27001_control="A.8.15 Logging",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Activity Log nicht exportiert",
                            description=(
                                f"Subscription {sub_id} exportiert Activity Logs nicht. "
                                "Ohne Export fehlt der Audit-Trail."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.15 Logging",
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/diagnosticSettings",
                            account_id=sub_id,
                            current_state={"diagnostic_settings": 0},
                            expected_state="Diagnostic Setting für Activity Logs vorhanden",
                            remediation=(
                                "Konfigurieren Sie Activity Log Export: "
                                "az monitor diagnostic-settings create --name 'activity-log-export' "
                                "--resource '/subscriptions/<sub>' "
                                "--workspace <log-analytics-id>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="diagnostic_settings.list() returned 0 settings for subscription",
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


class CheckSentinelWorkspace(BaseCheck):
    """Check that a Sentinel-capable Log Analytics workspace exists."""

    check_id = "AZ-NR1-005"
    title = "Log Analytics Workspace (Sentinel-Basis)"
    description = "Prüft ob ein Sentinel-fähiger Log-Analytics-Workspace existiert."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.OperationalInsights/workspaces/read"]
    pruefgrenzen = (
        "Prüft nur, ob ein Sentinel-fähiger Log-Analytics-Workspace existiert. "
        "Ein SIEM außerhalb von Azure (Splunk, Elastic u. a.) wird nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.loganalytics import LogAnalyticsManagementClient

                la_client = session.get_client(LogAnalyticsManagementClient, sub_id)
                workspaces = list(la_client.workspaces.list())

                # Check if any workspace is active — this only proves a Sentinel-capable
                # workspace exists, not that Sentinel itself is enabled on it.
                sentinel_found = False
                for ws in workspaces:
                    if ws.provisioning_state == "Succeeded":
                        sentinel_found = True
                        break

                if sentinel_found:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Log Analytics Workspace aktiv",
                            description=(
                                f"Subscription {sub_id} hat einen aktiven Log Analytics Workspace, "
                                f"der als Grundlage für Microsoft Sentinel dienen kann."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.OperationalInsights/workspaces",
                            account_id=sub_id,
                            current_state={"log_analytics_workspaces": len(workspaces)},
                            expected_state="Mindestens ein aktiver Log Analytics Workspace",
                            audit_evidence=(f"workspaces.list() returned {len(workspaces)} workspace(s), >=1 active"),
                            iso27001_control="A.5.7 Threat Intelligence",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein aktiver Log Analytics Workspace",
                            description=(
                                f"Subscription {sub_id} hat keinen aktiven Log Analytics Workspace. "
                                "Ohne einen aktiven Workspace fehlt die Grundlage für Microsoft "
                                "Sentinel als SIEM. Ein SIEM außerhalb von Azure wurde nicht geprüft."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.7 Threat Intelligence",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.OperationalInsights/workspaces",
                            account_id=sub_id,
                            current_state={"log_analytics_workspaces": len(workspaces)},
                            expected_state="Mindestens ein aktiver Log Analytics Workspace",
                            remediation=(
                                "Erstellen Sie einen Log Analytics Workspace und aktivieren Sie Sentinel: "
                                "az monitor log-analytics workspace create --resource-group <rg> "
                                "--workspace-name sentinel-ws"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=f"workspaces.list() returned {len(workspaces)} workspaces, 0 active",
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
