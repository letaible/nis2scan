"""§30 Abs. 2 Nr. 6 — Bewertung der Wirksamkeit von Risikomanagementmaßnahmen checks for Azure.

Checks Defender Secure Score, Policy Compliance, Log Retention, and Diagnostic Settings.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 6
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 6 BSIG — Konzepte und Verfahren zur Bewertung der Wirksamkeit "
    "von Risikomanagementmaßnahmen im Bereich der Sicherheit in der "
    "Informationstechnik"
)

MIN_SECURE_SCORE_PERCENT = 70
MIN_LOG_RETENTION_DAYS = 365
CRITICAL_RESOURCE_TYPES = [
    "Microsoft.KeyVault/vaults",
    "Microsoft.Sql/servers",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Network/networkSecurityGroups",
]


class CheckDefenderSecureScore(BaseCheck):
    """Check that Defender Secure Score is at least 70%."""

    check_id = "AZ-NR6-001"
    title = "Defender Secure Score ≥70%"
    description = "Prüft ob der Microsoft Defender Secure Score mindestens 70% beträgt."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Security/secureScores/read"]
    pruefgrenzen = (
        "Liest nur den von Defender berechneten Secure Score. Der Schwellwert 70% "
        "ist eine Tool-Konvention, kein gesetzlicher Grenzwert."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.security import SecurityCenter

                security_client = session.get_client(SecurityCenter, sub_id)
                scores = list(security_client.secure_scores.list())

                if not scores:
                    # B-Nr.6-7: no fabricated 0/1 defaults — an empty result means the
                    # state is unknowable, not that the score is zero (ADR-0016).
                    errors.append(
                        CheckError(
                            check_id=self.check_id,
                            error_type="NoSecureScoreData",
                            message="secure_scores.list() lieferte keine Einträge",
                            region="global",
                        )
                    )
                    continue

                for score in scores:
                    if score.current is None or score.max is None:
                        errors.append(
                            CheckError(
                                check_id=self.check_id,
                                error_type="IncompleteSecureScore",
                                message="Secure Score unvollständig — Zustand nicht bewertbar",
                                region="global",
                            )
                        )
                        continue

                    current = score.current
                    max_score = score.max
                    percentage = (current / max_score * 100) if max_score > 0 else 0

                    if percentage >= MIN_SECURE_SCORE_PERCENT:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Defender Secure Score ausreichend",
                                description=(
                                    f"Subscription {sub_id} hat einen Secure Score von "
                                    f"{percentage:.0f}% ({current}/{max_score}) — Minimum "
                                    f"{MIN_SECURE_SCORE_PERCENT}% ist erreicht."
                                ),
                                region="global",
                                resource_id=f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Security/secureScores",
                                account_id=sub_id,
                                current_state={
                                    "current_score": current,
                                    "max_score": max_score,
                                    "percentage": round(percentage, 1),
                                },
                                expected_state=f"Secure Score ≥ {MIN_SECURE_SCORE_PERCENT}%",
                                audit_evidence=(
                                    f"secure_scores.list(): score={current}/{max_score} ({percentage:.0f}%)"
                                ),
                                iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Defender Secure Score unter 70%",
                                description=(
                                    f"Subscription {sub_id} hat einen Secure Score "
                                    f"von {percentage:.0f}% ({current}/{max_score}). "
                                    f"Mindestens {MIN_SECURE_SCORE_PERCENT}% wird empfohlen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region="global",
                                resource_id=f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Security/secureScores",
                                account_id=sub_id,
                                current_state={
                                    "current_score": current,
                                    "max_score": max_score,
                                    "percentage": round(percentage, 1),
                                },
                                expected_state=f"Secure Score ≥ {MIN_SECURE_SCORE_PERCENT}%",
                                remediation=(
                                    "Befolgen Sie die Empfehlungen in Microsoft Defender for Cloud, "
                                    "um den Secure Score zu verbessern. Priorisieren Sie Empfehlungen "
                                    "mit hoher Auswirkung."
                                ),
                                remediation_effort="HIGH",
                                audit_evidence=(
                                    f"secure_scores.list(): score={current}/{max_score} ({percentage:.0f}%)"
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


class CheckPolicyComplianceState(BaseCheck):
    """Check Azure Policy compliance state."""

    check_id = "AZ-NR6-002"
    title = "Azure Policy Compliance State"
    description = "Prüft den Azure Policy Compliance-Status der Subscription."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.PolicyInsights/policyStates/queryResults/action"]
    pruefgrenzen = (
        "Liest nur den Azure-Policy-Compliance-Stand. Aussagekraft hängt von der "
        "Abdeckung der zugewiesenen Policies ab (siehe AZ-NR1-002)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.policyinsights import (  # type: ignore[import-untyped, unused-ignore]
                    PolicyInsightsClient,
                )

                policy_client = PolicyInsightsClient(session.credential, sub_id)
                query_results = list(
                    policy_client.policy_states.list_query_results_for_subscription(
                        policy_states_resource="latest",
                        subscription_id=sub_id,
                    )
                )

                non_compliant = [r for r in query_results if r.compliance_state == "NonCompliant"]

                if not query_results:
                    # B-Nr.6-8(i): an empty result set was previously silent (neither
                    # branch below matched) — it means there is no technical basis for
                    # the effectiveness assessment via Azure Policy at all.
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Policy-Compliance-Daten vorhanden",
                            description=(
                                f"Subscription {sub_id} liefert keine Policy-Compliance-Ergebnisse. Ohne "
                                f"ausgewertete Policy-Zuweisungen fehlt die technische Grundlage für die "
                                f"Wirksamkeitsbewertung über Azure Policy (mögliche Ursache: keine "
                                f"zugewiesenen Policies, siehe AZ-NR1-002)."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.PolicyInsights/policyStates",
                            account_id=sub_id,
                            current_state={"total_results": 0, "non_compliant": 0},
                            expected_state="Keine Policy-Assignments im Status 'NonCompliant'",
                            remediation=(
                                "Weisen Sie Azure Policies zu (siehe AZ-NR1-002) und stellen Sie sicher, "
                                "dass die Policy-Compliance-Auswertung läuft: "
                                "az policy state list --top 1"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="policy_states.list_query_results_for_subscription(): 0 results",
                        )
                    )
                elif not non_compliant:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine nicht-konformen Policy-Ergebnisse",
                            description=(
                                f"Subscription {sub_id} hat {len(query_results)} Policy-Ergebnisse, "
                                f"keines im Status 'NonCompliant'."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.PolicyInsights/policyStates",
                            account_id=sub_id,
                            current_state={"total_results": len(query_results), "non_compliant": 0},
                            expected_state="Keine Policy-Assignments im Status 'NonCompliant'",
                            audit_evidence=(
                                f"policy_states.list_query_results_for_subscription(): "
                                f"0/{len(query_results)} non-compliant"
                            ),
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                        )
                    )
                elif non_compliant:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Nicht-konforme Azure Policies",
                            description=(
                                f"Subscription {sub_id} hat {len(non_compliant)} "
                                f"nicht-konforme Policy-Ergebnisse von insgesamt {len(query_results)}. "
                                "Nicht-konforme Policies deuten auf Sicherheitslücken hin."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.PolicyInsights/policyStates",
                            account_id=sub_id,
                            current_state={
                                "total_results": len(query_results),
                                "non_compliant": len(non_compliant),
                            },
                            expected_state="Keine Policy-Assignments im Status 'NonCompliant'",
                            remediation=(
                                "Beheben Sie die nicht-konformen Policy-Ergebnisse: "
                                "az policy state list --filter \"complianceState eq 'NonCompliant'\" "
                                "und folgen Sie den Empfehlungen zur Remediation."
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=(
                                f"policy_states.list_query_results_for_subscription(): "
                                f"{len(non_compliant)}/{len(query_results)} non-compliant"
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


class CheckLogRetention(BaseCheck):
    """Check that Log Analytics Workspace retention is at least 365 days."""

    check_id = "AZ-NR6-003"
    title = "Log Analytics Workspace Retention ≥365 Tage"
    description = (
        "Prüft ob Log Analytics Workspaces eine Datenaufbewahrung von mindestens 365 Tagen konfiguriert haben."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.OperationalInsights/workspaces/read",
    ]
    pruefgrenzen = (
        "Prüft nur die Workspace-Retention. Ob Activity Logs tatsächlich in einen "
        "Workspace exportiert werden, wird nicht geprüft; externe Archivierung "
        "(Storage/SIEM) mit kürzerer nativer Retention wird als Mangel gewertet, "
        "obwohl sie gleichwertig sein kann. Der Schwellwert 365 Tage ist eine "
        "Tool-Konvention."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.loganalytics import LogAnalyticsManagementClient

                la_client = session.get_client(LogAnalyticsManagementClient, sub_id)
                workspaces = list(la_client.workspaces.list())

                if not workspaces:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Log Analytics Workspaces",
                            description=(
                                f"Subscription {sub_id} hat keine Log Analytics Workspaces. "
                                "Ohne Workspaces fehlt der in diesem Check geprüfte Aufbewahrungspfad für Log-Daten."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.15 Logging",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.OperationalInsights/workspaces",
                            account_id=sub_id,
                            current_state={"workspaces": 0},
                            expected_state="Log Analytics Workspace mit Retention ≥ 365 Tage",
                            remediation=(
                                "Erstellen Sie einen Log Analytics Workspace: "
                                "az monitor log-analytics workspace create --resource-group <rg> "
                                "--workspace-name <name> --retention-time 365"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="workspaces.list() returned 0 workspaces",
                        )
                    )
                    continue

                for ws in workspaces:
                    explicit_retention = ws.retention_in_days
                    retention = explicit_retention if explicit_retention is not None else 30
                    if retention >= MIN_LOG_RETENTION_DAYS:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Log Retention ausreichend",
                                description=(
                                    f"Log Analytics Workspace {ws.name} hat {retention} Tage "
                                    f"Retention (Minimum: {MIN_LOG_RETENTION_DAYS})."
                                ),
                                region=ws.location or "global",
                                resource_id=ws.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.OperationalInsights/workspaces",
                                account_id=sub_id,
                                current_state={"retention_in_days": retention},
                                expected_state=f"Retention ≥ {MIN_LOG_RETENTION_DAYS} Tage",
                                audit_evidence=f"workspaces: {ws.name} retention_in_days={retention}",
                                iso27001_control="A.8.15 Logging",
                            )
                        )
                    elif explicit_retention is None:
                        # B-Nr.6-9: no explicit retention configured — the 30-day Azure
                        # default is an assumption, not an observed value; say so.
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Log Retention unter 365 Tage",
                                description=(
                                    f"Log Analytics Workspace {ws.name} in "
                                    f"Subscription {sub_id} hat keine explizite Retention "
                                    f"konfiguriert (Azure-Standard: 30 Tage)."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.15 Logging",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AZURE,
                                region=ws.location or "global",
                                resource_id=ws.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.OperationalInsights/workspaces",
                                account_id=sub_id,
                                current_state={"retention_in_days": None, "assumed_default_days": 30},
                                expected_state=f"Retention ≥ {MIN_LOG_RETENTION_DAYS} Tage",
                                remediation=(
                                    f"Erhöhen Sie die Retention: "
                                    f"az monitor log-analytics workspace update "
                                    f"--resource-group <rg> --workspace-name {ws.name} "
                                    f"--retention-time {MIN_LOG_RETENTION_DAYS}"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"workspaces: {ws.name} retention_in_days=None (Azure default 30)",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Log Retention unter 365 Tage",
                                description=(
                                    f"Log Analytics Workspace {ws.name} in "
                                    f"Subscription {sub_id} hat nur "
                                    f"{retention} Tage Retention."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.15 Logging",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AZURE,
                                region=ws.location or "global",
                                resource_id=ws.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.OperationalInsights/workspaces",
                                account_id=sub_id,
                                current_state={"retention_in_days": retention},
                                expected_state=f"Retention ≥ {MIN_LOG_RETENTION_DAYS} Tage",
                                remediation=(
                                    f"Erhöhen Sie die Retention: "
                                    f"az monitor log-analytics workspace update "
                                    f"--resource-group <rg> --workspace-name {ws.name} "
                                    f"--retention-time {MIN_LOG_RETENTION_DAYS}"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"workspaces: {ws.name} retention_in_days={retention}",
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


class CheckDiagnosticSettings(BaseCheck):
    """Check that Diagnostic Settings are configured on critical resources."""

    check_id = "AZ-NR6-004"
    title = "Diagnostic Settings auf kritischen Ressourcen"
    description = "Prüft ob Diagnostic Settings auf kritischen Ressourcen konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Insights/diagnosticSettings/read",
        "Microsoft.Resources/subscriptions/resources/read",
    ]
    pruefgrenzen = (
        "Prüft Diagnostic Settings nur auf den erfassten Ressourcentypen: KeyVault-Vaults, "
        "SQL-Server, Storage-Accounts und Network-Security-Groups. Welche Ressourcen als "
        "kritisch gelten, ist eine organisatorische Festlegung."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.monitor import MonitorManagementClient
                from azure.mgmt.resource.resources import ResourceManagementClient

                resource_client = session.get_client(ResourceManagementClient, sub_id)
                monitor_client = session.get_client(MonitorManagementClient, sub_id)

                # Find critical resources
                critical_resources = [r for r in resource_client.resources.list() if r.type in CRITICAL_RESOURCE_TYPES]

                resources_without_diag = []
                failed_resource_ids: list[str] = []
                resources_checked = 0
                for resource in critical_resources:
                    try:
                        settings = list(monitor_client.diagnostic_settings.list(resource_uri=resource.id))
                        resources_checked += 1
                        if not settings:
                            resources_without_diag.append({"name": resource.name, "type": resource.type})
                    except Exception:
                        failed_resource_ids.append(resource.id)

                if failed_resource_ids:
                    # B-Nr.6-10: failed per-resource queries used to be swallowed
                    # silently — surface them so the scan result stays honest about
                    # what could not be verified (ADR-0016).
                    failed_summary = ", ".join(failed_resource_ids[:5])
                    errors.append(
                        CheckError(
                            check_id=self.check_id,
                            error_type="DiagnosticSettingsQueryFailed",
                            message=(
                                f"{len(failed_resource_ids)} von {len(critical_resources)} "
                                f"Diagnostic-Settings-Abfragen in Subscription {sub_id} fehlgeschlagen: "
                                f"{failed_summary}{'...' if len(failed_resource_ids) > 5 else ''}"
                            ),
                            region="global",
                        )
                    )

                if critical_resources and resources_checked == len(critical_resources) and not resources_without_diag:
                    # Positive evidence only when every critical resource was verifiable (ADR-0016)
                    findings.append(
                        compliant_finding(
                            self,
                            title="Kritische Ressourcen mit Diagnostic Settings",
                            description=(
                                f"Alle {len(critical_resources)} kritischen Ressourcen in "
                                f"Subscription {sub_id} haben Diagnostic Settings konfiguriert."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/diagnosticSettings",
                            account_id=sub_id,
                            current_state={
                                "critical_resources_total": len(critical_resources),
                                "without_diagnostic_settings": 0,
                            },
                            expected_state="Alle kritischen Ressourcen mit Diagnostic Settings",
                            audit_evidence=(
                                f"Checked {resources_checked}/{len(critical_resources)} critical resources, "
                                f"all with settings"
                            ),
                            iso27001_control="A.5.35, A.8.15 Logging und Überprüfung",
                        )
                    )
                elif resources_without_diag:
                    resource_summary = ", ".join(
                        f"{r['name']} ({r['type'].split('/')[-1]})" for r in resources_without_diag[:5]
                    )
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kritische Ressourcen ohne Diagnostic Settings",
                            description=(
                                f"Subscription {sub_id} hat "
                                f"{len(resources_without_diag)} kritische Ressourcen ohne "
                                f"Diagnostic Settings: {resource_summary}"
                                f"{'...' if len(resources_without_diag) > 5 else ''}."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35, A.8.15 Logging und Überprüfung",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/diagnosticSettings",
                            account_id=sub_id,
                            current_state={
                                "critical_resources_total": len(critical_resources),
                                "without_diagnostic_settings": len(resources_without_diag),
                                # resource_summary above interpolates resource names
                                # (Key Vaults, SQL servers, storage accounts, NSGs)
                                # into the description; resource_id/account_id here
                                # only cover the subscription. Suffix key (ADR-0011)
                                # so the names get pseudonymized.
                                "resource_without_diag_name": [r["name"] for r in resources_without_diag],
                            },
                            expected_state="Alle kritischen Ressourcen mit Diagnostic Settings",
                            remediation=(
                                "Konfigurieren Sie Diagnostic Settings für jede kritische Ressource: "
                                "az monitor diagnostic-settings create --resource <resource-id> "
                                "--name <diag-name> --workspace <workspace-id>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"Checked {resources_checked}/{len(critical_resources)} critical resources, "
                                f"{len(resources_without_diag)} without diagnostic settings"
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
