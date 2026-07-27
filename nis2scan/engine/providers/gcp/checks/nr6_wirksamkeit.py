"""§30 Abs. 2 Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen checks for GCP.

Checks Cloud Logging Sinks, Security Command Center Health Analytics,
IAM Policy Intelligence (Recommender), and Monitoring Dashboards.
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


class CheckAuditLogIntegrity(BaseCheck):
    """Prüft ob Log-Sinks in einen Storage-Bucket exportieren (Grundlage für unveränderliche Audit-Logs)."""

    check_id = "GCP-NR6-001"
    title = "Audit-Log-Export in Storage-Bucket"
    description = (
        "Prüft ob Cloud Logging Sinks Logs in einen Storage-Bucket exportieren — "
        "Grundlage für unveränderliche Audit-Logs. Die Sperrung der "
        "Aufbewahrungsrichtlinie des Ziel-Buckets wird nicht geprüft."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["logging.sinks.list"]
    pruefgrenzen = (
        "Prüft nur, ob ein Log-Sink in einen Storage-Bucket exportiert. Ob dessen "
        "Aufbewahrungsrichtlinie gesperrt ist, wird nicht geprüft; andere "
        "Integritätssicherungen werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client

                client = ConfigServiceV2Client(
                    credentials=session.credentials,
                )
                sinks = list(
                    client.list_sinks(
                        request={"parent": f"projects/{project_id}"},
                    )
                )

                # B-Nr.6-11: count storage-bucket-destined sinks instead of stopping
                # at the first match, so the positive finding carries a real count.
                storage_bucket_sink_count = sum(
                    1 for sink in sinks if "storage.googleapis.com/" in (sink.destination or "")
                )

                if storage_bucket_sink_count > 0:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Log-Sink mit Storage-Bucket-Export vorhanden",
                            description=(
                                f"Projekt {project_id} exportiert Logs über mindestens einen "
                                f"Sink in einen Storage-Bucket — Grundlage für unveränderliche "
                                f"Audit-Logs."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/sinks",
                            resource_type="gcp.logging.Sink",
                            account_id=project_id,
                            current_state={
                                "total_sinks": len(sinks),
                                "storage_bucket_sinks": storage_bucket_sink_count,
                            },
                            expected_state="Mindestens ein Log-Sink mit Export in einen Storage-Bucket",
                            audit_evidence=(
                                f"list_sinks() returned {len(sinks)} sink(s), >=1 with storage destination"
                            ),
                            iso27001_control="A.5.35 Unabhängige Überprüfung, A.8.15 Logging",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Log-Sink mit Storage-Bucket-Export",
                            description=(
                                f"Projekt {project_id} hat keinen Logging-Sink, der Logs in einen "
                                f"Storage-Bucket exportiert. Ohne Log-Export in einen Storage-Bucket "
                                f"fehlt die Grundlage für unveränderliche Audit-Logs."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung, A.8.15 Logging",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/sinks",
                            resource_type="gcp.logging.Sink",
                            account_id=project_id,
                            current_state={
                                "total_sinks": len(sinks),
                                "storage_bucket_sinks": 0,
                            },
                            expected_state="Mindestens ein Log-Sink mit Export in einen Storage-Bucket",
                            remediation=(
                                "Erstellen Sie einen Log-Sink mit gesperrtem Bucket:\n"
                                "1. gcloud storage buckets create gs://<BUCKET_NAME> "
                                "--retention-period=2592000 --locked\n"
                                "2. gcloud logging sinks create <SINK_NAME> "
                                "storage.googleapis.com/<BUCKET_NAME> "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"list_sinks() returned {len(sinks)} sinks, none with storage bucket destination"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecurityHealthAnalytics(BaseCheck):
    """Prüft ob SCC Security Health Analytics aktiviert und zugänglich ist."""

    check_id = "GCP-NR6-002"
    title = "Security Command Center zugänglich"
    description = "Prüft ob die Security-Command-Center-Findings-API des Projekts zugänglich ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["securitycenter.findings.list"]
    pruefgrenzen = (
        "Prüft nur, ob die SCC-Findings-API erreichbar ist. Welche Quelle (z. B. "
        "Security Health Analytics) Findings liefert, wird nicht unterschieden. Nur "
        "eindeutige Deaktivierungssignale in der Fehlermeldung (z. B. "
        "'accessNotConfigured', 'not enabled', 'disabled') werden als Mangel "
        "gewertet; ein generisches PERMISSION_DENIED ohne dieses Signal führt zu "
        "einem Scan-Fehler statt einem Mangel-Finding."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import securitycenter_v1

                client = securitycenter_v1.SecurityCenterClient(
                    credentials=session.credentials,
                )
                # Try listing findings to verify SCC is enabled
                request = securitycenter_v1.ListFindingsRequest(
                    parent=f"projects/{project_id}/sources/-",
                )
                result = client.list_findings(request=request)
                # If we get here, SCC is enabled — iterate to check
                finding_count = sum(1 for _ in result)

                logger.info(
                    "scc.health_analytics.accessible",
                    project=project_id,
                    finding_count=finding_count,
                )
                findings.append(
                    compliant_finding(
                        self,
                        title="Security Command Center API zugänglich",
                        description=(
                            f"Projekt {project_id}: SCC-Findings-API ist zugänglich "
                            f"({finding_count} Finding(s) abrufbar) — technische Grundlage für "
                            f"automatisierte Wirksamkeitsbewertung vorhanden."
                        ),
                        region="global",
                        resource_id=f"projects/{project_id}/securitycenter",
                        resource_type="gcp.securitycenter.Findings",
                        account_id=project_id,
                        current_state={"scc_accessible": True, "finding_count": finding_count},
                        expected_state="Security Command Center API aktiviert und zugänglich",
                        audit_evidence=f"list_findings() succeeded with {finding_count} finding(s)",
                        iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                    )
                )
            except Exception as exc:
                # B-Nr.6-13(ii): only unambiguous deactivation signals count as a
                # defect. A bare PERMISSION_DENIED/403 could mean many things
                # (wrong role, org policy, transient auth issue) — that is a scan
                # error, not evidence that SCC is disabled.
                error_msg = str(exc).lower()
                disabled_signals = (
                    "accessnotconfigured",
                    "has not been used in project",
                    "not enabled",
                    "disabled",
                )
                if any(signal in error_msg for signal in disabled_signals):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Security Command Center nicht zugänglich",
                            description=(
                                f"Projekt {project_id} hat kein "
                                "zugängliches Security Command Center. Ohne SCC "
                                "fehlt die automatische Bewertung der Wirksamkeit "
                                "von Sicherheitsmaßnahmen."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/securitycenter",
                            resource_type="gcp.securitycenter.Findings",
                            account_id=project_id,
                            current_state={"scc_accessible": False, "error": str(exc)[:200]},
                            expected_state="Security Command Center API aktiviert und zugänglich",
                            remediation=(
                                "Aktivieren Sie das Security Command Center:\n"
                                "gcloud scc settings update --project=<PROJECT_ID> "
                                "--enable-scc\n"
                                "Oder aktivieren Sie SCC Premium in der Google Cloud Console "
                                "unter Sicherheit > Security Command Center."
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"SCC API returned error: {type(exc).__name__}",
                        )
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckPolicyIntelligence(BaseCheck):
    """Prüft ob IAM Policy Intelligence (Recommender) aktiviert ist."""

    check_id = "GCP-NR6-003"
    title = "IAM Policy Intelligence aktiviert"
    description = "Prüft ob die IAM-Recommender-API aktiviert und zugänglich ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["recommender.iamPolicyRecommendations.list"]
    pruefgrenzen = (
        "Prüft nur, ob die Recommender-API zugänglich ist. Ob Empfehlungen umgesetzt werden, wird "
        "nicht bewertet. Nur eindeutige Deaktivierungssignale in der Fehlermeldung (z. B. "
        "'accessNotConfigured', 'not enabled', 'disabled') werden als Mangel gewertet; ein "
        "generisches PERMISSION_DENIED ohne dieses Signal führt zu einem Scan-Fehler statt einem "
        "Mangel-Finding."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("recommender", "v1")
                result = (
                    service.projects()
                    .locations()
                    .recommenders()
                    .recommendations()
                    .list(
                        parent=(f"projects/{project_id}/locations/-/recommenders/google.iam.policy.Recommender"),
                    )
                    .execute()
                )
                recommendations = result.get("recommendations", [])
                logger.info(
                    "recommender.iam_policy.accessible",
                    project=project_id,
                    recommendation_count=len(recommendations),
                )
                findings.append(
                    compliant_finding(
                        self,
                        title="IAM Policy Intelligence aktiviert",
                        description=(
                            f"Projekt {project_id} hat einen zugänglichen IAM Recommender "
                            f"({len(recommendations)} aktuelle Empfehlung(en))."
                        ),
                        region="global",
                        resource_id=f"projects/{project_id}/recommender",
                        resource_type="gcp.recommender.Recommendation",
                        account_id=project_id,
                        current_state={
                            "recommender_api_enabled": True,
                            "recommendation_count": len(recommendations),
                        },
                        expected_state="IAM Recommender API aktiviert und zugänglich",
                        audit_evidence=(
                            f"recommendations.list() succeeded with {len(recommendations)} recommendation(s)"
                        ),
                        iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                    )
                )
            except Exception as exc:
                # B-Nr.6-13(ii): same unified classification as GCP-NR6-002 — only
                # unambiguous deactivation signals count as a defect.
                error_msg = str(exc).lower()
                disabled_signals = (
                    "accessnotconfigured",
                    "has not been used in project",
                    "not enabled",
                    "disabled",
                )
                if any(signal in error_msg for signal in disabled_signals):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAM Policy Intelligence nicht aktiviert",
                            description=(
                                f"Projekt {project_id} hat keinen "
                                "zugänglichen IAM Recommender. Ohne Policy Intelligence "
                                "fehlen automatische Empfehlungen zur Verbesserung "
                                "der Zugriffskontrollrichtlinien."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/recommender",
                            resource_type="gcp.recommender.Recommendation",
                            account_id=project_id,
                            current_state={"recommender_api_enabled": False},
                            expected_state=("IAM Recommender API aktiviert und zugänglich"),
                            remediation=(
                                "Aktivieren Sie die Recommender API:\n"
                                "gcloud services enable recommender.googleapis.com "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"Recommender API returned error: {type(exc).__name__}",
                        )
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckMonitoringDashboards(BaseCheck):
    """Prüft ob benutzerdefinierte Monitoring-Dashboards existieren."""

    check_id = "GCP-NR6-004"
    title = "Monitoring-Dashboards vorhanden"
    description = (
        "Prüft ob benutzerdefinierte Cloud Monitoring Dashboards "
        "eingerichtet sind, um die Wirksamkeit von Sicherheitsmaßnahmen "
        "visuell zu überwachen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["monitoring.dashboards.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Monitoring-Dashboards. Ob sie "
        "sicherheitsrelevante Inhalte zeigen, wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("monitoring", "v1")
                result = service.projects().dashboards().list(parent=f"projects/{project_id}").execute()
                dashboards = result.get("dashboards", [])

                if dashboards:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Monitoring-Dashboards vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(dashboards)} benutzerdefinierte(s) Cloud "
                                f"Monitoring Dashboard(s). Ob sie sicherheitsrelevante Inhalte zeigen, wird "
                                f"nicht bewertet (siehe Prüfgrenzen)."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/dashboards",
                            resource_type="gcp.monitoring.Dashboard",
                            account_id=project_id,
                            current_state={"dashboards": len(dashboards)},
                            expected_state="Mindestens ein benutzerdefiniertes Monitoring-Dashboard",
                            audit_evidence=f"dashboards.list() returned {len(dashboards)} dashboard(s)",
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Monitoring-Dashboards konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "benutzerdefinierten Cloud Monitoring Dashboards. "
                                "Ohne Dashboards fehlt die visuelle Überwachung "
                                "der Wirksamkeit von Sicherheitsmaßnahmen."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.LOW,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/dashboards",
                            resource_type="gcp.monitoring.Dashboard",
                            account_id=project_id,
                            current_state={"dashboards": 0},
                            expected_state="Mindestens ein benutzerdefiniertes Monitoring-Dashboard",
                            remediation=(
                                "Erstellen Sie ein Monitoring-Dashboard:\n"
                                "gcloud monitoring dashboards create "
                                "--config-from-file=dashboard.json "
                                "--project=<PROJECT_ID>\n"
                                "Empfohlen: Erstellen Sie Dashboards für IAM-Aktivitäten, "
                                "Netzwerk-Anomalien und Audit-Log-Metriken."
                            ),
                            remediation_effort="LOW",
                            audit_evidence="dashboards.list() returned 0 dashboards",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
