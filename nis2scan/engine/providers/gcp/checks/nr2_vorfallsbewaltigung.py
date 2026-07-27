"""§30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for GCP.

Checks SCC Notification Configs, Monitoring Alert Policies, Notification Channels,
Log-Based Metrics, and Logging Sinks.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 2
BSIG_30_TEXT = "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"


class CheckSccNotifications(BaseCheck):
    """Prüft ob SCC-Benachrichtigungskonfigurationen vorhanden sind."""

    check_id = "GCP-NR2-001"
    title = "SCC-Benachrichtigungen konfiguriert"
    description = (
        "Prüft ob Security Command Center Benachrichtigungskonfigurationen "
        "für die automatische Alarmierung bei Sicherheitsvorfällen eingerichtet sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["securitycenter.notificationconfig.list"]
    pruefgrenzen = (
        "Prüft nur konfigurierte SCC-Benachrichtigungen. Zustellung und Bearbeitung der Meldungen werden nicht geprüft."
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
                configs = list(
                    client.list_notification_configs(
                        request={"parent": f"projects/{project_id}"},
                    )
                )

                if configs:
                    findings.append(
                        compliant_finding(
                            self,
                            title="SCC-Benachrichtigungen konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(configs)} "
                                f"SCC-Benachrichtigungskonfiguration(en) für automatische Alarmierung."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.securitycenter.NotificationConfig",
                            account_id=project_id,
                            current_state={"notification_configs": len(configs)},
                            expected_state="Mindestens eine SCC-Benachrichtigungskonfiguration",
                            audit_evidence=f"list_notification_configs() returned {len(configs)} config(s)",
                            iso27001_control="A.5.24 Planung der Informationssicherheitsvorfallsreaktion",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine SCC-Benachrichtigungen konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "SCC-Benachrichtigungskonfigurationen. Ohne "
                                "Benachrichtigungen erfolgt bei Sicherheitsbefunden "
                                "keine automatische Alarmierung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24 Planung der Informationssicherheitsvorfallsreaktion",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.securitycenter.NotificationConfig",
                            account_id=project_id,
                            current_state={"notification_configs": 0},
                            expected_state="Mindestens eine SCC-Benachrichtigungskonfiguration",
                            remediation=(
                                "Erstellen Sie eine SCC-Benachrichtigung: "
                                "gcloud scc notifications create <NAME> "
                                "--project=<PROJECT_ID> "
                                "--pubsub-topic=projects/<PROJECT_ID>/topics/<TOPIC> "
                                "--filter='state=\"ACTIVE\"'"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="list_notification_configs() returned 0 configs",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckMonitoringAlertPolicies(BaseCheck):
    """Prüft ob Cloud Monitoring Alarmrichtlinien konfiguriert sind."""

    check_id = "GCP-NR2-002"
    title = "Monitoring-Alarmrichtlinien vorhanden"
    description = "Prüft ob Google Cloud Monitoring Alarmrichtlinien konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["monitoring.alertPolicies.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Alarmrichtlinien. Abdeckung sicherheitsrelevanter Metriken wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import monitoring_v3

                client = monitoring_v3.AlertPolicyServiceClient(
                    credentials=session.credentials,
                )
                policies = list(
                    client.list_alert_policies(
                        request={"name": f"projects/{project_id}"},
                    )
                )

                if policies:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Monitoring-Alarmrichtlinien vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(policies)} Cloud Monitoring "
                                f"Alarmrichtlinie(n) — eine technische Alarmierungsgrundlage ist vorhanden."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.monitoring.AlertPolicy",
                            account_id=project_id,
                            current_state={"alert_policies": len(policies)},
                            expected_state="Mindestens eine Cloud Monitoring Alarmrichtlinie konfiguriert",
                            audit_evidence=f"list_alert_policies() returned {len(policies)} policies",
                            iso27001_control="A.5.24, A.8.16 Überwachung von Aktivitäten",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Monitoring-Alarmrichtlinien vorhanden",
                            description=(
                                f"Projekt {project_id} hat keine Cloud Monitoring Alarmrichtlinien. "
                                "Ohne Alarmrichtlinien fehlt eine technische Alarmierungsgrundlage."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24, A.8.16 Überwachung von Aktivitäten",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.monitoring.AlertPolicy",
                            account_id=project_id,
                            current_state={"alert_policies": 0},
                            expected_state="Mindestens eine Cloud Monitoring Alarmrichtlinie konfiguriert",
                            remediation=(
                                "Erstellen Sie eine Alarmrichtlinie: "
                                "gcloud alpha monitoring policies create "
                                "--policy-from-file=alert-policy.json "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="list_alert_policies() returned 0 policies",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckNotificationChannels(BaseCheck):
    """Prüft ob Benachrichtigungskanäle in Cloud Monitoring konfiguriert sind."""

    check_id = "GCP-NR2-003"
    title = "Benachrichtigungskanäle konfiguriert"
    description = (
        "Prüft ob Benachrichtigungskanäle (E-Mail, PagerDuty, Slack etc.) in Cloud Monitoring eingerichtet sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["monitoring.notificationChannels.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Benachrichtigungskanälen. Erreichbarkeit der "
        "hinterlegten Kontakte wird nicht verifiziert."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import monitoring_v3

                client = monitoring_v3.NotificationChannelServiceClient(
                    credentials=session.credentials,
                )
                channels = list(
                    client.list_notification_channels(
                        request={"name": f"projects/{project_id}"},
                    )
                )

                if channels:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Benachrichtigungskanäle konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(channels)} Benachrichtigungskanal/-kanäle "
                                f"in Cloud Monitoring für die Alarmzustellung."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.monitoring.NotificationChannel",
                            account_id=project_id,
                            current_state={"notification_channels": len(channels)},
                            expected_state="Mindestens ein Benachrichtigungskanal konfiguriert",
                            audit_evidence=f"list_notification_channels() returned {len(channels)} channel(s)",
                            iso27001_control="A.5.24 Planung der Informationssicherheitsvorfallsreaktion",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Benachrichtigungskanäle konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Benachrichtigungskanäle in Cloud Monitoring. "
                                "Ohne Kanäle können Alarme nicht zugestellt werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24 Planung der Informationssicherheitsvorfallsreaktion",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.monitoring.NotificationChannel",
                            account_id=project_id,
                            current_state={"notification_channels": 0},
                            expected_state="Mindestens ein Benachrichtigungskanal konfiguriert",
                            remediation=(
                                "Erstellen Sie einen Benachrichtigungskanal: "
                                "gcloud alpha monitoring channels create "
                                "--type=email --display-name='Security Team' "
                                "--channel-labels=email_address=security@example.com "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="list_notification_channels() returned 0 channels",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckLogBasedAlerts(BaseCheck):
    """Prüft ob logbasierte Metriken für Sicherheitsereignisse existieren."""

    check_id = "GCP-NR2-004"
    title = "Logbasierte Metriken vorhanden"
    description = "Prüft ob logbasierte Metriken in Cloud Logging konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["logging.logMetrics.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz logbasierter Metriken. Ob sicherheitsrelevante "
        "Ereignisse abgedeckt sind, wird nicht inhaltlich bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.logging_v2.services.metrics_service_v2 import MetricsServiceV2Client

                client = MetricsServiceV2Client(
                    credentials=session.credentials,
                )
                metrics = list(
                    client.list_log_metrics(
                        request={"parent": f"projects/{project_id}"},
                    )
                )

                if metrics:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Logbasierte Metriken vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(metrics)} logbasierte Metrik(en) — "
                                f"Grundlage, um Log-Ereignisse in Alarme zu überführen."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.logging.LogMetric",
                            account_id=project_id,
                            current_state={"log_metrics": len(metrics)},
                            expected_state="Mindestens eine logbasierte Metrik in Cloud Logging konfiguriert",
                            audit_evidence=f"list_log_metrics() returned {len(metrics)} metric(s)",
                            iso27001_control="A.5.24, A.8.16 Überwachung von Aktivitäten",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine logbasierten Metriken vorhanden",
                            description=(
                                f"Projekt {project_id} hat keine logbasierten Metriken. Ohne Metriken "
                                "werden Log-Ereignisse nicht automatisch in Alarme umgewandelt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24, A.8.16 Überwachung von Aktivitäten",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.logging.LogMetric",
                            account_id=project_id,
                            current_state={"log_metrics": 0},
                            expected_state="Mindestens eine logbasierte Metrik in Cloud Logging konfiguriert",
                            remediation=(
                                "Erstellen Sie logbasierte Metriken: "
                                "gcloud logging metrics create iam-policy-changes "
                                "--description='IAM Policy Änderungen' "
                                "--log-filter='protoPayload.methodName=\"SetIamPolicy\"' "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="list_log_metrics() returned 0 metrics",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckLoggingSinks(BaseCheck):
    """Prüft ob ein benutzerdefinierter Log-Sink mit Export-Ziel konfiguriert ist.

    GCP creates the built-in sinks "_Required" and "_Default" in every project;
    their presence is not evidence of any deliberate export configuration, so
    they are excluded from the count.
    """

    check_id = "GCP-NR2-005"
    title = "Benutzerdefinierter Log-Export vorhanden"
    description = (
        "Prüft ob ein benutzerdefinierter Cloud Logging Sink mit Export-Ziel "
        "(z. B. Cloud Storage, BigQuery, Pub/Sub) konfiguriert ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["logging.sinks.list"]
    pruefgrenzen = (
        "Prüft nur, ob ein benutzerdefinierter Log-Sink mit Export-Ziel (Cloud Storage, "
        "BigQuery, Pub/Sub) existiert; die eingebauten Sinks _Required/_Default zählen "
        "nicht. Ob das Ziel ein SIEM ist, Aufbewahrungsfristen erfüllt oder die Logs "
        "ausgewertet werden, wird nicht geprüft."
    )

    _BUILTIN_SINK_NAMES = frozenset({"_Required", "_Default"})
    _EXPORT_DESTINATION_PREFIXES = (
        "storage.googleapis.com",
        "bigquery.googleapis.com",
        "pubsub.googleapis.com",
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

                custom_sinks = [s for s in sinks if getattr(s, "name", None) not in self._BUILTIN_SINK_NAMES]
                custom_export_sinks = [
                    s
                    for s in custom_sinks
                    if (getattr(s, "destination", "") or "").startswith(self._EXPORT_DESTINATION_PREFIXES)
                ]

                if custom_export_sinks:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Benutzerdefinierter Log-Export konfiguriert",
                            description=(
                                f"Projekt '{project_id}' hat {len(custom_export_sinks)} "
                                f"benutzerdefinierte(n) Log-Sink(s) mit Export-Ziel "
                                f"(z. B. Cloud Storage, BigQuery, Pub/Sub)."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.logging.LogSink",
                            account_id=project_id,
                            current_state={
                                "log_sinks_total": len(sinks),
                                "custom_export_sinks": len(custom_export_sinks),
                            },
                            expected_state=(
                                "Mindestens ein benutzerdefinierter Log-Sink mit Export-Ziel "
                                "(z. B. Cloud Storage, BigQuery, Pub/Sub)"
                            ),
                            audit_evidence=(
                                f"list_sinks() returned {len(sinks)} sink(s), "
                                f"{len(custom_export_sinks)} custom with export destination "
                                f"(built-in _Required/_Default excluded)"
                            ),
                            iso27001_control="A.5.25 Bewertung und Entscheidung zu Informationssicherheitsereignissen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein benutzerdefinierter Log-Export",
                            description=(
                                f"Projekt '{project_id}' hat keinen benutzerdefinierten Log-Sink mit "
                                "Export-Ziel (Cloud Storage, BigQuery, Pub/Sub). Ein Log-Export an "
                                "diese Ziele — etwa für Langzeitaufbewahrung oder externe Auswertung — "
                                "ist damit nicht konfiguriert; anderweitige Sink-Ziele (z. B. zentrale "
                                "Log-Buckets) werden von dieser Prüfung nicht als Export gewertet."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.25 Bewertung und Entscheidung zu Informationssicherheitsereignissen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.logging.LogSink",
                            account_id=project_id,
                            current_state={
                                "log_sinks_total": len(sinks),
                                "custom_sinks": len(custom_sinks),
                                "custom_export_sinks": 0,
                            },
                            expected_state=(
                                "Mindestens ein benutzerdefinierter Log-Sink mit Export-Ziel "
                                "(z. B. Cloud Storage, BigQuery, Pub/Sub)"
                            ),
                            remediation=(
                                "Erstellen Sie einen benutzerdefinierten Log-Sink mit Export-Ziel: "
                                "gcloud logging sinks create export-sink "
                                "storage.googleapis.com/<BUCKET_NAME> "
                                "--project=<PROJECT_ID> "
                                "--log-filter='severity>=WARNING'"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"list_sinks() returned {len(sinks)} sink(s), 0 custom with export "
                                f"destination (built-in _Required/_Default excluded)"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
