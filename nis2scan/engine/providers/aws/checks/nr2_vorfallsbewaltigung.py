"""§30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for AWS.

Checks GuardDuty enablement and CloudWatch alarm configuration.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 2
BSIG_30_TEXT = "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"
ISO_CONTROL = "A.5.24-A.5.28 Incident management"


class CheckGuardDutyEnabled(BaseCheck):
    """Check that Amazon GuardDuty is enabled in the account region."""

    check_id = "AWS-NR2-001"
    title = "GuardDuty Aktivierung"
    description = (
        "Prüft ob Amazon GuardDuty in der Region aktiviert ist, um "
        "Bedrohungserkennung für AWS-Ressourcen zu gewährleisten."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["guardduty:ListDetectors", "guardduty:GetDetector"]
    pruefgrenzen = (
        "Prüft nur den Detector-Status je Region. Nicht geprüft werden aktivierte "
        "Schutzmodule und ob GuardDuty-Befunde in einen Incident-Prozess münden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                gd = session.client("guardduty", region=region)

                try:
                    detectors = gd.list_detectors().get("DetectorIds", [])

                    if not detectors:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="GuardDuty nicht aktiviert",
                                description=(
                                    f"Amazon GuardDuty ist in der Region {region} nicht aktiviert. "
                                    f"Ohne GuardDuty fehlt die automatische Bedrohungserkennung "
                                    f"für AWS-Ressourcen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.CRITICAL,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:guardduty:{region}:{session.account_id}:detector/*",
                                resource_type="AWS::GuardDuty::Detector",
                                account_id=session.account_id,
                                current_state={"guardduty_enabled": False},
                                expected_state="GuardDuty Detector Status=ENABLED",
                                remediation=(
                                    "Aktivieren Sie Amazon GuardDuty: "
                                    "aws guardduty create-detector --enable "
                                    "--finding-publishing-frequency FIFTEEN_MINUTES"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"ListDetectors returned 0 detectors in {region}",
                            )
                        )
                    else:
                        for detector_id in detectors:
                            try:
                                detector = gd.get_detector(DetectorId=detector_id)
                                status = detector.get("Status", "DISABLED")
                                if status == "ENABLED":
                                    findings.append(
                                        compliant_finding(
                                            self,
                                            title="GuardDuty aktiviert",
                                            description=(
                                                f"Amazon GuardDuty ist in der Region {region} aktiviert "
                                                f"und liefert Bedrohungserkennung für die Vorfallsbewältigung."
                                            ),
                                            region=region,
                                            resource_id=(
                                                f"arn:aws:guardduty:{region}:{session.account_id}"
                                                f":detector/{detector_id}"
                                            ),
                                            resource_type="AWS::GuardDuty::Detector",
                                            account_id=session.account_id,
                                            current_state={"status": status, "detector_id": detector_id},
                                            expected_state="GuardDuty Detector Status=ENABLED",
                                            audit_evidence=f"GetDetector: Status=ENABLED in {region}",
                                            iso27001_control=ISO_CONTROL,
                                        )
                                    )
                                else:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title="GuardDuty Detector deaktiviert",
                                            description=(
                                                f"Der GuardDuty Detector in Region {region} "
                                                f"hat den Status '{status}' statt 'ENABLED'."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control=ISO_CONTROL,
                                            severity=Severity.CRITICAL,
                                            provider=CloudProvider.AWS,
                                            region=region,
                                            resource_id=f"arn:aws:guardduty:{region}:{session.account_id}:detector/{detector_id}",
                                            resource_type="AWS::GuardDuty::Detector",
                                            account_id=session.account_id,
                                            current_state={"status": status},
                                            expected_state="GuardDuty Detector Status=ENABLED",
                                            remediation=(
                                                "Aktivieren Sie den GuardDuty Detector: "
                                                "aws guardduty update-detector --detector-id <id> --enable"
                                            ),
                                            remediation_effort="LOW",
                                            audit_evidence=f"GetDetector: Status={status}",
                                        )
                                    )
                            except Exception as e:
                                errors.append(
                                    CheckError(
                                        message=(f"GuardDuty Detector {detector_id} Check fehlgeschlagen: {e}"),
                                        error_type="AWSClientError",
                                    )
                                )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"GuardDuty Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"GuardDuty Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCloudWatchAlarms(BaseCheck):
    """Check that CloudWatch Alarms are configured for monitoring."""

    check_id = "AWS-NR2-004"
    title = "CloudWatch Alarms Konfiguration"
    description = (
        "Prüft ob CloudWatch Alarms konfiguriert sind, um auf Sicherheitsvorfälle und Anomalien reagieren zu können."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["cloudwatch:DescribeAlarms"]
    pruefgrenzen = (
        "Prüft nur, ob überhaupt mindestens ein CloudWatch-Alarm existiert. "
        "Nicht geprüft werden Abdeckung sicherheitsrelevanter Metriken, "
        "Alarmziele (Benachrichtigungswege) und ob Alarme funktionieren."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                cw = session.client("cloudwatch", region=region)

                try:
                    alarms = cw.describe_alarms(MaxRecords=1).get("MetricAlarms", [])
                    composite: list[dict[str, Any]] = []
                    if not alarms:
                        # Also check composite alarms
                        composite = cw.describe_alarms(AlarmTypes=["CompositeAlarm"], MaxRecords=1).get(
                            "CompositeAlarms", []
                        )

                    if alarms or composite:
                        first_alarm = (alarms or composite)[0]
                        findings.append(
                            compliant_finding(
                                self,
                                title="CloudWatch Alarms konfiguriert",
                                description=(
                                    f"In der Region {region} ist mindestens ein CloudWatch Alarm "
                                    f"konfiguriert — eine technische Alarmierungsgrundlage ist vorhanden."
                                ),
                                region=region,
                                resource_id=first_alarm.get(
                                    "AlarmArn", f"arn:aws:cloudwatch:{region}:{session.account_id}:alarm:*"
                                ),
                                resource_type="AWS::CloudWatch::Alarm",
                                account_id=session.account_id,
                                current_state={"alarms_configured": True},
                                expected_state=(
                                    "Mindestens ein CloudWatch Alarm (Metric- oder Composite-Alarm) konfiguriert"
                                ),
                                audit_evidence=f"DescribeAlarms returned >=1 alarm in {region}",
                                iso27001_control=ISO_CONTROL,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Keine CloudWatch Alarms konfiguriert",
                                description=(
                                    f"In der Region {region} sind keine CloudWatch Alarms "
                                    f"konfiguriert. Ohne Alarms fehlt die automatische "
                                    f"Benachrichtigung bei Sicherheitsvorfällen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:cloudwatch:{region}:{session.account_id}:alarm:*",
                                resource_type="AWS::CloudWatch::Alarm",
                                account_id=session.account_id,
                                current_state={"alarms_configured": 0},
                                expected_state=(
                                    "Mindestens ein CloudWatch Alarm (Metric- oder Composite-Alarm) konfiguriert"
                                ),
                                remediation=(
                                    "Erstellen Sie CloudWatch Alarms für kritische Metriken wie "
                                    "unerlaubte API-Aufrufe, Root-Account-Nutzung und Billing-Anomalien."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=f"DescribeAlarms returned 0 alarms in {region}",
                            )
                        )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"CloudWatch Alarms Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"CloudWatch Alarms Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecurityHubFindings(BaseCheck):
    """Check that AWS Security Hub is enabled and aggregating findings."""

    check_id = "AWS-NR2-002"
    title = "Security Hub Findings Aggregation"
    description = "Prüft ob AWS Security Hub aktiviert ist und Sicherheitsbefunde zentral aggregiert."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["securityhub:GetFindings"]
    pruefgrenzen = (
        "Prüft nur, ob Security Hub aktiviert und die Findings-API erfolgreich aufrufbar ist. "
        "Nicht geprüft werden Multi-Account-Aggregation und ob Befunde "
        "triagiert und behoben werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                sh_client = session.client("securityhub", region=region)

                try:
                    sh_client.get_findings(MaxResults=1)
                    # Security Hub is enabled — positive evidence (ADR-0006)
                    findings.append(
                        compliant_finding(
                            self,
                            title="Security Hub aggregiert Befunde",
                            description=(
                                f"AWS Security Hub ist in der Region {region} aktiviert "
                                f"und aggregiert Sicherheitsbefunde zentral."
                            ),
                            region=region,
                            resource_id=f"arn:aws:securityhub:{region}:{session.account_id}:hub/default",
                            resource_type="AWS::SecurityHub::Hub",
                            account_id=session.account_id,
                            current_state={"securityhub_enabled": True},
                            expected_state="Security Hub aktiviert mit zentraler Befundaggregation",
                            audit_evidence=f"GetFindings succeeded in {region}",
                            iso27001_control="A.5.25",
                        )
                    )
                except sh_client.exceptions.InvalidAccessException:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Security Hub nicht aktiviert",
                            description=(
                                f"AWS Security Hub ist in der Region "
                                f"{region} nicht aktiviert. Ohne "
                                f"Security Hub fehlt die zentrale "
                                f"Aggregation von Sicherheitsbefunden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.25",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:securityhub:{region}:{session.account_id}:hub/default"),
                            resource_type="AWS::SecurityHub::Hub",
                            account_id=session.account_id,
                            current_state={
                                "securityhub_enabled": False,
                            },
                            expected_state=("Security Hub aktiviert mit zentraler Befundaggregation"),
                            remediation=("Aktivieren Sie AWS Security Hub: aws securityhub enable-security-hub"),
                            remediation_effort="LOW",
                            audit_evidence=(f"GetFindings raised InvalidAccessException in {region}"),
                        )
                    )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=(f"Security Hub Check in {region} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"Security Hub Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckDetectiveEnabled(BaseCheck):
    """Check that Amazon Detective is enabled for forensic analysis.

    Detective provides automated security investigation capabilities
    to analyze, investigate, and identify root causes of security findings.
    """

    check_id = "AWS-NR2-005"
    title = "Detective Aktivierung (Forensik)"
    description = (
        "Prüft ob Amazon Detective für forensische Analysen aktiviert ist, "
        "um Sicherheitsvorfälle untersuchen und Ursachen identifizieren zu können."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["detective:ListGraphs"]
    pruefgrenzen = (
        "Prüft nur, ob ein Detective-Verhaltensgraph existiert. Nicht geprüft wird, "
        "ob Detective bei Vorfällen tatsächlich zur Ursachenanalyse genutzt wird. "
        "Detective ist eine von mehreren möglichen Forensik-Lösungen — der Einsatz "
        "eines anderen Werkzeugs wird nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                detective = session.client("detective", region=region)

                try:
                    graphs = detective.list_graphs().get("GraphList", [])

                    if graphs:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Detective aktiviert",
                                description=(
                                    f"Amazon Detective ist in der Region {region} aktiviert — "
                                    f"forensische Analyse von Sicherheitsvorfällen ist möglich."
                                ),
                                region=region,
                                resource_id=graphs[0].get(
                                    "Arn", f"arn:aws:detective:{region}:{session.account_id}:graph/*"
                                ),
                                resource_type="AWS::Detective::Graph",
                                account_id=session.account_id,
                                current_state={"detective_enabled": True, "graphs": len(graphs)},
                                expected_state="Amazon Detective aktiviert mit mindestens einem Behavior Graph",
                                audit_evidence=f"ListGraphs returned {len(graphs)} graph(s) in {region}",
                                iso27001_control="A.5.27 Learning from information security incidents",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Detective nicht aktiviert",
                                description=(
                                    f"Amazon Detective ist in der Region {region} nicht aktiviert. "
                                    f"Ohne Detective fehlt die AWS-native automatisierte forensische "
                                    f"Analysefähigkeit zur Untersuchung von Sicherheitsvorfällen; ein "
                                    f"anderes eingesetztes Forensik-Werkzeug wird von dieser Prüfung "
                                    f"nicht erkannt."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.27 Learning from information security incidents",
                                severity=Severity.LOW,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:detective:{region}:{session.account_id}:graph/*",
                                resource_type="AWS::Detective::Graph",
                                account_id=session.account_id,
                                current_state={"detective_enabled": False, "graphs": 0},
                                expected_state="Amazon Detective aktiviert mit mindestens einem Behavior Graph",
                                remediation=(
                                    "Aktivieren Sie Amazon Detective: "
                                    "aws detective create-graph. Detective benötigt "
                                    "GuardDuty als Datenquelle."
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"ListGraphs returned 0 graphs in {region}",
                            )
                        )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"Detective Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Detective Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIncidentManagerResponsePlans(BaseCheck):
    """Check that Incident Manager Response Plans are configured."""

    check_id = "AWS-NR2-003"
    title = "Incident Manager Response Plans"
    description = "Prüft ob AWS Systems Manager Incident Manager mit Response Plans konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ssm-incidents:ListResponsePlans"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Response Plans im AWS Incident Manager. "
        "Ein außerhalb von AWS geführter Incident-Response-Plan wird nicht erkannt — "
        "dieser ist über die Attestierungs-Checkliste nachzuweisen."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                incidents_client = session.client("ssm-incidents", region=region)

                try:
                    response = incidents_client.list_response_plans()
                    plans = response.get("responsePlanSummaries", [])

                    if plans:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Incident Manager Response Plans konfiguriert",
                                description=(
                                    f"In der Region {region} sind {len(plans)} Incident Manager "
                                    f"Response Plans konfiguriert — ein strukturierter Reaktionsablauf "
                                    f"ist in AWS Incident Manager hinterlegt."
                                ),
                                region=region,
                                resource_id=plans[0].get(
                                    "arn", f"arn:aws:ssm-incidents:{region}:{session.account_id}:response-plan/*"
                                ),
                                resource_type="AWS::SSMIncidents::ResponsePlan",
                                account_id=session.account_id,
                                current_state={"response_plans": len(plans)},
                                expected_state="Mindestens ein Incident Manager Response Plan konfiguriert",
                                audit_evidence=f"ListResponsePlans returned {len(plans)} plan(s) in {region}",
                                iso27001_control="A.5.26",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title=("Keine Incident Manager Response Plans"),
                                description=(
                                    f"In der Region {region} sind keine Incident Manager Response Plans "
                                    f"konfiguriert. Damit ist in AWS Incident Manager kein strukturierter "
                                    f"Reaktionsablauf hinterlegt; ein außerhalb von AWS geführter "
                                    f"Incident-Response-Plan wird von dieser Prüfung nicht erkannt."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.26",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=(f"arn:aws:ssm-incidents:{region}:{session.account_id}:response-plan/*"),
                                resource_type=("AWS::SSMIncidents::ResponsePlan"),
                                account_id=session.account_id,
                                current_state={
                                    "response_plans": 0,
                                },
                                expected_state=("Mindestens ein Incident Manager Response Plan konfiguriert"),
                                remediation=(
                                    "Erstellen Sie einen "
                                    "Incident Manager Response "
                                    "Plan: aws ssm-incidents "
                                    "create-response-plan "
                                    "--name <plan-name>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(f"ListResponsePlans returned 0 plans in {region}"),
                            )
                        )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=(f"Incident Manager Check in {region} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"Incident Manager Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
