"""§30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for AWS.

Checks CloudTrail configuration for audit trail and log integrity.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 1
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
)
ISO_CONTROL = "A.8.15 Logging"


class CheckCloudTrail(BaseCheck):
    """Check that CloudTrail is active with log file validation enabled."""

    check_id = "AWS-NR1-004"
    title = "CloudTrail Log-Integrität"
    description = "Prüft ob mindestens ein CloudTrail aktiv ist und Log-File-Validation aktiviert hat."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]
    pruefgrenzen = (
        "Prüft nur Existenz, Logging-Status und Log-File-Validation der Trails. "
        "Nicht geprüft werden Vollständigkeit der aufgezeichneten Events, "
        "S3-Bucket-Schutz der Logs und ob die Logs tatsächlich ausgewertet werden. "
        "Nicht geprüft wird, ob der Trail alle Regionen abdeckt (Multi-Region)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

            if not trails:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Kein CloudTrail konfiguriert",
                        description=(
                            "Es ist kein CloudTrail in diesem Account konfiguriert. "
                            "Ohne CloudTrail gibt es keinen Audit-Trail für API-Aktivitäten."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control=ISO_CONTROL,
                        severity=Severity.CRITICAL,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=f"arn:aws:cloudtrail:{session.regions[0]}:{session.account_id}:trail/*",
                        resource_type="AWS::CloudTrail::Trail",
                        account_id=session.account_id,
                        current_state={"trails_configured": 0},
                        expected_state="Mindestens ein CloudTrail mit Log-File-Validation aktiv",
                        remediation=(
                            "Erstellen Sie einen CloudTrail mit Log-File-Validation: "
                            "aws cloudtrail create-trail --name main-trail "
                            "--s3-bucket-name <bucket> --enable-log-file-validation"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence="DescribeTrails returned 0 trails",
                    )
                )
            else:
                for trail in trails:
                    trail_name = trail.get("Name", "unknown")
                    trail_arn = trail.get("TrailARN", trail_name)
                    home_region = trail.get("HomeRegion", session.regions[0])
                    trail_compliant = True

                    # Check log file validation
                    if not trail.get("LogFileValidationEnabled", False):
                        trail_compliant = False
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="CloudTrail ohne Log-File-Validation",
                                description=(
                                    f"Der CloudTrail '{trail_name}' hat keine "
                                    f"Log-File-Validation aktiviert. Ohne Validation können "
                                    f"Log-Dateien unbemerkt manipuliert werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.CRITICAL,
                                provider=CloudProvider.AWS,
                                region=home_region,
                                resource_id=trail_arn,
                                resource_type="AWS::CloudTrail::Trail",
                                account_id=session.account_id,
                                current_state={
                                    "log_file_validation_enabled": False,
                                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                                    "trail_name": trail_name,
                                },
                                expected_state="LogFileValidationEnabled=true",
                                remediation=(
                                    "Aktivieren Sie die Log-File-Validation: "
                                    "aws cloudtrail update-trail --name <trail-name> "
                                    "--enable-log-file-validation"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"DescribeTrails: LogFileValidationEnabled=false for trail {trail_name}"
                                ),
                            )
                        )

                    # Check if trail is logging
                    try:
                        status = ct.get_trail_status(Name=trail_arn)
                        if not status.get("IsLogging", False):
                            trail_compliant = False
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="CloudTrail Logging deaktiviert",
                                    description=(
                                        f"Der CloudTrail '{trail_name}' ist "
                                        f"konfiguriert aber das Logging ist deaktiviert."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL,
                                    severity=Severity.CRITICAL,
                                    provider=CloudProvider.AWS,
                                    region=home_region,
                                    resource_id=trail_arn,
                                    resource_type="AWS::CloudTrail::Trail",
                                    account_id=session.account_id,
                                    current_state={"is_logging": False},
                                    expected_state="CloudTrail Logging aktiv",
                                    remediation=(
                                        "Aktivieren Sie das Logging: aws cloudtrail start-logging --name <trail-name>"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(f"GetTrailStatus: IsLogging=false for trail {trail_name}"),
                                )
                            )
                    except Exception as e:
                        trail_compliant = False  # unknown state is never positive evidence (ADR-0016)
                        errors.append(
                            CheckError(
                                message=f"Trail Status für {trail_name} fehlgeschlagen: {e}",
                                error_type="AWSClientError",
                            )
                        )

                    if trail_compliant:
                        findings.append(
                            compliant_finding(
                                self,
                                title="CloudTrail mit Log-Integrität aktiv",
                                description=(
                                    f"Der CloudTrail '{trail_name}' ist aktiv und hat Log-File-Validation aktiviert."
                                ),
                                region=home_region,
                                resource_id=trail_arn,
                                resource_type="AWS::CloudTrail::Trail",
                                account_id=session.account_id,
                                current_state={
                                    "is_logging": True,
                                    "log_file_validation_enabled": True,
                                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                                },
                                expected_state="CloudTrail aktiv mit LogFileValidationEnabled=true",
                                audit_evidence=(
                                    f"DescribeTrails/GetTrailStatus: IsLogging=true, "
                                    f"LogFileValidationEnabled=true for trail {trail_name}"
                                ),
                                iso27001_control=ISO_CONTROL,
                            )
                        )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"CloudTrail Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckConfigRecorder(BaseCheck):
    """Check that AWS Config Recorder is active in all regions."""

    check_id = "AWS-NR1-001"
    title = "AWS Config Recorder"
    description = "Prüft ob AWS Config Recorder in allen Regionen aktiv ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
    ]
    pruefgrenzen = (
        "Prüft nur, ob ein Config Recorder in den gescannten Regionen aufzeichnet. "
        "Nicht geprüft werden der Aufzeichnungsumfang und ob die aufgezeichneten "
        "Daten ausgewertet werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                config_client = session.client("config", region=region)
                recorders = config_client.describe_configuration_recorders().get("ConfigurationRecorders", [])

                if not recorders:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein AWS Config Recorder konfiguriert",
                            description=(
                                f"In der Region '{region}' ist kein AWS Config Recorder "
                                f"konfiguriert. Ohne Config Recorder werden "
                                f"Konfigurationsänderungen nicht aufgezeichnet."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.1, A.8.9",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=f"arn:aws:config:{region}:{session.account_id}:*",
                            resource_type="AWS::Config::ConfigurationRecorder",
                            account_id=session.account_id,
                            current_state={"recorders_configured": 0},
                            expected_state="Mindestens ein Config Recorder aktiv",
                            remediation=(
                                "Aktivieren Sie AWS Config in allen Regionen: "
                                "aws configservice put-configuration-recorder "
                                "--configuration-recorder name=default,"
                                "roleARN=<role-arn> --recording-group "
                                "allSupported=true,includeGlobalResourceTypes=true"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"DescribeConfigurationRecorders returned 0 recorders in {region}"),
                        )
                    )
                else:
                    status_resp = config_client.describe_configuration_recorder_status()
                    statuses = status_resp.get("ConfigurationRecordersStatus", [])
                    for status in statuses:
                        recorder_name = status.get("name", "unknown")
                        if status.get("recording", False):
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Config Recorder aktiv",
                                    description=(
                                        f"Der Config Recorder '{recorder_name}' in Region "
                                        f"'{region}' zeichnet Konfigurationsänderungen auf."
                                    ),
                                    region=region,
                                    resource_id=f"arn:aws:config:{region}:{session.account_id}:recorder/{recorder_name}",
                                    resource_type="AWS::Config::ConfigurationRecorder",
                                    account_id=session.account_id,
                                    current_state={"recording": True, "recorder_name": recorder_name},
                                    expected_state="Config Recorder recording=true",
                                    audit_evidence=(
                                        f"DescribeConfigurationRecorderStatus: recording=true "
                                        f"for {recorder_name} in {region}"
                                    ),
                                    iso27001_control="A.5.1, A.8.9",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="Config Recorder nicht aktiv",
                                    description=(
                                        f"Der Config Recorder "
                                        f"'{recorder_name}' in "
                                        f"Region '{region}' zeichnet derzeit "
                                        f"nicht auf."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.5.1, A.8.9",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=(f"arn:aws:config:{region}:{session.account_id}:*"),
                                    resource_type=("AWS::Config::ConfigurationRecorder"),
                                    account_id=session.account_id,
                                    current_state={
                                        "recording": False,
                                        "recorder_name": recorder_name,
                                    },
                                    expected_state="Config Recorder recording=true",
                                    remediation=(
                                        "Starten Sie den Config Recorder: "
                                        "aws configservice "
                                        "start-configuration-recorder "
                                        "--configuration-recorder-name "
                                        "<recorder-name>"
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(
                                        f"DescribeConfigurationRecorderStatus: "
                                        f"recording=false for "
                                        f"{recorder_name} "
                                        f"in {region}"
                                    ),
                                )
                            )

            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Config Recorder Check in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecurityHub(BaseCheck):
    """Check that AWS Security Hub is enabled with CIS/Foundational Benchmarks."""

    check_id = "AWS-NR1-002"
    title = "AWS Security Hub"
    description = "Prüft ob AWS Security Hub aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["securityhub:DescribeHub"]
    pruefgrenzen = (
        "Prüft nur, ob Security Hub aktiviert ist — nicht, welche Standards "
        "(CIS/Foundational) tatsächlich aktiviert sind und ob Befunde bearbeitet werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                sh_client = session.client("securityhub", region=region)
                hub = sh_client.describe_hub()
                findings.append(
                    compliant_finding(
                        self,
                        title="Security Hub aktiviert",
                        description=f"AWS Security Hub ist in Region '{region}' aktiviert.",
                        region=region,
                        resource_id=hub.get("HubArn", f"arn:aws:securityhub:{region}:{session.account_id}:hub/default"),
                        resource_type="AWS::SecurityHub::Hub",
                        account_id=session.account_id,
                        current_state={"security_hub_enabled": True},
                        expected_state="Security Hub aktiviert",
                        audit_evidence=f"DescribeHub succeeded in {region}",
                        iso27001_control="A.5.1",
                    )
                )
            except sh_client.exceptions.InvalidAccessException:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Security Hub nicht aktiviert",
                        description=(
                            f"AWS Security Hub ist in Region '{region}' "
                            f"nicht aktiviert. Ohne Security Hub fehlt "
                            f"eine zentrale Übersicht über "
                            f"Sicherheitsbefunde."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.1",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AWS,
                        region=region,
                        resource_id=(f"arn:aws:securityhub:{region}:{session.account_id}:hub/default"),
                        resource_type="AWS::SecurityHub::Hub",
                        account_id=session.account_id,
                        current_state={"security_hub_enabled": False},
                        expected_state=("Security Hub aktiviert"),
                        remediation=(
                            "Aktivieren Sie Security Hub: "
                            "aws securityhub enable-security-hub "
                            "--enable-default-standards"
                        ),
                        remediation_effort="LOW",
                        audit_evidence=(f"DescribeHub: InvalidAccessException in {region} — Security Hub not enabled"),
                    )
                )
            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Security Hub Check in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOrganizationsScp(BaseCheck):
    """Check that AWS Organizations with SCPs is configured."""

    check_id = "AWS-NR1-003"
    title = "AWS Organizations mit SCPs"
    description = "Prüft ob AWS Organizations mit Service Control Policies (SCPs) konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "organizations:DescribeOrganization",
        "organizations:ListPolicies",
    ]
    pruefgrenzen = (
        "Prüft nur Existenz der Organization und benutzerdefinierter SCPs. "
        "Nicht geprüft werden Inhalt und Wirksamkeit der SCPs sowie deren "
        "tatsächliche Zuordnung zu Accounts/OUs. Bei Einzel-Account-Konstellationen wird "
        "ein Hinweis mit niedriger Schwere ausgegeben; die Anwendbarkeit ist organisatorisch "
        "zu bewerten."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            organizations = session.client("organizations")

            try:
                org = organizations.describe_organization().get("Organization", {})
            except organizations.exceptions.AWSOrganizationsNotInUseException:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Kein AWS Organizations konfiguriert",
                        description=(
                            "AWS Organizations ist in diesem Account "
                            "nicht konfiguriert. Ohne Organizations "
                            "können keine zentralen Service Control "
                            "Policies durchgesetzt werden. Betreibt Ihre Einrichtung nur einen "
                            "einzelnen AWS-Account, kann dieser Punkt gegenstandslos sein; die "
                            "Anwendbarkeit ist organisatorisch zu bewerten."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.1, A.5.2",
                        severity=Severity.LOW,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=(f"arn:aws:organizations::{session.account_id}:organization/*"),
                        resource_type=("AWS::Organizations::Organization"),
                        account_id=session.account_id,
                        current_state={
                            "organizations_enabled": False,
                        },
                        expected_state=("AWS Organizations mit SCPs aktiviert"),
                        remediation=(
                            "Erstellen Sie eine AWS Organization: "
                            "aws organizations "
                            "create-organization --feature-set ALL"
                        ),
                        remediation_effort="HIGH",
                        audit_evidence=("DescribeOrganization: AWSOrganizationsNotInUseException"),
                    )
                )
                return CheckResult(
                    check_id=self.check_id,
                    findings=findings,
                    errors=errors,
                )

            # Organization exists — check for custom SCPs
            org_id = org.get("Id", "unknown")
            policies = organizations.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])

            custom_policies = [p for p in policies if p.get("Name") != "FullAWSAccess"]

            if custom_policies:
                findings.append(
                    compliant_finding(
                        self,
                        title="AWS Organizations mit benutzerdefinierten SCPs",
                        description=(
                            f"AWS Organizations ist aktiv und es sind "
                            f"{len(custom_policies)} benutzerdefinierte Service Control "
                            f"Policies konfiguriert."
                        ),
                        region="global",
                        resource_id=f"arn:aws:organizations::{session.account_id}:organization/{org_id}",
                        resource_type="AWS::Organizations::Organization",
                        account_id=session.account_id,
                        current_state={
                            "total_policies": len(policies),
                            "custom_policies": len(custom_policies),
                        },
                        expected_state="Mindestens eine benutzerdefinierte SCP konfiguriert",
                        audit_evidence=f"ListPolicies: {len(policies)} policies, {len(custom_policies)} custom SCPs",
                        iso27001_control="A.5.1, A.5.2",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=("Keine benutzerdefinierten SCPs"),
                        description=(
                            "AWS Organizations ist aktiv, aber es "
                            "sind keine benutzerdefinierten Service "
                            "Control Policies konfiguriert. Nur die "
                            "Standard-FullAWSAccess-Policy ist "
                            "vorhanden."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.1, A.5.2",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=(f"arn:aws:organizations::{session.account_id}:organization/{org_id}"),
                        resource_type=("AWS::Organizations::Organization"),
                        account_id=session.account_id,
                        current_state={
                            "total_policies": len(policies),
                            "custom_policies": 0,
                        },
                        expected_state=("Mindestens eine benutzerdefinierte SCP konfiguriert"),
                        remediation=(
                            "Erstellen Sie SCPs zur "
                            "Einschränkung von Berechtigungen: "
                            "aws organizations create-policy "
                            "--name <policy-name> --type "
                            "SERVICE_CONTROL_POLICY --content "
                            "<policy-json>"
                        ),
                        remediation_effort="HIGH",
                        audit_evidence=(f"ListPolicies: {len(policies)} policies, 0 custom SCPs"),
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"Organizations SCP Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckGuardDutyRiskAnalysis(BaseCheck):
    """Check that GuardDuty is enabled for risk analysis."""

    check_id = "AWS-NR1-005"
    title = "GuardDuty für Risikoanalyse"
    description = "Prüft ob Amazon GuardDuty als Bedrohungserkennungsdienst für die Risikoanalyse aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
    ]
    pruefgrenzen = (
        "Prüft nur den Detector-Status in den gescannten Regionen. Nicht geprüft "
        "werden aktivierte Schutz-Features (S3/EKS/Malware Protection) und ob "
        "GuardDuty-Befunde tatsächlich bearbeitet werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                gd = session.client("guardduty", region=region)
                detectors = gd.list_detectors().get("DetectorIds", [])

                if not detectors:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=("GuardDuty nicht aktiviert"),
                            description=(
                                f"Amazon GuardDuty ist in Region "
                                f"'{region}' nicht aktiviert. "
                                f"Ohne GuardDuty fehlt eine "
                                f"automatische Bedrohungserkennung "
                                f"für die Risikoanalyse."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.7",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:guardduty:{region}:{session.account_id}:detector/*"),
                            resource_type=("AWS::GuardDuty::Detector"),
                            account_id=session.account_id,
                            current_state={
                                "detectors_configured": 0,
                            },
                            expected_state=("GuardDuty Detector aktiv"),
                            remediation=("Aktivieren Sie GuardDuty: aws guardduty create-detector --enable"),
                            remediation_effort="LOW",
                            audit_evidence=(f"ListDetectors returned 0 detectors in {region}"),
                        )
                    )
                else:
                    for detector_id in detectors:
                        detector = gd.get_detector(DetectorId=detector_id)
                        status = detector.get("Status", "")

                        if status == "ENABLED":
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="GuardDuty aktiv",
                                    description=(
                                        f"Amazon GuardDuty ist in Region '{region}' aktiv "
                                        f"und überwacht auf Bedrohungen."
                                    ),
                                    region=region,
                                    resource_id=(
                                        f"arn:aws:guardduty:{region}:{session.account_id}:detector/{detector_id}"
                                    ),
                                    resource_type="AWS::GuardDuty::Detector",
                                    account_id=session.account_id,
                                    current_state={"status": status, "detector_id": detector_id},
                                    expected_state="GuardDuty Status=ENABLED",
                                    audit_evidence=f"GetDetector: Status=ENABLED for {detector_id} in {region}",
                                    iso27001_control="A.5.7",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("GuardDuty Detector nicht aktiv"),
                                    description=(
                                        f"Der GuardDuty Detector "
                                        f"'{detector_id}'"
                                        f" in Region '{region}' ist "
                                        f"nicht aktiv (Status: "
                                        f"{status})."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.5.7",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=(
                                        f"arn:aws:guardduty:{region}:{session.account_id}:detector/{detector_id}"
                                    ),
                                    resource_type=("AWS::GuardDuty::Detector"),
                                    account_id=(session.account_id),
                                    current_state={
                                        "status": status,
                                        "detector_id": detector_id,
                                    },
                                    expected_state=("GuardDuty Status=ENABLED"),
                                    remediation=(
                                        "Aktivieren Sie den "
                                        "Detector: aws guardduty "
                                        "update-detector "
                                        "--detector-id "
                                        "<detector-id> --enable"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(f"GetDetector: Status={status} for {detector_id} in {region}"),
                                )
                            )

            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"GuardDuty Check in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
