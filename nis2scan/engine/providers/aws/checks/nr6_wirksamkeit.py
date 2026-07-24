"""§30 Abs. 2 Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen checks for AWS.

Checks CloudTrail operational effectiveness by verifying recent log delivery.
"""

from datetime import UTC, datetime
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
ISO_CONTROL = "A.5.36 Compliance with policies, rules and standards"

# Maximum acceptable age (in hours) for last CloudTrail log delivery
MAX_DELIVERY_AGE_HOURS = 24


class CheckCloudTrailLogIntegrity(BaseCheck):
    """Check that CloudTrail is actively delivering logs (operational effectiveness).

    This goes beyond checking if CloudTrail is configured (NR1-004) by verifying
    that log delivery is actually happening recently, demonstrating operational
    effectiveness of the audit trail.
    """

    check_id = "AWS-NR6-001"
    title = "CloudTrail Betriebliche Wirksamkeit"
    description = (
        f"Prüft ob CloudTrail-Logs tatsächlich zugestellt werden "
        f"(letzte Zustellung innerhalb von {MAX_DELIVERY_AGE_HOURS} Stunden) "
        f"und die Digest-Validierung funktioniert."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]
    pruefgrenzen = (
        "Prüft nur, ob CloudTrail aktiv Ereignisse liefert (betriebliche Funktion). "
        "Nicht geprüft wird, ob die Ereignisse ausgewertet werden."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        now = datetime.now(UTC)

        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

            for trail in trails:
                trail_name = trail.get("Name", "unknown")
                trail_arn = trail.get("TrailARN", trail_name)
                home_region = trail.get("HomeRegion", session.regions[0])
                has_log_validation = trail.get("LogFileValidationEnabled", False)

                try:
                    status = ct.get_trail_status(Name=trail_arn)

                    if not status.get("IsLogging", False):
                        # NR1-004 already covers this — skip to avoid duplicates
                        continue

                    # Positive evidence only when every observable signal is
                    # fresh; missing timestamps stay unknown (ADR-0016).
                    delivery_fresh = False
                    digest_fresh = not has_log_validation

                    # Check last log delivery time
                    last_delivery = status.get("LatestDeliveryTime")
                    delivery_hours_ago: float | None = None
                    if last_delivery:
                        if last_delivery.tzinfo is None:
                            last_delivery = last_delivery.replace(tzinfo=UTC)

                        hours_since_delivery = (now - last_delivery).total_seconds() / 3600
                        delivery_hours_ago = round(hours_since_delivery, 1)
                        delivery_fresh = hours_since_delivery <= MAX_DELIVERY_AGE_HOURS

                        if hours_since_delivery > MAX_DELIVERY_AGE_HOURS:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="CloudTrail Log-Zustellung veraltet",
                                    description=(
                                        f"Der CloudTrail '{trail_name}' hat seit "
                                        f"{int(hours_since_delivery)} Stunden keine Logs zugestellt. "
                                        f"Dies deutet auf ein operatives Problem mit dem Audit-Trail hin."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL,
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=home_region,
                                    resource_id=trail_arn,
                                    resource_type="AWS::CloudTrail::Trail",
                                    account_id=session.account_id,
                                    current_state={
                                        "hours_since_delivery": round(hours_since_delivery, 1),
                                        "last_delivery": last_delivery.isoformat(),
                                        "trail_name": trail_name,
                                    },
                                    expected_state=(
                                        f"Log-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"
                                    ),
                                    remediation=(
                                        "Überprüfen Sie den S3-Bucket und die IAM-Berechtigungen "
                                        "des CloudTrail. Prüfen Sie LatestDeliveryError für Details."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(
                                        f"GetTrailStatus: LatestDeliveryTime={last_delivery.isoformat()}, "
                                        f"hours_ago={round(hours_since_delivery, 1)}"
                                    ),
                                )
                            )
                    else:
                        # B-Nr.6-1: IsLogging=True but no delivery timestamp registered at
                        # all is a defect in its own right — do not fail silently (ADR-0016).
                        delivery_error = status.get("LatestDeliveryError")
                        delivery_current_state: dict[str, Any] = {
                            "trail_name": trail_name,
                            "latest_delivery_time": None,
                        }
                        delivery_evidence = "GetTrailStatus: LatestDeliveryTime missing"
                        if delivery_error:
                            delivery_current_state["latest_delivery_error"] = delivery_error
                            delivery_evidence += f", LatestDeliveryError={delivery_error}"
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="CloudTrail ohne registrierte Log-Zustellung",
                                description=(
                                    f"Der CloudTrail '{trail_name}' hat aktiviertes Logging "
                                    f"(IsLogging=True), aber es ist keine Log-Zustellung registriert "
                                    f"(LatestDeliveryTime ist nicht gesetzt). Dies deutet auf ein "
                                    f"operatives Problem mit dem Audit-Trail hin."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region=home_region,
                                resource_id=trail_arn,
                                resource_type="AWS::CloudTrail::Trail",
                                account_id=session.account_id,
                                current_state=delivery_current_state,
                                expected_state=(
                                    f"Log-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"
                                ),
                                remediation=(
                                    "Überprüfen Sie den S3-Bucket und die IAM-Berechtigungen "
                                    "des CloudTrail. Prüfen Sie LatestDeliveryError für Details."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=delivery_evidence,
                            )
                        )

                    # Check digest delivery for trails with validation
                    last_digest = None
                    digest_hours_ago: float | None = None
                    if has_log_validation:
                        digest_fresh = False
                        last_digest = status.get("LatestDigestDeliveryTime")
                        if last_digest:
                            if last_digest.tzinfo is None:
                                last_digest = last_digest.replace(tzinfo=UTC)

                            hours_since_digest = (now - last_digest).total_seconds() / 3600
                            digest_hours_ago = round(hours_since_digest, 1)
                            digest_fresh = hours_since_digest <= MAX_DELIVERY_AGE_HOURS

                            if hours_since_digest > MAX_DELIVERY_AGE_HOURS:
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title="CloudTrail Digest-Zustellung veraltet",
                                        description=(
                                            f"Der CloudTrail '{trail_name}' hat seit "
                                            f"{int(hours_since_digest)} Stunden keinen Log-Digest "
                                            f"zugestellt. Die Log-Integritätsvalidierung ist beeinträchtigt."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL,
                                        severity=Severity.HIGH,
                                        provider=CloudProvider.AWS,
                                        region=home_region,
                                        resource_id=trail_arn,
                                        resource_type="AWS::CloudTrail::Trail",
                                        account_id=session.account_id,
                                        current_state={
                                            "hours_since_digest": round(hours_since_digest, 1),
                                            "last_digest": last_digest.isoformat(),
                                            "trail_name": trail_name,
                                        },
                                        expected_state=(
                                            f"Digest-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"
                                        ),
                                        remediation=(
                                            "Überprüfen Sie die CloudTrail-Konfiguration und "
                                            "S3-Bucket-Berechtigungen für die Digest-Zustellung."
                                        ),
                                        remediation_effort="MEDIUM",
                                        audit_evidence=(
                                            f"GetTrailStatus: LatestDigestDeliveryTime={last_digest.isoformat()}, "
                                            f"hours_ago={round(hours_since_digest, 1)}"
                                        ),
                                    )
                                )
                        else:
                            # B-Nr.6-1 (analog): validation enabled but no digest delivery
                            # timestamp registered at all is a defect, not a silent gap.
                            digest_error = status.get("LatestDigestDeliveryError")
                            digest_current_state: dict[str, Any] = {
                                "trail_name": trail_name,
                                "latest_digest_delivery_time": None,
                            }
                            digest_evidence = "GetTrailStatus: LatestDigestDeliveryTime missing"
                            if digest_error:
                                digest_current_state["latest_digest_delivery_error"] = digest_error
                                digest_evidence += f", LatestDigestDeliveryError={digest_error}"
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="CloudTrail ohne registrierte Digest-Zustellung",
                                    description=(
                                        f"Der CloudTrail '{trail_name}' hat aktivierte "
                                        f"Log-File-Validierung, aber es ist keine Digest-Zustellung "
                                        f"registriert (LatestDigestDeliveryTime ist nicht gesetzt). "
                                        f"Die Log-Integritätsvalidierung ist beeinträchtigt."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL,
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=home_region,
                                    resource_id=trail_arn,
                                    resource_type="AWS::CloudTrail::Trail",
                                    account_id=session.account_id,
                                    current_state=digest_current_state,
                                    expected_state=(
                                        f"Digest-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"
                                    ),
                                    remediation=(
                                        "Überprüfen Sie die CloudTrail-Konfiguration und "
                                        "S3-Bucket-Berechtigungen für die Digest-Zustellung."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=digest_evidence,
                                )
                            )

                    if delivery_fresh and digest_fresh:
                        # B-Nr.6-2: evidence covers delivery and — when log file validation
                        # is enabled — digest delivery, both within MAX_DELIVERY_AGE_HOURS.
                        compliant_evidence = (
                            f"GetTrailStatus: LatestDeliveryTime={last_delivery.isoformat()} "
                            f"(hours_ago={delivery_hours_ago}), log_file_validation={has_log_validation}"
                        )
                        if has_log_validation and last_digest:
                            compliant_evidence += (
                                f", LatestDigestDeliveryTime={last_digest.isoformat()} (hours_ago={digest_hours_ago})"
                            )
                        findings.append(
                            compliant_finding(
                                self,
                                title="CloudTrail-Zustellung betrieblich wirksam",
                                description=(
                                    f"Der CloudTrail '{trail_name}' stellt Logs aktuell zu "
                                    f"(letzte Zustellung innerhalb von {MAX_DELIVERY_AGE_HOURS} Stunden)."
                                ),
                                region=home_region,
                                resource_id=trail_arn,
                                resource_type="AWS::CloudTrail::Trail",
                                account_id=session.account_id,
                                current_state={
                                    "delivery_fresh": True,
                                    "log_file_validation_enabled": has_log_validation,
                                    "trail_name": trail_name,
                                },
                                expected_state=(
                                    "Log-Zustellung (und bei aktivierter Log-File-Validierung: "
                                    f"Digest-Zustellung) innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"
                                ),
                                audit_evidence=compliant_evidence,
                                iso27001_control=ISO_CONTROL,
                            )
                        )

                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"CloudTrail Status für {trail_name} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"CloudTrail Log Integrity Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckConfigRulesCompliance(BaseCheck):
    """Check that AWS Config Rules are configured for automated compliance evaluation.

    Verifies that AWS Config is active and Config Rules exist to provide
    automated compliance assessment of infrastructure resources.
    """

    check_id = "AWS-NR6-002"
    title = "Config Rules Compliance"
    description = "Prüft ob AWS Config Rules für automatisierte Compliance-Bewertung konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "config:DescribeConfigRules",
        "config:DescribeComplianceByConfigRule",
    ]
    pruefgrenzen = (
        "Prüft nur Existenz und Compliance-Stand der AWS-Config-Rules. Nicht geprüft "
        "wird, ob die Regelabdeckung für die Umgebung angemessen ist."
    )

    async def execute(self, session: Any) -> CheckResult:
        # B-Nr.6-3: lazy import, matching the module's other lazy-SDK-import checks.
        from botocore.exceptions import ClientError

        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                config_client = session.client("config", region=region)
            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Config Client in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )
                continue

            try:
                rules_resp = config_client.describe_config_rules()
                config_rules = rules_resp.get("ConfigRules", [])

                if not config_rules:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine AWS Config Rules konfiguriert",
                            description=(
                                f"In Region '{region}' sind keine AWS Config "
                                f"Rules konfiguriert. Ohne Config Rules fehlt "
                                f"eine automatisierte Compliance-Bewertung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=("A.5.35 Unabhängige Überprüfung der Informationssicherheit"),
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:config:{region}:{session.account_id}:config-rule/*"),
                            resource_type="AWS::Config::ConfigRule",
                            account_id=session.account_id,
                            current_state={
                                "config_rules_count": 0,
                            },
                            expected_state=("AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung"),
                            remediation=(
                                "Erstellen Sie mindestens eine AWS Config Rule, z. B.: "
                                "aws configservice put-config-rule --config-rule "
                                '\'{"ConfigRuleName":"s3-bucket-encryption-enabled",'
                                '"Source":{"Owner":"AWS",'
                                '"SourceIdentifier":"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}}\''
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"DescribeConfigRules: 0 rules found in region {region}"),
                        )
                    )
                else:
                    # B-Nr.6-4: pull the compliance-status call before the positive
                    # finding so the count of NON_COMPLIANT rules becomes part of the
                    # evidence, not just a log line.
                    non_compliant_count: int | None = None
                    try:
                        compliance_resp = config_client.describe_compliance_by_config_rule()
                        non_compliant = [
                            r
                            for r in compliance_resp.get("ComplianceByConfigRules", [])
                            if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT"
                        ]
                        non_compliant_count = len(non_compliant)
                    except Exception as e:
                        logger.warning(
                            "config_compliance_check_failed",
                            region=region,
                            error=str(e),
                        )

                    positive_current_state: dict[str, Any] = {"config_rules_count": len(config_rules)}
                    if non_compliant_count is not None:
                        positive_current_state["non_compliant_rules"] = non_compliant_count
                        positive_audit_evidence = (
                            f"DescribeConfigRules: {len(config_rules)} rules, "
                            f"DescribeComplianceByConfigRule: {non_compliant_count} NON_COMPLIANT in region {region}"
                        )
                    else:
                        positive_audit_evidence = (
                            f"DescribeConfigRules: {len(config_rules)} rules in region {region}; "
                            f"compliance status not retrievable"
                        )

                    findings.append(
                        compliant_finding(
                            self,
                            title="AWS Config Rules konfiguriert",
                            description=(
                                f"In Region '{region}' sind {len(config_rules)} AWS Config Rules "
                                f"konfiguriert — automatisierte Compliance-Bewertung ist aktiv."
                            ),
                            region=region,
                            resource_id=f"arn:aws:config:{region}:{session.account_id}:config-rule/*",
                            resource_type="AWS::Config::ConfigRule",
                            account_id=session.account_id,
                            current_state=positive_current_state,
                            expected_state="AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung",
                            audit_evidence=positive_audit_evidence,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                        )
                    )

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "NoAvailableConfigurationRecorderException":
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="AWS Config nicht aktiviert",
                            description=(
                                f"In Region '{region}' ist AWS Config nicht "
                                f"aktiviert. Ohne Config Recorder ist keine "
                                f"automatisierte Compliance-Bewertung möglich."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=("A.5.35 Unabhängige Überprüfung der Informationssicherheit"),
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:config:{region}:{session.account_id}:config-rule/*"),
                            resource_type="AWS::Config::ConfigRule",
                            account_id=session.account_id,
                            current_state={
                                "config_enabled": False,
                            },
                            expected_state=("AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung"),
                            remediation=(
                                "Aktivieren Sie AWS Config und erstellen Sie Config Rules:\n"
                                "1. aws configservice put-configuration-recorder --configuration-recorder "
                                '\'{"name":"default","roleARN":"<CONFIG_ROLE_ARN>",'
                                '"recordingGroup":{"allSupported":true}}\'\n'
                                "2. aws configservice start-configuration-recorder "
                                "--configuration-recorder-name default\n"
                                "3. aws configservice put-config-rule --config-rule "
                                '\'{"ConfigRuleName":"s3-bucket-encryption-enabled",'
                                '"Source":{"Owner":"AWS",'
                                '"SourceIdentifier":"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}}\''
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"NoAvailableConfigurationRecorderException in region {region}"),
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=(f"Config Rules Check in {region} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )
            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Config Rules Check in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


# Minimum retention period in days for CloudWatch Log Groups
MIN_RETENTION_DAYS = 365


class CheckCloudWatchLogRetention(BaseCheck):
    """Check that CloudWatch Log Groups have sufficient retention periods.

    Verifies that all CloudWatch Log Groups retain logs for at least the
    tool's minimum retention threshold (see MIN_RETENTION_DAYS).
    """

    check_id = "AWS-NR6-004"
    title = "CloudWatch Log Retention"
    description = "Prüft ob CloudWatch Log Groups eine Aufbewahrungsfrist von mindestens 365 Tagen haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["logs:DescribeLogGroups"]
    pruefgrenzen = (
        "Prüft nur die Retention-Einstellung der CloudWatch-Log-Gruppen. Nicht geprüft "
        "werden Vollständigkeit der Log-Quellen und Archivierung außerhalb von CloudWatch. "
        "Der Schwellwert 365 Tage ist eine Tool-Konvention, kein gesetzlicher Grenzwert."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                logs_client = session.client("logs", region=region)
                paginator = logs_client.get_paginator("describe_log_groups")

                for page in paginator.paginate():
                    for log_group in page.get("logGroups", []):
                        retention = log_group.get("retentionInDays")
                        lg_name = log_group.get("logGroupName", "unknown")
                        lg_arn = log_group.get("arn", lg_name)

                        # None means "never expire" — compliant
                        if retention is None or retention >= MIN_RETENTION_DAYS:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="CloudWatch Log Retention ausreichend",
                                    description=(
                                        f"Die Log Group '{lg_name}' hat eine Aufbewahrungsfrist von "
                                        f"{'unbegrenzt' if retention is None else f'{retention} Tagen'} "
                                        f"(Minimum: {MIN_RETENTION_DAYS} Tage)."
                                    ),
                                    region=region,
                                    resource_id=lg_arn,
                                    resource_type="AWS::Logs::LogGroup",
                                    account_id=session.account_id,
                                    current_state={
                                        "retention_days": retention,
                                        "log_group_name": lg_name,
                                    },
                                    expected_state=(
                                        f"CloudWatch Log Retention ≥ {MIN_RETENTION_DAYS} Tage (oder 'Never expire')"
                                    ),
                                    audit_evidence=(f"DescribeLogGroups: retentionInDays={retention} for {lg_name}"),
                                    iso27001_control="A.8.15 Logging",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("CloudWatch Log Retention zu kurz"),
                                    description=(
                                        f"Die Log Group "
                                        f"'{lg_name}' "
                                        f"hat eine Aufbewahrungsfrist "
                                        f"von nur {retention} Tagen. "
                                        f"Dieser Check setzt mindestens "
                                        f"{MIN_RETENTION_DAYS} Tage "
                                        f"als Mindestwert an."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=("A.8.15 Logging"),
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=lg_arn,
                                    resource_type=("AWS::Logs::LogGroup"),
                                    account_id=session.account_id,
                                    current_state={
                                        "retention_days": retention,
                                        "log_group_name": lg_name,
                                    },
                                    expected_state=(
                                        f"CloudWatch Log Retention ≥ {MIN_RETENTION_DAYS} Tage (oder 'Never expire')"
                                    ),
                                    remediation=(
                                        "Setzen Sie die "
                                        "Aufbewahrungsfrist: aws logs"
                                        " put-retention-policy "
                                        "--log-group-name <name> "
                                        "--retention-in-days 365"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(f"DescribeLogGroups: retentionInDays={retention} for {lg_name}"),
                                )
                            )

            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"CloudWatch Log Retention Check in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckSecurityHubComplianceScore(BaseCheck):
    """Check that AWS Security Hub is enabled with adequate compliance score.

    Verifies that Security Hub is activated and maintains a compliance score
    of at least 80% to demonstrate effective risk management assessment.
    """

    check_id = "AWS-NR6-003"
    title = "Security Hub Compliance Score"
    description = (
        "Prüft ob AWS Security Hub aktiviert ist und höchstens 20 Findings mit "
        "ComplianceStatus=FAILED offen sind (Tool-Schwellwert)."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "securityhub:DescribeHub",
        "securityhub:GetFindings",
    ]
    pruefgrenzen = (
        "Zählt nur Findings mit ComplianceStatus=FAILED und RecordState=ACTIVE. Der "
        "Schwellwert 20 ist eine Tool-Konvention, kein gesetzlicher Grenzwert; ein "
        "Security-Hub-Score wird nicht abgerufen."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for region in session.regions:
            try:
                sh_client = session.client("securityhub", region=region)
            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Security Hub Client in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )
                continue

            try:
                sh_client.describe_hub()
            except sh_client.exceptions.InvalidAccessException:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=("Security Hub nicht aktiviert"),
                        description=(
                            f"In Region '{region}' ist AWS Security Hub nicht aktiviert — "
                            f"der über Security Hub automatisierte Wirksamkeits-Nachweis "
                            f"steht damit nicht zur Verfügung."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AWS,
                        region=region,
                        resource_id=(f"arn:aws:securityhub:{region}:{session.account_id}:hub/default"),
                        resource_type=("AWS::SecurityHub::Hub"),
                        account_id=session.account_id,
                        current_state={
                            "security_hub_enabled": False,
                        },
                        expected_state=(
                            "Security Hub aktiviert; höchstens 20 offene FAILED-Compliance-Findings (Tool-Schwellwert)"
                        ),
                        remediation=("Aktivieren Sie AWS Security Hub: aws securityhub enable-security-hub"),
                        remediation_effort="MEDIUM",
                        audit_evidence=(f"DescribeHub: InvalidAccessException in region {region}"),
                    )
                )
                continue
            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Security Hub DescribeHub in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )
                continue

            # Security Hub is enabled — count open FAILED findings against the tool threshold
            try:
                # B-Nr.6-5: only ACTIVE findings count, and we paginate until the
                # threshold is exceeded or the result set is exhausted — a single
                # MaxResults=100 page silently undercounted larger environments.
                failed_count = 0
                next_token: str | None = None
                while True:
                    get_findings_kwargs: dict[str, Any] = {
                        "Filters": {
                            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                        },
                        "MaxResults": 100,
                    }
                    if next_token:
                        get_findings_kwargs["NextToken"] = next_token
                    findings_resp = sh_client.get_findings(**get_findings_kwargs)
                    failed_count += len(findings_resp.get("Findings", []))
                    next_token = findings_resp.get("NextToken")
                    if failed_count > 20 or not next_token:
                        break

                if failed_count <= 20:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Offene FAILED-Compliance-Findings unter Tool-Schwellwert",
                            description=(
                                f"In Region '{region}' ist Security Hub aktiviert und hat nur "
                                f"{failed_count} fehlgeschlagene Findings (Grenze: 20)."
                            ),
                            region=region,
                            resource_id=f"arn:aws:securityhub:{region}:{session.account_id}:hub/default",
                            resource_type="AWS::SecurityHub::Hub",
                            account_id=session.account_id,
                            current_state={"failed_findings_count": failed_count},
                            expected_state=(
                                "Security Hub aktiviert; höchstens 20 offene FAILED-Compliance-Findings "
                                "(Tool-Schwellwert)"
                            ),
                            audit_evidence=f"GetFindings: {failed_count} FAILED findings in region {region}",
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=("Offene FAILED-Compliance-Findings über Tool-Schwellwert"),
                            description=(
                                f"In Region '{region}' hat "
                                f"Security Hub "
                                f"{failed_count} fehl"
                                f"geschlagene Findings. "
                                f"Dieser Check setzt höchstens 20 offene "
                                f"FAILED-Findings als Tool-Schwellwert an."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.35 Unabhängige Überprüfung der Informationssicherheit",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:securityhub:{region}:{session.account_id}:hub/default"),
                            resource_type=("AWS::SecurityHub::Hub"),
                            account_id=session.account_id,
                            current_state={
                                "failed_findings_count": (failed_count),
                            },
                            expected_state=(
                                "Security Hub aktiviert; höchstens 20 offene FAILED-Compliance-Findings "
                                "(Tool-Schwellwert)"
                            ),
                            remediation=(
                                "Beheben Sie die fehl"
                                "geschlagenen Security Hub "
                                "Findings und überprüfen "
                                "Sie den Compliance-Status."
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"GetFindings: {failed_count} FAILED findings in region {region}"),
                        )
                    )

            except Exception as e:
                errors.append(
                    CheckError(
                        message=(f"Security Hub GetFindings in {region} fehlgeschlagen: {e}"),
                        error_type="AWSClientError",
                    )
                )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
