"""§30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs (BCM) checks for AWS.

Checks backup retention, versioning, and data protection configurations.
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
ISO_CONTROL_BACKUP = "A.8.13 Information backup"
ISO_CONTROL_AVAILABILITY = "A.5.30 IKT-Bereitschaft für Business Continuity"

RDS_MIN_BACKUP_RETENTION_DAYS = 7


class CheckRdsBackupRetention(BaseCheck):
    """Check that all RDS instances have backup retention ≥ 7 days."""

    check_id = "AWS-NR3-001"
    title = "RDS Backup Retention"
    description = (
        f"Prüft ob alle RDS-Instanzen eine Backup-Aufbewahrung von "
        f"mindestens {RDS_MIN_BACKUP_RETENTION_DAYS} Tagen konfiguriert haben."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["rds:DescribeDBInstances"]
    pruefgrenzen = (
        "Prüft nur die konfigurierte Backup-Aufbewahrung der RDS-Instanzen. "
        "Nicht geprüft werden Backup-Erfolg, Wiederherstellbarkeit und "
        "Datenbanken außerhalb von RDS."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                rds = session.client("rds", region=region)
                paginator = rds.get_paginator("describe_db_instances")

                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        retention = db.get("BackupRetentionPeriod", 0)
                        db_id = db.get("DBInstanceIdentifier", "unknown")
                        db_arn = db.get("DBInstanceArn", db_id)

                        if retention >= RDS_MIN_BACKUP_RETENTION_DAYS:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="RDS Backup-Aufbewahrung ausreichend",
                                    description=(
                                        f"Die RDS-Instanz '{db_id}' hat eine Backup-Aufbewahrung "
                                        f"von {retention} Tagen (Minimum: "
                                        f"{RDS_MIN_BACKUP_RETENTION_DAYS})."
                                    ),
                                    region=region,
                                    resource_id=db_arn,
                                    resource_type="AWS::RDS::DBInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "backup_retention_period": retention,
                                        "engine": db.get("Engine"),
                                        "db_name": db_id,
                                    },
                                    expected_state=f"BackupRetentionPeriod >= {RDS_MIN_BACKUP_RETENTION_DAYS} Tage",
                                    audit_evidence=(
                                        f"DescribeDBInstances: BackupRetentionPeriod={retention} for {db_id}"
                                    ),
                                    iso27001_control=ISO_CONTROL_BACKUP,
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="RDS Backup-Aufbewahrung zu kurz",
                                    description=(
                                        f"Die RDS-Instanz '{db_id}' hat eine "
                                        f"Backup-Aufbewahrung von nur {retention} Tagen. "
                                        f"Dieser Check setzt mindestens "
                                        f"{RDS_MIN_BACKUP_RETENTION_DAYS} Tage als Mindestwert an."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL_BACKUP,
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=db_arn,
                                    resource_type="AWS::RDS::DBInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "backup_retention_period": retention,
                                        "engine": db.get("Engine"),
                                        "db_name": db_id,
                                    },
                                    expected_state=(f"BackupRetentionPeriod >= {RDS_MIN_BACKUP_RETENTION_DAYS} Tage"),
                                    remediation=(
                                        "Erhöhen Sie die Backup-Aufbewahrungsfrist: "
                                        "aws rds modify-db-instance --db-instance-identifier <id> "
                                        f"--backup-retention-period {RDS_MIN_BACKUP_RETENTION_DAYS} "
                                        "--apply-immediately"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(
                                        f"DescribeDBInstances: BackupRetentionPeriod={retention} for {db_id}"
                                    ),
                                )
                            )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"RDS Backup Retention Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckS3Versioning(BaseCheck):
    """Check that all S3 buckets have versioning enabled."""

    check_id = "AWS-NR3-002"
    title = "S3 Bucket Versioning"
    description = "Prüft ob alle S3-Buckets Versionierung aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning",
        "s3:GetBucketLocation",
    ]
    pruefgrenzen = (
        "Prüft nur den Versioning-Status der Buckets. Nicht geprüft werden "
        "Lifecycle-Regeln, die alte Versionen löschen, und ob Versioning als "
        "Wiederherstellungsweg tatsächlich trägt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            s3 = session.client("s3")
            paginator = s3.get_paginator("list_buckets")
            buckets = [bucket for page in paginator.paginate() for bucket in page.get("Buckets", [])]

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get("Status", "Disabled")
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get("LocationConstraint") or "us-east-1"

                    if status == "Enabled":
                        findings.append(
                            compliant_finding(
                                self,
                                title="S3-Bucket mit Versionierung",
                                description=(
                                    f"Der S3-Bucket '{bucket_name}' hat Versionierung aktiviert — "
                                    f"frühere Objektversionen bleiben erhalten, sofern keine "
                                    f"Lifecycle-Regeln sie löschen."
                                ),
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=session.account_id,
                                current_state={"versioning_status": status},
                                expected_state="Versionierung aktiviert (Status=Enabled)",
                                audit_evidence=f"GetBucketVersioning: Status=Enabled for {bucket_name}",
                                iso27001_control=ISO_CONTROL_BACKUP,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="S3-Bucket ohne Versionierung",
                                description=(
                                    "Der S3-Bucket hat keine Versionierung aktiviert. "
                                    "Ohne Versionierung können gelöschte oder überschriebene "
                                    "Objekte nicht über Objektversionen wiederhergestellt werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL_BACKUP,
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=session.account_id,
                                current_state={"versioning_status": status},
                                expected_state="Versionierung aktiviert (Status=Enabled)",
                                remediation=(
                                    "Aktivieren Sie die Versionierung: "
                                    "aws s3api put-bucket-versioning --bucket <name> "
                                    "--versioning-configuration Status=Enabled"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(f"GetBucketVersioning: Status={status} for bucket"),
                            )
                        )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"S3 Versioning Check für {bucket_name} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"S3 Versioning Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckS3ObjectLock(BaseCheck):
    """Check that critical S3 buckets have Object Lock enabled."""

    check_id = "AWS-NR3-003"
    title = "S3 Object Lock"
    description = "Prüft ob kritische S3-Buckets Object Lock für unveränderlichen Datenschutz aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketLocation",
    ]
    pruefgrenzen = (
        "Prüft nur, ob Object Lock auf Buckets aktiviert ist. Nicht geprüft werden "
        "Retention-Modus und -Dauer je Objekt. Object Lock ist nur für "
        "Unveränderlichkeits-Anforderungen relevant — fehlendes Object Lock ist "
        "nicht per se ein Mangel für jedes Bucket."
    )

    def _no_object_lock_finding(self, session: Any, bucket_name: str, region: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            title="S3-Bucket ohne Object Lock",
            description=(
                f"Der S3-Bucket '{bucket_name}' hat kein Object Lock aktiviert. Für Buckets mit "
                f"Unveränderlichkeits-Anforderungen (z. B. Backup-Speicher) fehlt damit der Schutz "
                f"vor Ransomware und versehentlichem Löschen."
            ),
            bsig_30_nr=BSIG_30_NR,
            bsig_30_text=BSIG_30_TEXT,
            iso27001_control=ISO_CONTROL_BACKUP,
            severity=Severity.LOW,
            provider=CloudProvider.AWS,
            region=region,
            resource_id=(f"arn:aws:s3:::{bucket_name}"),
            resource_type="AWS::S3::Bucket",
            account_id=session.account_id,
            current_state={
                "object_lock": "Disabled",
            },
            expected_state=("Object Lock aktiviert (Schutz gegen Ransomware und versehentliches Löschen)"),
            remediation=(
                "Object Lock muss bei "
                "Bucket-Erstellung aktiviert "
                "werden. Erstellen Sie einen "
                "neuen Bucket: aws s3api "
                "create-bucket --bucket <name> "
                "--object-lock-enabled-for-bucket"
            ),
            remediation_effort="HIGH",
            audit_evidence=("GetObjectLockConfiguration: not configured for bucket"),
        )

    async def execute(self, session: Any) -> CheckResult:
        from botocore.exceptions import ClientError

        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            s3 = session.client("s3")
            paginator = s3.get_paginator("list_buckets")
            buckets = [bucket for page in paginator.paginate() for bucket in page.get("Buckets", [])]

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    response = s3.get_object_lock_configuration(Bucket=bucket_name)
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get("LocationConstraint") or "us-east-1"
                    object_lock_enabled = (
                        response.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
                    )

                    if object_lock_enabled:
                        findings.append(
                            compliant_finding(
                                self,
                                title="S3-Bucket mit Object Lock",
                                description=(
                                    f"Der S3-Bucket '{bucket_name}' ist für Object Lock konfiguriert "
                                    f"(Retention-Modus und -Dauer je Objekt nicht geprüft)."
                                ),
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=session.account_id,
                                current_state={"object_lock": "Enabled"},
                                expected_state=(
                                    "Object Lock aktiviert (Schutz gegen Ransomware und versehentliches Löschen)"
                                ),
                                audit_evidence=(
                                    f"GetObjectLockConfiguration: ObjectLockEnabled=Enabled for {bucket_name}"
                                ),
                                iso27001_control=ISO_CONTROL_BACKUP,
                            )
                        )
                    else:
                        findings.append(self._no_object_lock_finding(session, bucket_name, region))
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "ObjectLockConfigurationNotFoundError":
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        region = location.get("LocationConstraint") or "us-east-1"
                        findings.append(self._no_object_lock_finding(session, bucket_name, region))
                    else:
                        errors.append(
                            CheckError(
                                message=(f"S3 Object Lock Check für {bucket_name} fehlgeschlagen: {e}"),
                                error_type="AWSClientError",
                            )
                        )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=(f"S3 Object Lock Check für {bucket_name} fehlgeschlagen: {e}"),
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"S3 Object Lock Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckEbsSnapshotEncryption(BaseCheck):
    """Check that EBS volumes have encrypted snapshots."""

    check_id = "AWS-NR3-006"
    title = "EBS Snapshot Verschlüsselung"
    description = "Prüft ob EBS-Volumes verschlüsselte Snapshots haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
    ]
    pruefgrenzen = (
        "Prüft nur das Verschlüsselungs-Flag vorhandener EBS-Snapshots. "
        "Nicht geprüft werden Snapshot-Aktualität, Vollständigkeit der "
        "Sicherungsabdeckung und Wiederherstellbarkeit."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ec2 = session.client("ec2", region=region)
                paginator = ec2.get_paginator("describe_volumes")

                for page in paginator.paginate():
                    for vol in page.get("Volumes", []):
                        vol_id = vol.get("VolumeId", "unknown")
                        state = vol.get("State", "unknown")

                        if state not in ("in-use", "available"):
                            continue

                        snapshots_resp = ec2.describe_snapshots(
                            Filters=[
                                {
                                    "Name": "volume-id",
                                    "Values": [vol_id],
                                }
                            ]
                        )
                        snaps = snapshots_resp.get("Snapshots", [])

                        if not snaps:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("EBS-Volume ohne Snapshots"),
                                    description=(
                                        f"Das EBS-Volume {vol_id} hat keine Snapshots. "
                                        f"Ohne Snapshots ist keine Wiederherstellung aus "
                                        f"EBS-Snapshots möglich."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=("A.8.13, A.8.24"),
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=vol_id,
                                    resource_type=("AWS::EC2::Volume"),
                                    account_id=(session.account_id),
                                    current_state={
                                        "snapshots": 0,
                                        "volume_state": state,
                                    },
                                    expected_state=("Mindestens ein verschlüsselter Snapshot vorhanden"),
                                    remediation=(
                                        "Erstellen Sie "
                                        "verschlüsselte "
                                        "Snapshots: aws ec2 "
                                        "create-snapshot "
                                        "--volume-id <id> "
                                        "--encrypted. Nutzen "
                                        "Sie AWS Backup für "
                                        "automatisierte "
                                        "Snapshot-Pläne."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(f"DescribeSnapshots: no snapshots for {vol_id}"),
                                )
                            )
                            continue

                        latest = sorted(
                            snaps,
                            key=lambda s: s.get("StartTime", ""),
                            reverse=True,
                        )[0]

                        if latest.get("Encrypted", False):
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="EBS-Volume mit verschlüsselten Snapshots",
                                    description=(
                                        f"Das EBS-Volume '{vol_id}' hat {len(snaps)} Snapshot(s); "
                                        f"der neueste ist verschlüsselt."
                                    ),
                                    region=region,
                                    resource_id=vol_id,
                                    resource_type="AWS::EC2::Volume",
                                    account_id=session.account_id,
                                    current_state={
                                        "snapshot_id": latest.get("SnapshotId"),
                                        "encrypted": True,
                                        "snapshots": len(snaps),
                                    },
                                    expected_state="Neuester Snapshot verschlüsselt (Encrypted=True)",
                                    audit_evidence=(f"DescribeSnapshots: latest snapshot Encrypted=True for {vol_id}"),
                                    iso27001_control="A.8.13, A.8.24",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("EBS-Snapshot nicht verschlüsselt"),
                                    description=(
                                        "Der neueste Snapshot "
                                        "des EBS-Volumes ist "
                                        "nicht verschlüsselt. "
                                        "Unverschlüsselte "
                                        "Snapshots gefährden "
                                        "die Vertraulichkeit "
                                        "der Daten."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=("A.8.13, A.8.24"),
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=vol_id,
                                    resource_type=("AWS::EC2::Volume"),
                                    account_id=(session.account_id),
                                    current_state={
                                        "snapshot_id": latest.get("SnapshotId"),
                                        "encrypted": False,
                                        "volume_state": state,
                                    },
                                    expected_state=("Neuester Snapshot verschlüsselt (Encrypted=True)"),
                                    remediation=(
                                        "Erstellen Sie "
                                        "verschlüsselte "
                                        "Snapshots: aws ec2 "
                                        "create-snapshot "
                                        "--volume-id <id> "
                                        "--encrypted. Nutzen "
                                        "Sie AWS Backup für "
                                        "automatisierte "
                                        "Snapshot-Pläne."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(f"DescribeSnapshots: latest snapshot Encrypted=False for {vol_id}"),
                                )
                            )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"EBS Snapshot Encryption Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckRdsMultiAz(BaseCheck):
    """Check that RDS instances have Multi-AZ enabled for high availability."""

    check_id = "AWS-NR3-004"
    title = "RDS Multi-AZ Verfügbarkeit"
    description = "Prüft ob RDS-Instanzen mit Multi-AZ für Hochverfügbarkeit konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["rds:DescribeDBInstances"]
    pruefgrenzen = (
        "Prüft nur das Multi-AZ-Flag der RDS-Instanzen. Nicht geprüft werden "
        "Failover-Funktion, regionsübergreifende Redundanz und Nicht-RDS-Datenbanken."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                rds = session.client("rds", region=region)
                paginator = rds.get_paginator("describe_db_instances")

                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        if db.get("DBClusterIdentifier"):
                            continue

                        db_id = db.get("DBInstanceIdentifier", "unknown")
                        multi_az = db.get("MultiAZ", False)

                        if multi_az:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="RDS-Instanz mit Multi-AZ",
                                    description=(
                                        f"Die RDS-Instanz '{db_id}' ist mit Multi-AZ konfiguriert — "
                                        f"automatisches Failover ist verfügbar."
                                    ),
                                    region=region,
                                    resource_id=db["DBInstanceArn"],
                                    resource_type="AWS::RDS::DBInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "multi_az": True,
                                        "engine": db.get("Engine"),
                                        "db_name": db_id,
                                    },
                                    expected_state="MultiAZ=True für Hochverfügbarkeit",
                                    audit_evidence=f"DescribeDBInstances: MultiAZ=True for {db_id}",
                                    iso27001_control="A.5.29, A.8.14",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title=("RDS-Instanz ohne Multi-AZ"),
                                    description=(
                                        "Die RDS-Instanz "
                                        f"'{db_id}'"
                                        " ist nicht mit "
                                        "Multi-AZ konfiguriert."
                                        " Ohne Multi-AZ ist "
                                        "keine automatische "
                                        "Failover-Funktion "
                                        "verfügbar."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=("A.5.29, A.8.14"),
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=(db["DBInstanceArn"]),
                                    resource_type=("AWS::RDS::DBInstance"),
                                    account_id=(session.account_id),
                                    current_state={
                                        "multi_az": False,
                                        "engine": db.get("Engine"),
                                        "db_name": db_id,
                                    },
                                    expected_state=("MultiAZ=True für Hochverfügbarkeit"),
                                    remediation=(
                                        "Aktivieren Sie "
                                        "Multi-AZ: aws rds "
                                        "modify-db-instance "
                                        "--db-instance-"
                                        "identifier <id> "
                                        "--multi-az "
                                        "--apply-immediately"
                                    ),
                                    remediation_effort=("MEDIUM"),
                                    audit_evidence=(f"DescribeDBInstances: MultiAZ=False for {db_id}"),
                                )
                            )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"RDS Multi-AZ Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )


class CheckRoute53HealthChecks(BaseCheck):
    """Check that Route 53 Health Checks are configured for availability monitoring."""

    check_id = "AWS-NR3-007"
    title = "Route 53 Health Checks"
    description = "Prüft ob Route 53 Health Checks für Verfügbarkeitsüberwachung konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["route53:ListHealthChecks"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Route-53-Health-Checks. Nicht geprüft wird, "
        "ob kritische Endpunkte abgedeckt sind und ob Failover-Routing konfiguriert ist. "
        "Externes Monitoring außerhalb von Route 53 wird nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            # Route 53 is a global service — use us-east-1
            route53 = session.client("route53", region="us-east-1")

            try:
                health_checks = route53.list_health_checks().get("HealthChecks", [])

                if health_checks:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Route 53 Health Checks konfiguriert",
                            description=(
                                f"Es sind {len(health_checks)} Route 53 Health Checks konfiguriert — "
                                f"die Abdeckung kritischer Endpunkte ist organisatorisch nachzuweisen."
                            ),
                            region="global",
                            resource_id=(f"arn:aws:route53:::healthcheck/{health_checks[0].get('Id', '*')}"),
                            resource_type="AWS::Route53::HealthCheck",
                            account_id=session.account_id,
                            current_state={"health_checks": len(health_checks)},
                            expected_state="Mindestens ein Route 53 Health Check für Verfügbarkeitsüberwachung",
                            audit_evidence=f"ListHealthChecks returned {len(health_checks)} health check(s)",
                            iso27001_control=ISO_CONTROL_AVAILABILITY,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Route 53 Health Checks konfiguriert",
                            description=(
                                "Es sind keine Route 53 Health Checks konfiguriert. "
                                "Ohne Health Checks fehlt die automatische Überwachung "
                                "der Verfügbarkeit kritischer Endpunkte und DNS-Failover."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL_AVAILABILITY,
                            severity=Severity.LOW,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:route53:{session.account_id}:healthcheck/*",
                            resource_type="AWS::Route53::HealthCheck",
                            account_id=session.account_id,
                            current_state={"health_checks": 0},
                            expected_state="Mindestens ein Route 53 Health Check für Verfügbarkeitsüberwachung",
                            remediation=(
                                "Erstellen Sie Route 53 Health Checks: "
                                "aws route53 create-health-check --caller-reference <ref> "
                                "--health-check-config Type=HTTPS,FullyQualifiedDomainName=<domain>,Port=443"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="ListHealthChecks returned 0 health checks",
                        )
                    )
            except Exception as e:
                errors.append(
                    CheckError(
                        message=f"Route 53 Health Checks Check fehlgeschlagen: {e}",
                        error_type="AWSClientError",
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Route 53 Health Checks Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckBackupPlans(BaseCheck):
    """Check that AWS Backup Plans are configured for automated backups."""

    check_id = "AWS-NR3-005"
    title = "AWS Backup Plans"
    description = "Prüft ob AWS Backup Plans für automatisierte Datensicherung konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["backup:ListBackupPlans"]
    pruefgrenzen = (
        "Prüft nur die Existenz von AWS-Backup-Plänen. Nicht geprüft werden "
        "Ressourcen-Zuordnung (was wird gesichert?), Backup-Erfolg und "
        "Wiederherstellungstests. Backup-Lösungen außerhalb von AWS Backup "
        "werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                backup_client = session.client("backup", region=region)
                response = backup_client.list_backup_plans()
                plans = response.get("BackupPlansList", [])

                if plans:
                    findings.append(
                        compliant_finding(
                            self,
                            title="AWS Backup Plans konfiguriert",
                            description=(
                                f"In der Region '{region}' sind {len(plans)} AWS Backup Plans "
                                f"konfiguriert — die Zuordnung kritischer Ressourcen ist gesondert "
                                f"nachzuweisen."
                            ),
                            region=region,
                            resource_id=plans[0].get(
                                "BackupPlanArn", f"arn:aws:backup:{region}:{session.account_id}:*"
                            ),
                            resource_type="AWS::Backup::BackupPlan",
                            account_id=session.account_id,
                            current_state={"backup_plans_count": len(plans)},
                            expected_state="Mindestens ein AWS Backup Plan konfiguriert",
                            audit_evidence=f"ListBackupPlans: {len(plans)} backup plan(s) in region {region}",
                            iso27001_control="A.8.13",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=("Keine AWS Backup Plans konfiguriert"),
                            description=(
                                "In der Region "
                                f"'{region}' sind keine "
                                "AWS Backup Plans "
                                "konfiguriert. Ohne "
                                "Backup Plans ist keine "
                                "automatisierte "
                                "Datensicherung "
                                "gewährleistet."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=("A.8.13"),
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region=region,
                            resource_id=(f"arn:aws:backup:{region}:{session.account_id}:*"),
                            resource_type=("AWS::Backup::BackupPlan"),
                            account_id=(session.account_id),
                            current_state={
                                "backup_plans_count": 0,
                            },
                            expected_state=("Mindestens ein AWS Backup Plan konfiguriert"),
                            remediation=(
                                "Erstellen Sie einen "
                                "AWS Backup Plan: aws "
                                "backup create-backup-"
                                "plan --backup-plan "
                                "'<plan-json>'. Nutzen "
                                "Sie die AWS Console "
                                "für eine geführte "
                                "Einrichtung."
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"ListBackupPlans: no backup plans in region {region}"),
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"AWS Backup Plans Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
