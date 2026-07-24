"""§30 Abs. 2 Nr. 8 — Kryptographie checks for AWS.

Checks encryption at rest and in transit across S3, EBS, RDS, KMS, TLS policies, and certificates.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 8
BSIG_30_TEXT = "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"
ISO_CONTROL = "A.8.24 Verwendung von Kryptographie"


class CheckS3DefaultEncryption(BaseCheck):
    """Check that all S3 buckets have default encryption enabled."""

    check_id = "AWS-NR8-001"
    title = "S3 Default Encryption"
    description = "Prüft ob alle S3-Buckets eine Default-Verschlüsselung (SSE-S3 oder SSE-KMS) aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
    ]
    pruefgrenzen = (
        "Prüft nur die Default-Encryption-Einstellung der Buckets. Nicht geprüft "
        "werden einzelne Objekte, die vor der Aktivierung unverschlüsselt abgelegt wurden."
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
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    sse_algorithm = (
                        rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "unknown")
                        if rules
                        else "unknown"
                    )
                    if not rules or sse_algorithm == "unknown":
                        # GetBucketEncryption succeeded but returned no evaluable rule —
                        # a positive finding here would fabricate a concrete algorithm
                        # that was never actually read (B-Nr.8-1).
                        errors.append(
                            CheckError(
                                message=(
                                    f"Verschlüsselungskonfiguration für Bucket {bucket_name} "
                                    "nicht auswertbar (leere Rules)"
                                ),
                                error_type="UnverifiableState",
                            )
                        )
                        continue
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get("LocationConstraint") or "us-east-1"
                    findings.append(
                        compliant_finding(
                            self,
                            title="S3-Bucket mit Default-Verschlüsselung",
                            description=(
                                f"Der S3-Bucket '{bucket_name}' hat serverseitige "
                                f"Default-Verschlüsselung ({sse_algorithm}) aktiviert."
                            ),
                            region=region,
                            resource_id=f"arn:aws:s3:::{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            account_id=session.account_id,
                            current_state={"encryption": sse_algorithm},
                            expected_state="SSE-S3 (AES-256) oder SSE-KMS Default-Verschlüsselung aktiviert",
                            audit_evidence=f"GetBucketEncryption: SSEAlgorithm={sse_algorithm} for {bucket_name}",
                            iso27001_control=ISO_CONTROL,
                        )
                    )
                except s3.exceptions.ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        region = location.get("LocationConstraint") or "us-east-1"
                        account_id = session.account_id

                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="S3-Bucket ohne Default-Verschlüsselung",
                                description=(
                                    f"Der S3-Bucket '{bucket_name}' hat keine serverseitige Default-Verschlüsselung "
                                    "konfiguriert. Alle hochgeladenen Objekte sind unverschlüsselt gespeichert."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=account_id,
                                current_state={"encryption": "none"},
                                expected_state="SSE-S3 (AES-256) oder SSE-KMS Default-Verschlüsselung aktiviert",
                                remediation=(
                                    "Aktivieren Sie die Default-Verschlüsselung für den S3-Bucket mit SSE-S3 (AES-256) "
                                    "oder SSE-KMS. AWS CLI: aws s3api put-bucket-encryption "
                                    "--bucket <name> --server-side-encryption-configuration "
                                    '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":'
                                    '{"SSEAlgorithm":"AES256"}}]}\''
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    "GetBucketEncryption returned "
                                    f"ServerSideEncryptionConfigurationNotFoundError for bucket '{bucket_name}'"
                                ),
                            )
                        )
                    else:
                        errors.append(
                            CheckError(
                                message=f"Fehler beim Prüfen von Bucket {bucket_name}: {error_code}",
                                error_type="AWSClientError",
                            )
                        )

        except Exception as e:
            errors.append(CheckError(message=f"S3 Encryption Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckEbsEncryption(BaseCheck):
    """Check that all EBS volumes are encrypted."""

    check_id = "AWS-NR8-002"
    title = "EBS Volume Encryption"
    description = "Prüft ob alle EBS-Volumes verschlüsselt sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ec2:DescribeVolumes"]
    pruefgrenzen = (
        "Prüft nur das Encrypted-Flag der EBS-Volumes in den gescannten Regionen. "
        "Die Schlüsselverwaltung (KMS-Key-Policy) wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ec2 = session.client("ec2", region=region)
                paginator = ec2.get_paginator("describe_volumes")

                for page in paginator.paginate():
                    for volume in page.get("Volumes", []):
                        if volume.get("Encrypted", False):
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="EBS-Volume verschlüsselt",
                                    description=f"Das EBS-Volume '{volume['VolumeId']}' ist verschlüsselt.",
                                    region=region,
                                    resource_id=volume["VolumeId"],
                                    resource_type="AWS::EC2::Volume",
                                    account_id=session.account_id,
                                    current_state={"encrypted": True, "state": volume.get("State")},
                                    expected_state="EBS-Volume mit AES-256 Verschlüsselung (aws/ebs oder CMK)",
                                    audit_evidence=f"DescribeVolumes: Encrypted=true for {volume['VolumeId']}",
                                    iso27001_control=ISO_CONTROL,
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="EBS-Volume ohne Verschlüsselung",
                                    description=(
                                        f"Das EBS-Volume '{volume['VolumeId']}' ist nicht verschlüsselt. "
                                        "Daten at Rest sind ungeschützt."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL,
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=volume["VolumeId"],
                                    resource_type="AWS::EC2::Volume",
                                    account_id=session.account_id,
                                    current_state={"encrypted": False, "state": volume.get("State")},
                                    expected_state="EBS-Volume mit AES-256 Verschlüsselung (aws/ebs oder CMK)",
                                    remediation=(
                                        "Erstellen Sie einen verschlüsselten Snapshot des Volumes und erstellen Sie "
                                        "daraus ein neues verschlüsseltes Volume. Aktivieren Sie die "
                                        "EBS-Verschlüsselung "
                                        "als Default für die Region: aws ec2 enable-ebs-encryption-by-default"
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=f"DescribeVolumes: Encrypted=false for {volume['VolumeId']}",
                                )
                            )

        except Exception as e:
            errors.append(CheckError(message=f"EBS Encryption Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckRdsEncryption(BaseCheck):
    """Check that all RDS instances have storage encryption enabled."""

    check_id = "AWS-NR8-003"
    title = "RDS Storage Encryption"
    description = "Prüft ob alle RDS-Instanzen Storage-Verschlüsselung aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["rds:DescribeDBInstances"]
    pruefgrenzen = (
        "Prüft nur das StorageEncrypted-Flag der RDS-Instanzen. Verschlüsselung "
        "in Transit (TLS zur Datenbank) wird hier nicht geprüft."
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
                        if db.get("StorageEncrypted", False):
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="RDS-Instanz mit Storage-Verschlüsselung",
                                    description=(
                                        f"Die RDS-Instanz '{db['DBInstanceIdentifier']}' hat "
                                        f"Storage-Verschlüsselung aktiviert."
                                    ),
                                    region=region,
                                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                                    resource_type="AWS::RDS::DBInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "storage_encrypted": True,
                                        "engine": db.get("Engine"),
                                    },
                                    expected_state="RDS Storage Encryption aktiviert mit KMS Key",
                                    audit_evidence=(
                                        f"DescribeDBInstances: StorageEncrypted=true for {db['DBInstanceIdentifier']}"
                                    ),
                                    iso27001_control=ISO_CONTROL,
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="RDS-Instanz ohne Storage-Verschlüsselung",
                                    description=(
                                        f"Die RDS-Datenbankinstanz '{db['DBInstanceIdentifier']}' hat keine "
                                        "Storage-Verschlüsselung aktiviert. Datenbank-Daten at Rest sind ungeschützt."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL,
                                    severity=Severity.CRITICAL,
                                    provider=CloudProvider.AWS,
                                    region=region,
                                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                                    resource_type="AWS::RDS::DBInstance",
                                    account_id=session.account_id,
                                    current_state={
                                        "storage_encrypted": False,
                                        "engine": db.get("Engine"),
                                        "instance_class": db.get("DBInstanceClass"),
                                    },
                                    expected_state="RDS Storage Encryption aktiviert mit KMS Key",
                                    remediation=(
                                        "RDS-Verschlüsselung kann nur bei der Erstellung aktiviert werden. "
                                        "Erstellen Sie einen Snapshot, kopieren Sie ihn mit Verschlüsselung, "
                                        "und stellen Sie die DB aus dem verschlüsselten Snapshot wieder her."
                                    ),
                                    remediation_effort="HIGH",
                                    audit_evidence=(
                                        f"DescribeDBInstances: StorageEncrypted=false for {db['DBInstanceIdentifier']}"
                                    ),
                                )
                            )

        except Exception as e:
            errors.append(CheckError(message=f"RDS Encryption Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckKmsKeyRotation(BaseCheck):
    """Check that all KMS customer-managed keys have automatic rotation enabled."""

    check_id = "AWS-NR8-004"
    title = "KMS Key Rotation"
    description = "Prüft ob alle KMS Customer-Managed Keys automatische Rotation aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["kms:ListKeys", "kms:GetKeyRotationStatus", "kms:DescribeKey"]
    pruefgrenzen = (
        "Prüft nur die automatische Rotation kundenverwalteter, symmetrischer KMS-Schlüssel "
        "(KeySpec SYMMETRIC_DEFAULT). AWS-verwaltete Schlüssel sowie Schlüssel mit Ursprung "
        "außerhalb von AWS KMS (importiertes Schlüsselmaterial, CloudHSM, externe "
        "Schlüsselspeicher) rotieren anders und werden nicht bewertet; deaktivierte Schlüssel "
        "ebenfalls nicht. Asymmetrische und HMAC-Schlüssel unterstützen die automatische "
        "Rotation nicht in gleicher Weise und werden ebenfalls nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                kms = session.client("kms", region=region)
                paginator = kms.get_paginator("list_keys")

                for page in paginator.paginate():
                    for key in page.get("Keys", []):
                        key_id = key["KeyId"]
                        try:
                            key_info = kms.describe_key(KeyId=key_id)["KeyMetadata"]

                            # Skip AWS-managed keys and keys not in enabled state
                            if key_info.get("KeyManager") != "CUSTOMER":
                                continue
                            if key_info.get("KeyState") != "Enabled":
                                continue
                            # EXTERNAL-origin keys (imported key material) rotate
                            # differently and are out of this check's Prüfgrenzen (H-3).
                            if key_info.get("Origin") != "AWS_KMS":
                                continue
                            # Asymmetric and HMAC keys do not support automatic rotation
                            # the same way symmetric keys do. AWS's GetKeyRotationStatus
                            # returns KeyRotationEnabled=false for them instead of an
                            # error, which would otherwise be misread as a defect (false
                            # positive).
                            if key_info.get("KeySpec") != "SYMMETRIC_DEFAULT":
                                continue

                            rotation = kms.get_key_rotation_status(KeyId=key_id)
                            if rotation.get("KeyRotationEnabled", False):
                                findings.append(
                                    compliant_finding(
                                        self,
                                        title="KMS-Key mit automatischer Rotation",
                                        description=(
                                            "Der KMS Customer-Managed Key hat automatische Key-Rotation aktiviert."
                                        ),
                                        region=region,
                                        resource_id=key_info.get("Arn", key_id),
                                        resource_type="AWS::KMS::Key",
                                        account_id=session.account_id,
                                        current_state={"key_rotation_enabled": True},
                                        expected_state="Automatische KMS Key Rotation aktiviert (jährlich)",
                                        audit_evidence=(f"GetKeyRotationStatus: KeyRotationEnabled=true for {key_id}"),
                                        iso27001_control=ISO_CONTROL,
                                    )
                                )
                            else:
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title="KMS-Key ohne automatische Rotation",
                                        description=(
                                            f"Der KMS Customer-Managed Key '{key_info.get('Arn', key_id)}' hat "
                                            "keine automatische Key-Rotation aktiviert. Regelmäßige "
                                            "Schlüsselrotation ist gängige kryptographische Praxis und begrenzt "
                                            "die Auswirkungen einer Schlüsselkompromittierung."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL,
                                        severity=Severity.MEDIUM,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=key_info.get("Arn", key_id),
                                        resource_type="AWS::KMS::Key",
                                        account_id=session.account_id,
                                        current_state={"key_rotation_enabled": False},
                                        expected_state="Automatische KMS Key Rotation aktiviert (jährlich)",
                                        remediation=(
                                            "Aktivieren Sie die automatische Key-Rotation: "
                                            "aws kms enable-key-rotation --key-id <key-id>"
                                        ),
                                        remediation_effort="LOW",
                                        audit_evidence=f"GetKeyRotationStatus: KeyRotationEnabled=false for {key_id}",
                                    )
                                )
                        except Exception as e:
                            errors.append(
                                CheckError(
                                    message=f"KMS Key {key_id} Check fehlgeschlagen: {e}",
                                    error_type="AWSClientError",
                                )
                            )

        except Exception as e:
            errors.append(
                CheckError(message=f"KMS Key Rotation Check fehlgeschlagen: {e}", error_type=type(e).__name__)
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckTlsPolicy(BaseCheck):
    """Check ELB/ALB HTTPS listeners against a deny-list of known-insecure predefined TLS policies."""

    check_id = "AWS-NR8-005"
    title = "ELB/ALB TLS Policy (Deny-List bekannter unsicherer Policies)"
    description = (
        "Prüft ob HTTPS-Listener von Load Balancern eine der bekannten unsicheren "
        "vordefinierten AWS-TLS-Policies verwenden."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
    ]
    pruefgrenzen = (
        "Dieser Check prüft nur gegen eine Liste bekannt unsicherer Predefined-Policies; "
        "die maßgebliche Protokollprüfung erfolgt in AWS-NR8-006. Eigene benannte Policies "
        "sowie alle Predefined-Policies, die nicht auf dieser Deny-Liste stehen, werden "
        "durch diesen Check nicht bewertet (weder als Mangel noch als Positivnachweis)."
    )

    # Deny-list of AWS predefined TLS policies known to permit TLS < 1.2
    INSECURE_POLICIES = {
        "ELBSecurityPolicy-2015-05",
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
        "ELBSecurityPolicy-TLS13-1-0-2021-06",
        "ELBSecurityPolicy-TLS13-1-1-2021-06",
    }

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                elbv2 = session.client("elbv2", region=region)

                try:
                    paginator = elbv2.get_paginator("describe_load_balancers")
                    for page in paginator.paginate():
                        for lb in page.get("LoadBalancers", []):
                            lb_arn = lb["LoadBalancerArn"]
                            listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])

                            for listener in listeners:
                                if listener.get("Protocol") != "HTTPS":
                                    continue

                                policy = listener.get("SslPolicy", "")
                                if policy and policy in self.INSECURE_POLICIES:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title="Load Balancer mit bekannt unsicherer TLS-Policy",
                                            description=(
                                                f"Der HTTPS-Listener von '{lb_arn}' verwendet die "
                                                f"vordefinierte TLS-Policy '{policy}', die bekanntermaßen "
                                                f"TLS-Versionen unter 1.2 zulässt."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control=ISO_CONTROL,
                                            severity=Severity.MEDIUM,
                                            provider=CloudProvider.AWS,
                                            region=region,
                                            resource_id=lb_arn,
                                            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                                            account_id=session.account_id,
                                            current_state={"ssl_policy": policy, "protocol": "HTTPS"},
                                            expected_state=(
                                                "TLS Policy nicht auf der Deny-Liste bekannt unsicherer "
                                                "Predefined-Policies (z.B. ELBSecurityPolicy-TLS-1-2-2017-01)"
                                            ),
                                            remediation=(
                                                "Ändern Sie die TLS-Policy des Listeners auf eine Policy "
                                                "die mindestens "
                                                "TLS 1.2 erzwingt, z.B. ELBSecurityPolicy-TLS-1-2-2017-01 oder neuer."
                                            ),
                                            remediation_effort="LOW",
                                            audit_evidence=f"DescribeListeners: SslPolicy={policy}",
                                        )
                                    )
                                # Any other policy (custom or predefined but not on the
                                # deny-list) is not judged by this check — the definitive
                                # protocol-based evaluation happens in AWS-NR8-006.
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"ELB TLS Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(CheckError(message=f"TLS Policy Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckElbTlsMinVersion(BaseCheck):
    """Check that ELB/ALB SSL policies enforce at least TLS 1.2 via DescribeSSLPolicies."""

    check_id = "AWS-NR8-006"
    title = "ELB/ALB TLS Mindestversion"
    description = "Prüft über DescribeSSLPolicies ob die SSL-Policies der Load Balancer mindestens TLS 1.2 erzwingen."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeSSLPolicies",
    ]
    pruefgrenzen = (
        "Prüft die TLS-Mindestversion der Listener-Policies. Nicht geprüft werden "
        "Endpunkte außerhalb von ELB/ALB (z. B. CloudFront, API Gateway, eigene Server)."
    )

    # TLS protocol versions that are considered insecure
    INSECURE_PROTOCOLS = {"TLSv1", "TLSv1.1"}

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                elbv2 = session.client("elbv2", region=region)

                try:
                    paginator = elbv2.get_paginator("describe_load_balancers")
                    for page in paginator.paginate():
                        for lb in page.get("LoadBalancers", []):
                            lb_arn = lb["LoadBalancerArn"]
                            listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])

                            for listener in listeners:
                                # HTTPS (ALB) and TLS (NLB) listeners both terminate TLS
                                # and are governed by an SSL policy (B-Nr.8-4).
                                if listener.get("Protocol") not in ("HTTPS", "TLS"):
                                    continue

                                policy_name = listener.get("SslPolicy", "")
                                if not policy_name:
                                    continue

                                try:
                                    ssl_policies = elbv2.describe_ssl_policies(Names=[policy_name]).get(
                                        "SslPolicies", []
                                    )

                                    if not ssl_policies:
                                        errors.append(
                                            CheckError(
                                                message=(
                                                    f"DescribeSSLPolicies für Policy {policy_name} lieferte "
                                                    "keine Daten — TLS-Mindestversion nicht bewertbar"
                                                ),
                                                error_type="UnverifiableState",
                                            )
                                        )
                                        continue

                                    policy = ssl_policies[0]
                                    protocols = set(policy.get("SslProtocols", []))

                                    insecure = protocols & self.INSECURE_PROTOCOLS
                                    if protocols and not insecure:
                                        findings.append(
                                            compliant_finding(
                                                self,
                                                title="Load Balancer erzwingt TLS 1.2+",
                                                description=(
                                                    f"Die SSL-Policy '{policy_name}' erlaubt nur sichere "
                                                    f"Protokolle: {', '.join(sorted(protocols))}."
                                                ),
                                                region=region,
                                                resource_id=lb_arn,
                                                resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                                                account_id=session.account_id,
                                                current_state={
                                                    "ssl_policy": policy_name,
                                                    "all_protocols": sorted(protocols),
                                                },
                                                expected_state="SSL-Policy mit ausschließlich TLS 1.2 und TLS 1.3",
                                                audit_evidence=(
                                                    f"DescribeSSLPolicies: {policy_name} allows only "
                                                    f"{', '.join(sorted(protocols))}"
                                                ),
                                                iso27001_control=ISO_CONTROL,
                                            )
                                        )
                                    elif insecure:
                                        findings.append(
                                            Finding(
                                                check_id=self.check_id,
                                                title="Load Balancer erlaubt unsichere TLS-Versionen",
                                                description=(
                                                    f"Die SSL-Policy '{policy_name}' erlaubt die "
                                                    f"unsicheren Protokolle: {', '.join(sorted(insecure))}. "
                                                    f"Nur TLS 1.2+ sollte zugelassen werden."
                                                ),
                                                bsig_30_nr=BSIG_30_NR,
                                                bsig_30_text=BSIG_30_TEXT,
                                                iso27001_control=ISO_CONTROL,
                                                severity=Severity.HIGH,
                                                provider=CloudProvider.AWS,
                                                region=region,
                                                resource_id=lb_arn,
                                                resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                                                account_id=session.account_id,
                                                current_state={
                                                    "ssl_policy": policy_name,
                                                    "insecure_protocols": sorted(insecure),
                                                    "all_protocols": sorted(protocols),
                                                },
                                                expected_state="SSL-Policy mit ausschließlich TLS 1.2 und TLS 1.3",
                                                remediation=(
                                                    "Ändern Sie die SSL-Policy des Listeners auf eine "
                                                    "Policy die nur TLS 1.2+ erlaubt, z.B. "
                                                    "ELBSecurityPolicy-TLS13-1-2-2021-06."
                                                ),
                                                remediation_effort="LOW",
                                                audit_evidence=(
                                                    f"DescribeSSLPolicies: {policy_name} allows "
                                                    f"{', '.join(sorted(insecure))}"
                                                ),
                                            )
                                        )
                                except Exception as e:
                                    errors.append(
                                        CheckError(
                                            message=f"SSL Policy {policy_name} Check fehlgeschlagen: {e}",
                                            error_type="AWSClientError",
                                        )
                                    )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"ELB TLS Min Version Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"ELB TLS Min Version Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


ACM_EXPIRY_WARNING_DAYS = 30


class CheckAcmCertificateExpiry(BaseCheck):
    """Check that ACM certificates are not expired or about to expire."""

    check_id = "AWS-NR8-007"
    title = "ACM Zertifikats-Ablauf"
    description = (
        f"Prüft ob ACM-Zertifikate gültig sind und nicht innerhalb von {ACM_EXPIRY_WARNING_DAYS} Tagen ablaufen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["acm:ListCertificates", "acm:DescribeCertificate"]
    pruefgrenzen = (
        "Prüft nur in ACM verwaltete Zertifikate auf Ablauf. Extern beschaffte, "
        "manuell installierte Zertifikate werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        now = datetime.now(UTC)

        try:
            for region in session.regions:
                acm = session.client("acm", region=region)

                try:
                    paginator = acm.get_paginator("list_certificates")
                    for page in paginator.paginate():
                        for cert_summary in page.get("CertificateSummaryList", []):
                            cert_arn = cert_summary["CertificateArn"]

                            try:
                                cert = acm.describe_certificate(CertificateArn=cert_arn).get("Certificate", {})

                                not_after = cert.get("NotAfter")
                                if not_after is None:
                                    continue

                                if not_after.tzinfo is None:
                                    not_after = not_after.replace(tzinfo=UTC)

                                days_remaining = (not_after - now).days
                                domain = cert.get("DomainName", "unknown")
                                status = cert.get("Status", "unknown")

                                if days_remaining < 0:
                                    severity = Severity.CRITICAL
                                    title = "ACM-Zertifikat abgelaufen"
                                    desc = (
                                        f"Das ACM-Zertifikat für '{domain}' "
                                        f"ist seit {abs(days_remaining)} Tagen abgelaufen."
                                    )
                                elif days_remaining <= ACM_EXPIRY_WARNING_DAYS:
                                    severity = Severity.HIGH
                                    title = "ACM-Zertifikat läuft bald ab"
                                    desc = f"Das ACM-Zertifikat für '{domain}' läuft in {days_remaining} Tagen ab."
                                else:
                                    findings.append(
                                        compliant_finding(
                                            self,
                                            title="ACM-Zertifikat gültig",
                                            description=(
                                                f"Das ACM-Zertifikat für '{domain}' ist noch "
                                                f"{days_remaining} Tage gültig."
                                            ),
                                            region=region,
                                            resource_id=cert_arn,
                                            resource_type="AWS::ACM::Certificate",
                                            account_id=session.account_id,
                                            current_state={
                                                "days_remaining": days_remaining,
                                                "not_after": not_after.isoformat(),
                                                "status": status,
                                                "domain_name": domain,
                                            },
                                            expected_state=(
                                                f"Zertifikat gültig mit mehr als "
                                                f"{ACM_EXPIRY_WARNING_DAYS} Tagen Restlaufzeit"
                                            ),
                                            audit_evidence=(
                                                f"DescribeCertificate: NotAfter={not_after.isoformat()}, "
                                                f"DaysRemaining={days_remaining}"
                                            ),
                                            iso27001_control=ISO_CONTROL,
                                        )
                                    )
                                    continue

                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title=title,
                                        description=desc,
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL,
                                        severity=severity,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=cert_arn,
                                        resource_type="AWS::ACM::Certificate",
                                        account_id=session.account_id,
                                        current_state={
                                            "days_remaining": days_remaining,
                                            "not_after": not_after.isoformat(),
                                            "status": status,
                                            "domain_name": domain,
                                        },
                                        expected_state=(
                                            f"Zertifikat gültig mit mehr als "
                                            f"{ACM_EXPIRY_WARNING_DAYS} Tagen Restlaufzeit"
                                        ),
                                        remediation=(
                                            "Erneuern oder ersetzen Sie das Zertifikat. "
                                            "Für ACM-verwaltete Zertifikate: Prüfen Sie die "
                                            "DNS-Validierung. Für importierte Zertifikate: "
                                            "Importieren Sie ein neues Zertifikat."
                                        ),
                                        remediation_effort="MEDIUM",
                                        audit_evidence=(
                                            f"DescribeCertificate: NotAfter={not_after.isoformat()}, "
                                            f"DaysRemaining={days_remaining}"
                                        ),
                                    )
                                )
                            except Exception as e:
                                errors.append(
                                    CheckError(
                                        message=f"ACM Cert {cert_arn} Check fehlgeschlagen: {e}",
                                        error_type="AWSClientError",
                                    )
                                )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"ACM Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"ACM Certificate Expiry Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
