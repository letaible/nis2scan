"""§30 Abs. 2 Nr. 9 — Zugriffskontrolle & Asset-Management checks for AWS.

Checks IAM users, access keys, S3 public access, security group rules,
IAM policy wildcards, and S3 bucket policies.
"""

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 9
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 9 BSIG — Erstellung von Konzepten für die Sicherheit des "
    "Personals, die Zugriffskontrolle und für die Verwaltung von IKT-Systemen, "
    "-Produkten und -Prozessen"
)
ISO_CONTROL_ACCESS = "A.5.15-A.5.18 Access control"
ISO_CONTROL_ASSET = "A.5.9-A.5.14 Asset management"

ACCESS_KEY_MAX_AGE_DAYS = 90
UNUSED_CREDENTIAL_DAYS = 90


class CheckIamMfa(BaseCheck):
    """Check that all IAM users have MFA enabled."""

    check_id = "AWS-NR9-001"
    title = "IAM User MFA Status"
    description = "Prüft ob alle IAM-Benutzer MFA aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListUsers", "iam:ListMFADevices", "iam:GetLoginProfile"]
    pruefgrenzen = (
        "Prüft nur IAM-Benutzer mit Konsolen-Login. Föderierte Zugänge (SSO/IdP) "
        "werden vom Identitätsanbieter durchgesetzt und hier nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    user_arn = user["Arn"]

                    try:
                        iam.get_login_profile(UserName=username)
                    except iam.exceptions.NoSuchEntityException:
                        # No console login — out of scope for this check (pruefgrenzen)
                        continue

                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

                    if mfa_devices:
                        findings.append(
                            compliant_finding(
                                self,
                                title="IAM-Benutzer mit MFA",
                                description=(f"Der IAM-Benutzer '{username}' hat MFA-Authentifizierung konfiguriert."),
                                region="global",
                                resource_id=user_arn,
                                resource_type="AWS::IAM::User",
                                account_id=session.account_id,
                                current_state={"mfa_enabled": True, "user_name": username},
                                expected_state="MFA aktiviert (Virtual MFA, Hardware-Token, oder FIDO2)",
                                audit_evidence=(
                                    f"ListMFADevices returned {len(mfa_devices)} device(s) for user {username}"
                                ),
                                iso27001_control=ISO_CONTROL_ACCESS,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="IAM-Benutzer ohne MFA",
                                description=(
                                    f"Der IAM-Benutzer '{username}' hat keine MFA-Authentifizierung "
                                    f"konfiguriert. Ohne MFA ist der Account anfällig für Credential-basierte Angriffe."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL_ACCESS,
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region="global",
                                resource_id=user_arn,
                                resource_type="AWS::IAM::User",
                                account_id=session.account_id,
                                current_state={"mfa_enabled": False, "user_name": username},
                                expected_state="MFA aktiviert (Virtual MFA, Hardware-Token, oder FIDO2)",
                                remediation=(
                                    "Aktivieren Sie MFA für den IAM-Benutzer. Empfohlen: FIDO2 Security Key "
                                    "oder Virtual MFA App. AWS Console: IAM → Users → Security credentials → MFA"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"ListMFADevices returned 0 devices for user {username}",
                            )
                        )

        except Exception as e:
            errors.append(CheckError(message=f"IAM MFA Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIamAccessKeyAge(BaseCheck):
    """Check that IAM access keys are not older than 90 days."""

    check_id = "AWS-NR9-002"
    title = "IAM Access Key Rotation"
    description = f"Prüft ob IAM Access Keys älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListUsers", "iam:ListAccessKeys"]
    pruefgrenzen = (
        "Prüft nur das Alter aktiver IAM-Access-Keys. Ob ein Key kompromittiert "
        "oder ungenutzt ist, wird in AWS-NR9-007 bzw. gar nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")
            now = datetime.now(UTC)

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    user_arn = user["Arn"]

                    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

                    for key in keys:
                        if key.get("Status") != "Active":
                            continue

                        created = key["CreateDate"]
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=UTC)

                        age_days = (now - created).days

                        if age_days <= ACCESS_KEY_MAX_AGE_DAYS:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="IAM Access Key aktuell rotiert",
                                    description=(
                                        f"Der aktive Access Key für Benutzer '{username}' ist "
                                        f"{age_days} Tage alt (Maximum: {ACCESS_KEY_MAX_AGE_DAYS} Tage)."
                                    ),
                                    region="global",
                                    resource_id=user_arn,
                                    resource_type="AWS::IAM::AccessKey",
                                    account_id=session.account_id,
                                    current_state={
                                        "access_key_age_days": age_days,
                                        "user_name": username,
                                    },
                                    expected_state=f"Access Key nicht älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage",
                                    audit_evidence=f"ListAccessKeys: Key age={age_days}d for user {username}",
                                    iso27001_control=ISO_CONTROL_ACCESS,
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="IAM Access Key älter als 90 Tage",
                                    description=(
                                        f"Der aktive Access Key für Benutzer '{username}' "
                                        f"ist {age_days} Tage alt. Access Keys sollten regelmäßig rotiert werden."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL_ACCESS,
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.AWS,
                                    region="global",
                                    resource_id=user_arn,
                                    resource_type="AWS::IAM::AccessKey",
                                    account_id=session.account_id,
                                    current_state={
                                        "access_key_age_days": age_days,
                                        "user_name": username,
                                    },
                                    expected_state=f"Access Key nicht älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage",
                                    remediation=(
                                        "Erstellen Sie einen neuen Access Key und deaktivieren/löschen Sie den alten. "
                                        "Besser: Nutzen Sie IAM Roles statt langlebiger Access Keys."
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(f"ListAccessKeys: Key age={age_days}d for user {username}"),
                                )
                            )

        except Exception as e:
            errors.append(CheckError(message=f"Access Key Age Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckS3PublicAccessBlock(BaseCheck):
    """Check that S3 public access block is enabled at account level."""

    check_id = "AWS-NR9-003"
    title = "S3 Account-Level Public Access Block"
    description = "Prüft ob der S3 Public Access Block auf Account-Ebene aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["s3:GetAccountPublicAccessBlock"]
    pruefgrenzen = (
        "Prüft nur den Account-weiten S3 Public Access Block. Bucket-Ebene wird in "
        "AWS-NR9-006 geprüft; andere öffentlich exponierbare Dienste sind nicht erfasst."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            s3control = session.client("s3control")
            account_id = session.account_id

            try:
                response = s3control.get_public_access_block(AccountId=account_id)
                config = response.get("PublicAccessBlockConfiguration", {})

                all_blocked = all(
                    [
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False),
                    ]
                )

                if all_blocked:
                    findings.append(
                        compliant_finding(
                            self,
                            title="S3 Public Access Block vollständig aktiviert",
                            description=(
                                "Alle vier S3 Public Access Block Einstellungen sind auf Account-Ebene aktiviert."
                            ),
                            region="global",
                            resource_id=f"arn:aws:s3:::account-{account_id}",
                            resource_type="AWS::S3::AccountPublicAccessBlock",
                            account_id=account_id,
                            current_state=dict(config.items()),
                            expected_state="Alle vier Public Access Block Einstellungen auf true",
                            audit_evidence=f"GetPublicAccessBlock: {config}",
                            iso27001_control=ISO_CONTROL_ACCESS,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="S3 Public Access Block nicht vollständig aktiviert",
                            description=(
                                "Der S3 Public Access Block auf Account-Ebene ist nicht vollständig aktiviert. "
                                "Dies ermöglicht potenziell öffentlichen Zugriff auf S3-Buckets."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL_ACCESS,
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:s3:::account-{account_id}",
                            resource_type="AWS::S3::AccountPublicAccessBlock",
                            account_id=account_id,
                            current_state={k: v for k, v in config.items()},
                            expected_state="Alle vier Public Access Block Einstellungen auf true",
                            remediation=(
                                "Aktivieren Sie alle vier S3 Public Access Block Einstellungen auf Account-Ebene: "
                                "aws s3control put-public-access-block --account-id <id> "
                                "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                                "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"GetPublicAccessBlock: {config}",
                        )
                    )

            except Exception as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="S3 Public Access Block nicht konfiguriert",
                            description="Kein S3 Public Access Block auf Account-Ebene konfiguriert.",
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL_ACCESS,
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:s3:::account-{account_id}",
                            resource_type="AWS::S3::AccountPublicAccessBlock",
                            account_id=account_id,
                            current_state={"public_access_block": "not_configured"},
                            expected_state="S3 Public Access Block vollständig konfiguriert und aktiviert",
                            remediation=(
                                "Konfigurieren Sie den S3 Public Access Block auf Account-Ebene. "
                                "Dies ist eine der wichtigsten Sicherheitsmaßnahmen für S3."
                            ),
                            remediation_effort="LOW",
                            audit_evidence="GetPublicAccessBlock: NoSuchPublicAccessBlockConfiguration",
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=f"S3 Public Access Block Check fehlgeschlagen: {e}",
                            error_type=type(e).__name__,
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"S3 Public Access Block Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecurityGroupOpenAccess(BaseCheck):
    """Check for security groups with unrestricted inbound access (0.0.0.0/0)."""

    check_id = "AWS-NR9-004"
    title = "Security Group Open Access"
    description = (
        "Prüft ob Security Groups unrestricted Inbound-Zugriff (0.0.0.0/0 bzw. ::/0) "
        "auf kritische/administrative Ports erlauben."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ec2:DescribeSecurityGroups"]
    pruefgrenzen = (
        "Prüft Security-Group-Regeln auf offene kritische/administrative Ports "
        "(SSH/RDP u. a.) sowie Vollbereichs-Freigaben (alle Ports) von 0.0.0.0/0 "
        "bzw. ::/0. Öffentliche Regeln auf nicht-administrative Ports werden nicht "
        "bewertet. Ob hinter einer offenen Regel tatsächlich eine Instanz "
        "erreichbar ist (Routing, NACLs), wird nicht geprüft."
    )

    CRITICAL_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                ec2 = session.client("ec2", region=region)
                paginator = ec2.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        sg_id = sg["GroupId"]
                        sg_open = False

                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort", 0)
                            to_port = rule.get("ToPort", 65535)
                            ip_protocol = rule.get("IpProtocol", "")

                            # Check if any critical/administrative port is in the range
                            exposed_ports = {
                                p: name for p, name in self.CRITICAL_PORTS.items() if from_port <= p <= to_port
                            }
                            is_full_range = ip_protocol == "-1" or (from_port == 0 and to_port == 65535)

                            if not exposed_ports and not is_full_range:
                                # Publicly open, but only on a non-critical/non-administrative
                                # port range — out of scope (pruefgrenzen), no finding.
                                continue

                            if exposed_ports:
                                port_desc = ", ".join(f"{p} ({n})" for p, n in exposed_ports.items())
                            else:
                                port_desc = "Alle Ports (0-65535)"

                            open_cidrs = [
                                ip_range["CidrIp"]
                                for ip_range in rule.get("IpRanges", [])
                                if ip_range.get("CidrIp") == "0.0.0.0/0"
                            ]
                            open_cidrs += [
                                ipv6_range["CidrIpv6"]
                                for ipv6_range in rule.get("Ipv6Ranges", [])
                                if ipv6_range.get("CidrIpv6") == "::/0"
                            ]

                            for cidr in open_cidrs:
                                sg_open = True
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title=f"Security Group mit öffentlichem Zugriff auf {port_desc}",
                                        description=(
                                            f"Die Security Group '{sg_id}' erlaubt eingehenden Zugriff "
                                            f"von {cidr} auf Port(s) {port_desc}."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control=ISO_CONTROL_ACCESS,
                                        severity=Severity.CRITICAL,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=sg_id,
                                        resource_type="AWS::EC2::SecurityGroup",
                                        account_id=session.account_id,
                                        current_state={
                                            "from_port": from_port,
                                            "to_port": to_port,
                                            "cidr": cidr,
                                        },
                                        expected_state=(
                                            "Kein unrestricted Inbound-Zugriff auf kritische/administrative Ports"
                                        ),
                                        remediation=(
                                            "Beschränken Sie den Zugriff auf spezifische IP-Bereiche oder "
                                            "verwenden Sie AWS Systems Manager Session Manager für SSH-Zugriff "
                                            "anstelle von öffentlichen Security-Group-Regeln."
                                        ),
                                        remediation_effort="LOW",
                                        audit_evidence=(
                                            f"DescribeSecurityGroups: {sg_id} allows {cidr} on {port_desc}"
                                        ),
                                    )
                                )

                        if not sg_open:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Security Group ohne öffentlichen Zugriff",
                                    description=(
                                        f"Die Security Group '{sg_id}' erlaubt keinen eingehenden "
                                        f"Zugriff von 0.0.0.0/0 oder ::/0 auf kritische/administrative Ports."
                                    ),
                                    region=region,
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    account_id=session.account_id,
                                    current_state={"open_to_internet": False},
                                    expected_state=(
                                        "Kein unrestricted Inbound-Zugriff auf kritische/administrative Ports"
                                    ),
                                    audit_evidence=(
                                        f"DescribeSecurityGroups: {sg_id} has no public inbound rule on "
                                        f"critical/administrative ports"
                                    ),
                                    iso27001_control=ISO_CONTROL_ACCESS,
                                )
                            )

        except Exception as e:
            errors.append(CheckError(message=f"Security Group Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIamWildcardPolicy(BaseCheck):
    """Check for IAM policies with wildcard (*) permissions."""

    check_id = "AWS-NR9-005"
    title = "IAM Wildcard Policies"
    description = (
        "Prüft ob IAM-Policies Wildcard-Berechtigungen (Action: * oder Resource: *) "
        "enthalten, die gegen das Least-Privilege-Prinzip verstoßen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion"]
    pruefgrenzen = (
        "Prüft kundenverwaltete IAM-Policies auf Wildcard-Aktionen (Action = * oder "
        "service-weit wie s3:*) in Kombination mit uneingeschränkten Ressourcen "
        "(Resource = *). AWS-verwaltete Policies und die effektive Wirkung über "
        "Policy-Kombinationen werden nicht bewertet. Ressourcen-gescopte Wildcards "
        "(z. B. arn:aws:s3:::bucket/*) und feingranulare Action-Muster werden nicht "
        "bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local", OnlyAttached=False):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    policy_name = policy.get("PolicyName", "unknown")
                    version_id = policy.get("DefaultVersionId", "v1")

                    try:
                        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get(
                            "PolicyVersion", {}
                        )

                        doc = version.get("Document", {})
                        # Document may be URL-encoded JSON string
                        if isinstance(doc, str):
                            from urllib.parse import unquote

                            doc = json.loads(unquote(doc))

                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]

                        wildcard_issues: list[str] = []
                        for stmt in statements:
                            if stmt.get("Effect") != "Allow":
                                continue

                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            resources = stmt.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]

                            # A wildcard action is "*" or a service-wide wildcard like
                            # "s3:*". Resource-scoped paths (arn:...:bucket/*) remain
                            # allowed — only Resource == "*" counts as unrestricted.
                            wildcard_actions = [a for a in actions if a == "*" or a.endswith(":*")]
                            if wildcard_actions and "*" in resources:
                                wildcard_issues.append(
                                    f"Action {', '.join(sorted(set(wildcard_actions)))} mit Resource: *"
                                )

                        if not wildcard_issues:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="IAM-Policy ohne Wildcard-Berechtigungen",
                                    description=(
                                        f"Die IAM-Policy '{policy_name}' enthält keine service-weiten "
                                        f"Wildcard-Aktionen (Action = * oder service:*) in Kombination "
                                        f"mit uneingeschränkten Ressourcen."
                                    ),
                                    region="global",
                                    resource_id=policy_arn,
                                    resource_type="AWS::IAM::Policy",
                                    account_id=session.account_id,
                                    current_state={
                                        "wildcard_issues": [],
                                        "policy_name": policy_name,
                                    },
                                    expected_state=(
                                        "IAM-Policies mit spezifischen Actions und Resources "
                                        "nach dem Least-Privilege-Prinzip"
                                    ),
                                    audit_evidence=f"GetPolicyVersion: no wildcards in policy {policy_name}",
                                    iso27001_control=ISO_CONTROL_ACCESS,
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="IAM-Policy mit Wildcard-Berechtigungen",
                                    description=(
                                        f"Die IAM-Policy '{policy_name}' enthält "
                                        f"Wildcard-Berechtigungen: {', '.join(wildcard_issues)}. "
                                        f"Dies verstößt gegen das Least-Privilege-Prinzip."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control=ISO_CONTROL_ACCESS,
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.AWS,
                                    region="global",
                                    resource_id=policy_arn,
                                    resource_type="AWS::IAM::Policy",
                                    account_id=session.account_id,
                                    current_state={
                                        "wildcard_issues": wildcard_issues,
                                        "policy_name": policy_name,
                                        "attachment_count": policy.get("AttachmentCount", 0),
                                    },
                                    expected_state=(
                                        "IAM-Policies mit spezifischen Actions und Resources "
                                        "nach dem Least-Privilege-Prinzip"
                                    ),
                                    remediation=(
                                        "Ersetzen Sie die Wildcard-Berechtigungen durch spezifische "
                                        "Actions und Resources. Verwenden Sie IAM Access Analyzer "
                                        "um die tatsächlich benötigten Berechtigungen zu ermitteln."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(
                                        f"GetPolicyVersion: {', '.join(wildcard_issues)} in policy {policy_name}"
                                    ),
                                )
                            )
                    except Exception as e:
                        errors.append(
                            CheckError(
                                message=f"IAM Policy {policy_name} Check fehlgeschlagen: {e}",
                                error_type="AWSClientError",
                            )
                        )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"IAM Wildcard Policy Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckS3BucketPolicy(BaseCheck):
    """Check for S3 bucket policies that allow public access (Principal: *)."""

    check_id = "AWS-NR9-006"
    title = "S3 Bucket Policy Public Access"
    description = "Prüft ob S3-Bucket-Policies öffentlichen Zugriff über Principal: * erlauben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketLocation",
    ]
    pruefgrenzen = (
        "Prüft Bucket-Policies auf öffentliche Freigaben (Principal: *). Öffentliche "
        "Freigaben über Bucket-ACLs, Zugriffe über CloudFront-Distributionen oder "
        "vorsignierte URLs sind nicht Gegenstand."
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
                    policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
                    policy_doc = json.loads(policy_str)

                    statements = policy_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    public_statements = []
                    for stmt in statements:
                        if stmt.get("Effect") != "Allow":
                            continue

                        principal = stmt.get("Principal", {})
                        is_public = False

                        if principal == "*":
                            is_public = True
                        elif isinstance(principal, dict):
                            aws_principal = principal.get("AWS", "")
                            if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                                is_public = True

                        if is_public:
                            public_statements.append(stmt)

                    unconditional = [s for s in public_statements if not s.get("Condition", {})]
                    conditional = [s for s in public_statements if s.get("Condition", {})]

                    if unconditional:
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        region = location.get("LocationConstraint") or "us-east-1"
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="S3-Bucket-Policy erlaubt öffentlichen Zugriff",
                                description=(
                                    "Die Bucket-Policy erlaubt Zugriff für Principal: * ohne Bedingung. "
                                    "Dies kann zu ungewollter Datenexposition führen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL_ACCESS,
                                severity=Severity.CRITICAL,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=session.account_id,
                                current_state={
                                    "principal": "*",
                                    "effect": "Allow",
                                    "has_condition": False,
                                },
                                expected_state="Kein Principal: * in Bucket-Policies",
                                remediation=(
                                    "Entfernen Sie den öffentlichen Zugriff aus der Bucket-Policy. "
                                    "Verwenden Sie stattdessen spezifische IAM-Rollen oder "
                                    "Account-IDs als Principal."
                                ),
                                remediation_effort="LOW",
                                audit_evidence="GetBucketPolicy: Principal=* with Effect=Allow, no Condition",
                            )
                        )
                    elif conditional:
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        region = location.get("LocationConstraint") or "us-east-1"
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Öffentlicher Bucket-Principal mit Bedingung — manuell prüfen",
                                description=(
                                    f"Der Bucket '{bucket_name}' hat ein Allow-Statement mit "
                                    f"Principal: * und einer Condition. Die Wirksamkeit der Bedingung "
                                    f"wird nicht automatisch bewertet und muss manuell geprüft werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL_ACCESS,
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="AWS::S3::Bucket",
                                account_id=session.account_id,
                                current_state={
                                    "principal": "*",
                                    "effect": "Allow",
                                    "has_condition": True,
                                },
                                expected_state=(
                                    "Keine Allow-Statements mit Principal: * ohne geprüfte Zugriffsbeschränkung"
                                ),
                                remediation=(
                                    "Prüfen Sie manuell, ob die Condition den Zugriff wirksam auf "
                                    "vertrauenswürdige Quellen einschränkt (z. B. aws:SourceArn, "
                                    "aws:SourceVpce). Entfernen Sie Principal: * falls die Bedingung "
                                    "keine ausreichende Einschränkung bietet."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence="GetBucketPolicy: Principal=* with Effect=Allow and Condition present",
                            )
                        )
                    else:
                        findings.append(self._compliant_bucket(session, bucket_name, "Bucket-Policy ohne Principal: *"))

                except s3.exceptions.ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "NoSuchBucketPolicy":
                        # No policy = no public access = compliant
                        findings.append(self._compliant_bucket(session, bucket_name, "Keine Bucket-Policy vorhanden"))
                        continue
                    errors.append(
                        CheckError(
                            message=(f"S3 Bucket Policy Check für {bucket_name} fehlgeschlagen: {error_code}"),
                            error_type="AWSClientError",
                        )
                    )
                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"S3 Bucket Policy Check fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"S3 Bucket Policy Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)

    def _compliant_bucket(self, session: Any, bucket_name: str, evidence: str) -> Finding:
        return compliant_finding(
            self,
            title="S3-Bucket ohne öffentliche Bucket-Policy",
            description=f"Der S3-Bucket '{bucket_name}' erlaubt keinen öffentlichen Zugriff über die Bucket-Policy.",
            region="global",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_type="AWS::S3::Bucket",
            account_id=session.account_id,
            current_state={"public_policy": False},
            expected_state="Kein Principal: * in Bucket-Policies",
            audit_evidence=f"GetBucketPolicy: {evidence}",
            iso27001_control=ISO_CONTROL_ACCESS,
        )


class CheckUnusedIamCredentials(BaseCheck):
    """Check for IAM access keys that have not been used in over 90 days."""

    check_id = "AWS-NR9-007"
    title = "Ungenutzte IAM-Zugangsdaten"
    description = f"Prüft ob IAM Access Keys seit mehr als {UNUSED_CREDENTIAL_DAYS} Tagen nicht verwendet wurden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
    ]
    pruefgrenzen = (
        "Bewertet Ungenutztheit anhand der letzten Nutzung laut IAM-Credential-Daten. "
        "AWS aktualisiert diese Angaben mit Verzögerung; sehr seltene, legitime "
        "Nutzung (z. B. Break-Glass) erscheint ebenfalls als ungenutzt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")
            now = datetime.now(UTC)

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    user_arn = user["Arn"]

                    try:
                        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

                        for key in keys:
                            if key.get("Status") != "Active":
                                continue

                            access_key_id = key["AccessKeyId"]
                            created = key["CreateDate"]
                            if created.tzinfo is None:
                                created = created.replace(tzinfo=UTC)

                            last_used_resp = iam.get_access_key_last_used(AccessKeyId=access_key_id).get(
                                "AccessKeyLastUsed", {}
                            )

                            last_used_date = last_used_resp.get("LastUsedDate")

                            if last_used_date is None:
                                # Never used — check if key is old enough
                                days_since_creation = (now - created).days
                                if days_since_creation > UNUSED_CREDENTIAL_DAYS:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title="IAM Access Key nie verwendet",
                                            description=(
                                                f"Der Access Key für Benutzer '{username}' "
                                                f"wurde seit der Erstellung vor {days_since_creation} Tagen "
                                                f"nie verwendet."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control=ISO_CONTROL_ACCESS,
                                            severity=Severity.MEDIUM,
                                            provider=CloudProvider.AWS,
                                            region="global",
                                            resource_id=user_arn,
                                            resource_type="AWS::IAM::AccessKey",
                                            account_id=session.account_id,
                                            current_state={
                                                "last_used": "never",
                                                "days_since_creation": days_since_creation,
                                                "user_name": username,
                                            },
                                            expected_state=(
                                                f"Access Key aktiv genutzt oder deaktiviert/gelöscht "
                                                f"wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
                                            ),
                                            remediation=(
                                                "Deaktivieren oder löschen Sie ungenutzte Access Keys: "
                                                "aws iam update-access-key --access-key-id <key-id> "
                                                "--status Inactive --user-name <username>"
                                            ),
                                            remediation_effort="LOW",
                                            audit_evidence=(
                                                f"GetAccessKeyLastUsed: never used, "
                                                f"created {days_since_creation}d ago for "
                                                f"{username}"
                                            ),
                                        )
                                    )
                            else:
                                if last_used_date.tzinfo is None:
                                    last_used_date = last_used_date.replace(tzinfo=UTC)

                                days_unused = (now - last_used_date).days
                                if days_unused <= UNUSED_CREDENTIAL_DAYS:
                                    findings.append(
                                        compliant_finding(
                                            self,
                                            title="IAM Access Key aktiv genutzt",
                                            description=(
                                                f"Der Access Key für Benutzer '{username}' wurde "
                                                f"zuletzt vor {days_unused} Tagen verwendet."
                                            ),
                                            region="global",
                                            resource_id=user_arn,
                                            resource_type="AWS::IAM::AccessKey",
                                            account_id=session.account_id,
                                            current_state={
                                                "days_unused": days_unused,
                                                "last_used": last_used_date.isoformat(),
                                                "user_name": username,
                                            },
                                            expected_state=(
                                                f"Access Key aktiv genutzt oder deaktiviert/gelöscht "
                                                f"wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
                                            ),
                                            audit_evidence=(
                                                f"GetAccessKeyLastUsed: last used {days_unused}d ago for {username}"
                                            ),
                                            iso27001_control=ISO_CONTROL_ACCESS,
                                        )
                                    )
                                else:
                                    findings.append(
                                        Finding(
                                            check_id=self.check_id,
                                            title=f"IAM Access Key seit {days_unused} Tagen ungenutzt",
                                            description=(
                                                f"Der Access Key für Benutzer '{username}' "
                                                f"wurde seit {days_unused} Tagen nicht verwendet."
                                            ),
                                            bsig_30_nr=BSIG_30_NR,
                                            bsig_30_text=BSIG_30_TEXT,
                                            iso27001_control=ISO_CONTROL_ACCESS,
                                            severity=Severity.MEDIUM,
                                            provider=CloudProvider.AWS,
                                            region="global",
                                            resource_id=user_arn,
                                            resource_type="AWS::IAM::AccessKey",
                                            account_id=session.account_id,
                                            current_state={
                                                "days_unused": days_unused,
                                                "last_used": last_used_date.isoformat(),
                                                "user_name": username,
                                            },
                                            expected_state=(
                                                f"Access Key aktiv genutzt oder deaktiviert/gelöscht "
                                                f"wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
                                            ),
                                            remediation=(
                                                "Deaktivieren oder löschen Sie ungenutzte Access Keys: "
                                                "aws iam update-access-key --access-key-id <key-id> "
                                                "--status Inactive --user-name <username>"
                                            ),
                                            remediation_effort="LOW",
                                            audit_evidence=(
                                                f"GetAccessKeyLastUsed: last used {days_unused}d ago for {username}"
                                            ),
                                        )
                                    )

                    except Exception as e:
                        errors.append(
                            CheckError(
                                message=(f"Unused credentials check for {username} fehlgeschlagen: {e}"),
                                error_type="AWSClientError",
                            )
                        )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Unused IAM Credentials Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
