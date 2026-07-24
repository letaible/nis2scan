"""§30 Abs. 2 Nr. 10 — MFA & gesicherte Kommunikation checks for AWS.

Checks root account MFA and IAM user MFA enforcement.
"""

import json
from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 10
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 10 BSIG — Verwendung von Lösungen zur "
    "Multi-Faktor-Authentifizierung oder kontinuierlichen Authentifizierung, "
    "gesicherte Sprach-, Video- und Textkommunikation sowie gegebenenfalls "
    "gesicherte Notfallkommunikationssysteme innerhalb der Einrichtung"
)
ISO_CONTROL = "A.8.5 Secure authentication"


class CheckRootMfa(BaseCheck):
    """Check that the AWS root account has MFA enabled."""

    check_id = "AWS-NR10-001"
    title = "Root Account MFA"
    description = "Prüft ob der AWS Root-Account MFA aktiviert hat."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:GetAccountSummary"]
    pruefgrenzen = (
        "Prüft nur, ob Root-MFA aktiviert ist. Art des zweiten Faktors "
        "(Hardware vs. virtuell) und die sichere Verwahrung werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})

            if summary.get("AccountMFAEnabled", 0):
                findings.append(
                    compliant_finding(
                        self,
                        title="AWS Root-Account mit MFA",
                        description="Der AWS Root-Account hat Multi-Faktor-Authentifizierung aktiviert.",
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:root",
                        resource_type="AWS::IAM::Root",
                        account_id=session.account_id,
                        current_state={"account_mfa_enabled": True},
                        expected_state="Root Account MFA aktiviert (Hardware-Token empfohlen)",
                        audit_evidence="GetAccountSummary: AccountMFAEnabled=1",
                        iso27001_control=ISO_CONTROL,
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="AWS Root-Account ohne MFA",
                        description=(
                            "Der AWS Root-Account hat keine Multi-Faktor-Authentifizierung aktiviert. "
                            "Der Root-Account hat uneingeschränkte Rechte und ist das höchste Angriffsziel."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control=ISO_CONTROL,
                        severity=Severity.CRITICAL,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:root",
                        resource_type="AWS::IAM::Root",
                        account_id=session.account_id,
                        current_state={"account_mfa_enabled": False},
                        expected_state="Root Account MFA aktiviert (Hardware-Token empfohlen)",
                        remediation=(
                            "Aktivieren Sie SOFORT MFA für den Root-Account. Empfohlen: Hardware-Token (YubiKey). "
                            "AWS Console: Account → Security credentials → MFA → Assign MFA device. "
                            "Der Root-Account sollte nach MFA-Aktivierung nicht für den "
                            "täglichen Betrieb verwendet werden."
                        ),
                        remediation_effort="LOW",
                        audit_evidence="GetAccountSummary: AccountMFAEnabled=0",
                    )
                )

        except Exception as e:
            errors.append(CheckError(message=f"Root MFA Check fehlgeschlagen: {e}", error_type=type(e).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIamUserMfaEnforcement(BaseCheck):
    """Check that IAM users with console access have MFA enabled."""

    check_id = "AWS-NR10-002"
    title = "IAM User MFA Enforcement"
    description = "Prüft ob alle IAM-Benutzer mit Konsolen-Zugang MFA aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListUsers", "iam:ListMFADevices", "iam:GetLoginProfile"]
    pruefgrenzen = (
        "Prüft MFA nur für IAM-Benutzer mit Konsolen-Login. Föderierte Zugänge "
        "(SSO/IdP) und programmatische Zugriffe (Access Keys) sind nicht erfasst."
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

                    # Check if user has console access (login profile)
                    try:
                        iam.get_login_profile(UserName=username)
                    except iam.exceptions.NoSuchEntityException:
                        continue  # No console access — out of scope for this check (pruefgrenzen)

                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

                    if mfa_devices:
                        findings.append(
                            compliant_finding(
                                self,
                                title="IAM-Benutzer mit Konsolen-Zugang und MFA",
                                description=(
                                    f"Der IAM-Benutzer '{username}' hat Konsolen-Zugang und MFA konfiguriert."
                                ),
                                region="global",
                                resource_id=user_arn,
                                resource_type="AWS::IAM::User",
                                account_id=session.account_id,
                                current_state={
                                    "has_console_access": True,
                                    "mfa_enabled": True,
                                    "user_name": username,
                                },
                                expected_state="MFA für alle Benutzer mit Konsolen-Zugang erzwungen",
                                audit_evidence=(f"User {username}: has_console=true, mfa_devices={len(mfa_devices)}"),
                                iso27001_control=ISO_CONTROL,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="IAM-Benutzer mit Konsolen-Zugang ohne MFA",
                                description=(
                                    f"Der IAM-Benutzer '{username}' hat Konsolen-Zugang, aber kein MFA-Gerät "
                                    f"konfiguriert. Ohne MFA ist der Konsolen-Zugang nur durch das Passwort "
                                    f"geschützt."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=ISO_CONTROL,
                                severity=Severity.CRITICAL,
                                provider=CloudProvider.AWS,
                                region="global",
                                resource_id=user_arn,
                                resource_type="AWS::IAM::User",
                                account_id=session.account_id,
                                current_state={
                                    "has_console_access": True,
                                    "mfa_enabled": False,
                                    "user_name": username,
                                },
                                expected_state="MFA für alle Benutzer mit Konsolen-Zugang erzwungen",
                                remediation=(
                                    "Erzwingen Sie MFA für alle IAM-Benutzer mit Konsolen-Zugang. "
                                    "Empfohlen: Erstellen Sie eine IAM Policy die API-Aktionen "
                                    "ohne MFA verweigert (aws:MultiFactorAuthPresent condition). "
                                    "Migrieren Sie auf AWS IAM Identity Center (SSO) "
                                    "mit MFA-Pflicht für eine zentralisierte Lösung."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=f"User {username}: has_console=true, mfa_devices=0",
                            )
                        )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"IAM MFA Enforcement Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpnAdminAccess(BaseCheck):
    """Check that VPN or Client VPN is configured for admin access.

    Administrative access to AWS resources should be protected by VPN
    connections to ensure secure communication channels.
    """

    check_id = "AWS-NR10-003"
    title = "VPN / Client VPN für Admin-Zugriff"
    description = "Prüft ob AWS VPN oder Client VPN für gesicherten administrativen Zugriff konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ec2:DescribeVpnGateways", "ec2:DescribeClientVpnEndpoints"]
    pruefgrenzen = (
        "Prüft nur, ob AWS-eigene VPN-Lösungen (Site-to-Site/Client VPN) konfiguriert "
        "sind. Drittanbieter-VPNs, Zero-Trust-Zugänge oder SSM Session Manager als "
        "Admin-Zugriffsweg werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            vpn_found = False

            for region in session.regions:
                ec2 = session.client("ec2", region=region)

                try:
                    # Check Site-to-Site VPN Gateways
                    vpn_gateways = ec2.describe_vpn_gateways().get("VpnGateways", [])
                    active_gateways = [gw for gw in vpn_gateways if gw.get("State") == "available"]
                    if active_gateways:
                        vpn_found = True
                        break

                    # Check Client VPN Endpoints
                    client_vpns = ec2.describe_client_vpn_endpoints().get("ClientVpnEndpoints", [])
                    active_vpns = [vpn for vpn in client_vpns if vpn.get("Status", {}).get("Code") == "available"]
                    if active_vpns:
                        vpn_found = True
                        break

                except Exception as e:
                    errors.append(
                        CheckError(
                            message=f"VPN Check in {region} fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

            if vpn_found:
                findings.append(
                    compliant_finding(
                        self,
                        title="VPN für Admin-Zugriff konfiguriert",
                        description=(
                            "AWS Site-to-Site VPN oder Client VPN ist konfiguriert — ein "
                            "gesicherter Kommunikationskanal für den administrativen Zugriff besteht."
                        ),
                        region="global",
                        resource_id=f"arn:aws:ec2:{session.account_id}:vpn/*",
                        resource_type="AWS::EC2::VPNGateway",
                        account_id=session.account_id,
                        current_state={"vpn_configured": True},
                        expected_state="VPN oder Client VPN für gesicherten Admin-Zugriff konfiguriert",
                        audit_evidence="DescribeVpnGateways/DescribeClientVpnEndpoints: active VPN found",
                        iso27001_control="A.8.20 Networks security",
                    )
                )
            elif not errors:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Kein VPN für Admin-Zugriff konfiguriert",
                        description=(
                            "Weder AWS Site-to-Site VPN noch Client VPN Endpoints sind "
                            "konfiguriert. Ohne VPN fehlt ein gesicherter Kommunikationskanal "
                            "für den administrativen Zugriff auf AWS-Ressourcen."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.20 Networks security",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=f"arn:aws:ec2:{session.account_id}:vpn/*",
                        resource_type="AWS::EC2::VPNGateway",
                        account_id=session.account_id,
                        current_state={"vpn_configured": False, "client_vpn_configured": False},
                        expected_state="VPN oder Client VPN für gesicherten Admin-Zugriff konfiguriert",
                        remediation=(
                            "Konfigurieren Sie AWS Client VPN für administrativen Zugriff: "
                            "aws ec2 create-client-vpn-endpoint --client-cidr-block 10.0.0.0/16 "
                            "--server-certificate-arn <arn> --authentication-options <options>. "
                            "Alternativ: AWS Site-to-Site VPN für Standortanbindung."
                        ),
                        remediation_effort="HIGH",
                        audit_evidence="DescribeVpnGateways + DescribeClientVpnEndpoints: no VPN found",
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"VPN Admin Access Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


def _sns_policy_enforces_tls(policy_str: str) -> bool:
    """Determine whether an SNS topic policy actually enforces TLS.

    Per Rechts-Review B-Nr.10-3: a mere substring match on "aws:SecureTransport"
    is not sufficient — that condition key can appear in an Allow statement with
    value "true", which does not block plaintext access. TLS is only enforced
    when a Deny statement blocks requests where aws:SecureTransport is false
    (as string "false" or boolean False).
    """
    try:
        policy = json.loads(policy_str)
    except (json.JSONDecodeError, TypeError):
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
            continue
        secure_transport = statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        if secure_transport in ("false", False):
            return True
    return False


class CheckSesSnsTls(BaseCheck):
    """Check that SNS enforces TLS for communications.

    SNS topic policies must enforce TLS to ensure encrypted
    communication channels as required by §30 Abs. 2 Nr. 10.
    """

    check_id = "AWS-NR10-004"
    title = "SNS TLS-Erzwingung"
    description = "Prüft ob AWS SNS-Topics TLS (aws:SecureTransport) in ihrer Access Policy erzwingen."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["sns:ListTopics", "sns:GetTopicAttributes"]
    pruefgrenzen = (
        "Prüft nur SNS-Topic-Policies. SES sowie die übrige Unternehmenskommunikation "
        "(E-Mail-Server, Messenger, Video) liegen außerhalb des Scans."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            for region in session.regions:
                # Check SNS topics for HTTPS enforcement
                try:
                    sns = session.client("sns", region=region)
                    topics_resp = sns.list_topics()
                    topics = topics_resp.get("Topics", [])

                    for topic in topics:
                        topic_arn = topic.get("TopicArn", "")
                        try:
                            attrs = sns.get_topic_attributes(TopicArn=topic_arn).get("Attributes", {})
                            # Check if topic has a policy that enforces ssl
                            policy_str = attrs.get("Policy", "{}")
                            topic_name = topic_arn.split(":")[-1] if topic_arn else "unknown"
                            if _sns_policy_enforces_tls(policy_str):
                                findings.append(
                                    compliant_finding(
                                        self,
                                        title="SNS-Topic mit TLS-Erzwingung",
                                        description=(
                                            f"Das SNS-Topic '{topic_name}' erzwingt TLS "
                                            f"(aws:SecureTransport) in seiner Access Policy."
                                        ),
                                        region=region,
                                        resource_id=topic_arn,
                                        resource_type="AWS::SNS::Topic",
                                        account_id=session.account_id,
                                        current_state={"tls_enforced": True, "topic_name": topic_name},
                                        expected_state="SNS Topic Policy mit aws:SecureTransport Condition",
                                        audit_evidence=(
                                            f"GetTopicAttributes: {topic_name} policy has Deny statement "
                                            f"with aws:SecureTransport=false"
                                        ),
                                        iso27001_control="A.8.20 Networks security",
                                    )
                                )
                            else:
                                findings.append(
                                    Finding(
                                        check_id=self.check_id,
                                        title="SNS-Topic ohne TLS-Erzwingung",
                                        description=(
                                            f"Das SNS-Topic '{topic_name}' erzwingt "
                                            f"nicht TLS (aws:SecureTransport) in seiner Access Policy. "
                                            f"Benachrichtigungen könnten unverschlüsselt übertragen werden."
                                        ),
                                        bsig_30_nr=BSIG_30_NR,
                                        bsig_30_text=BSIG_30_TEXT,
                                        iso27001_control="A.8.20 Networks security",
                                        severity=Severity.MEDIUM,
                                        provider=CloudProvider.AWS,
                                        region=region,
                                        resource_id=topic_arn,
                                        resource_type="AWS::SNS::Topic",
                                        account_id=session.account_id,
                                        current_state={
                                            "tls_enforced": False,
                                            "topic_name": topic_name,
                                        },
                                        expected_state="SNS Topic Policy mit aws:SecureTransport Condition",
                                        remediation=(
                                            "Fügen Sie eine Condition zur SNS Topic Policy hinzu: "
                                            '"Condition": {"Bool": {"aws:SecureTransport": "true"}}'
                                        ),
                                        remediation_effort="LOW",
                                        audit_evidence=(
                                            f"GetTopicAttributes: {topic_name} policy has no Deny statement "
                                            f"with aws:SecureTransport=false"
                                        ),
                                    )
                                )
                        except Exception as e:
                            errors.append(
                                CheckError(
                                    message=f"SNS Topic Check fehlgeschlagen: {e}",
                                    error_type="AWSClientError",
                                )
                            )

                except Exception as e:
                    error_str = str(e)
                    if "AuthorizationError" in error_str or "AccessDenied" in error_str:
                        pass  # SNS not accessible — skip
                    else:
                        errors.append(
                            CheckError(
                                message=f"SNS Check in {region} fehlgeschlagen: {e}",
                                error_type="AWSClientError",
                            )
                        )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"SES/SNS TLS Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckBreakGlassProcedure(BaseCheck):
    """Check that a break-glass emergency IAM user is configured."""

    check_id = "AWS-NR10-005"
    title = "Notfall-Break-Glass-Verfahren"
    description = "Prüft ob ein Break-Glass-Notfallzugang konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListUsers", "iam:ListUserTags"]
    pruefgrenzen = (
        "Heuristik: sucht nach Break-Glass-Indikatoren (benannte Notfall-Benutzer/"
        "-Rollen). Ein anders organisiertes Notfallzugriffsverfahren wird nicht "
        "erkannt und ist über die Attestierungs-Checkliste nachzuweisen."
    )

    _BREAK_GLASS_NAME_PATTERNS = (
        "break-glass",
        "breakglass",
        "emergency",
        "notfall",
    )
    _BREAK_GLASS_TAG_KEYS = ("Purpose", "Role")
    _BREAK_GLASS_TAG_VALUES = ("break-glass", "emergency", "notfall", "breakglass", "break_glass")

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")
            break_glass_found = False

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    name_lower = username.lower()

                    # Check username for break-glass patterns
                    if any(p in name_lower for p in self._BREAK_GLASS_NAME_PATTERNS):
                        break_glass_found = True
                        break

                    # Check user tags for break-glass indicators
                    tags_resp = iam.list_user_tags(UserName=username)
                    for tag in tags_resp.get("Tags", []):
                        if tag.get("Key") in self._BREAK_GLASS_TAG_KEYS:
                            tag_val = tag.get("Value", "").lower()
                            if any(v in tag_val for v in self._BREAK_GLASS_TAG_VALUES):
                                break_glass_found = True
                                break
                    if break_glass_found:
                        break
                if break_glass_found:
                    break

            if break_glass_found:
                findings.append(
                    compliant_finding(
                        self,
                        title="Break-Glass-Notfallzugang konfiguriert",
                        description=(
                            "Ein Break-Glass-Notfallzugang wurde im AWS-Account gefunden (Namenskonvention "
                            "oder Tags). Starke MFA und die Dokumentation des Verfahrens sind organisatorisch "
                            "nachzuweisen (Attestierungs-Checkliste) und werden von dieser Prüfung nicht "
                            "verifiziert."
                        ),
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:root",
                        resource_type="AWS::IAM::Account",
                        account_id=session.account_id,
                        current_state={"break_glass_user_found": True},
                        expected_state="Break-Glass-Notfallzugang konfiguriert",
                        audit_evidence="IAM-User mit Break-Glass-Namenskonvention oder entsprechenden Tags gefunden",
                        iso27001_control="A.5.30, A.8.5",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Kein Break-Glass-Notfallzugang erkannt",
                        description=(
                            "Es wurde kein Break-Glass-Notfallzugang im "
                            "AWS-Account gefunden. Organisationen sollten "
                            "einen dokumentierten Notfall-IAM-Benutzer "
                            "mit starker MFA für den Notfall vorhalten. "
                            "Anders organisierte Notfallzugangsverfahren werden von dieser Prüfung nicht erkannt."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.30, A.8.5",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=(f"arn:aws:iam::{session.account_id}:root"),
                        resource_type="AWS::IAM::Account",
                        account_id=session.account_id,
                        current_state={
                            "break_glass_user_found": False,
                        },
                        expected_state=("Break-Glass-Notfallzugang konfiguriert"),
                        remediation=(
                            "Erstellen Sie einen Break-Glass-IAM-Benutzer "
                            "für Notfälle: "
                            "1. IAM-User 'break-glass-admin' anlegen "
                            "2. Hardware-MFA zuweisen "
                            "3. AdminAccess-Policy anhängen "
                            "4. Credentials sicher verwahren (Tresor) "
                            "5. Nutzung per CloudWatch Alarm überwachen"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(
                            "Kein IAM-User mit Break-Glass-Namenskonvention oder entsprechenden Tags gefunden"
                        ),
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=(f"Break-Glass Check fehlgeschlagen: {e}"),
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
        )
