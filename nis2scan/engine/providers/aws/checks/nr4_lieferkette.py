"""§30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for AWS.

Checks Trusted Advisor access, RAM resource shares to external principals,
AWS Organizations FeatureSet, IAM cross-account role trust relationships,
and Service Control Policies for third-party organizational units.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 4
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 4 BSIG — Sicherheit der Lieferkette einschließlich "
    "sicherheitsbezogener Aspekte der Beziehungen zu unmittelbaren Anbietern oder "
    "Diensteanbietern"
)
ISO_CONTROL = "A.5.19-A.5.23 Supplier relationships"


class CheckTrustedAdvisorAccess(BaseCheck):
    """Check that AWS Trusted Advisor is accessible (Business/Enterprise support).

    Trusted Advisor provides automated best-practice checks for security,
    cost optimization, and reliability. Full access requires a Business or
    Enterprise support plan. Basic/Developer plans only get limited checks.
    """

    check_id = "AWS-NR4-001"
    title = "Trusted Advisor Zugang"
    description = (
        "Prüft ob AWS Trusted Advisor vollständig zugänglich ist (erfordert Business- oder Enterprise-Support-Plan)."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["support:DescribeTrustedAdvisorChecks"]
    pruefgrenzen = (
        "Prüft nur, ob Trusted Advisor per API zugänglich ist (erfordert "
        "Business/Enterprise Support). Fehlender Zugang ist ein Hinweis, "
        "kein Lieferketten-Mangel im engeren Sinne."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            # Trusted Advisor API is only available in us-east-1
            support = session.client("support", region="us-east-1")

            try:
                checks = support.describe_trusted_advisor_checks(language="en").get("checks", [])

                # 20 is a deliberate midpoint between Basic (<10 checks) and Business/Enterprise (50+ checks)
                if len(checks) >= 20:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Trusted Advisor vollständig zugänglich",
                            description=(
                                f"AWS Trusted Advisor bietet Zugriff auf {len(checks)} Checks — "
                                f"automatisierte Best-Practice-Prüfungen sind verfügbar."
                            ),
                            region="global",
                            resource_id=f"arn:aws:support:{session.account_id}:trusted-advisor",
                            resource_type="AWS::Support::TrustedAdvisor",
                            account_id=session.account_id,
                            current_state={"available_checks": len(checks)},
                            expected_state=(
                                "Vollständiger Trusted Advisor Zugang (50+ Checks, Business/Enterprise Support)"
                            ),
                            audit_evidence=f"DescribeTrustedAdvisorChecks returned {len(checks)} checks",
                            iso27001_control=ISO_CONTROL,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Eingeschränkter Trusted Advisor Zugang",
                            description=(
                                f"AWS Trusted Advisor hat nur Zugriff auf {len(checks)} Checks. "
                                f"Ein Business- oder Enterprise-Support-Plan bietet Zugriff auf "
                                f"alle Sicherheits- und Best-Practice-Checks. "
                                f"Hinweis: Fehlender Trusted-Advisor-Zugang bedeutet fehlende automatisierte "
                                f"Best-Practice-Prüfungen des Cloud-Anbieters, keinen Lieferketten-Mangel "
                                f"im engeren Sinne."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL,
                            severity=Severity.INFO,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:support:{session.account_id}:trusted-advisor",
                            resource_type="AWS::Support::TrustedAdvisor",
                            account_id=session.account_id,
                            current_state={"available_checks": len(checks)},
                            expected_state=(
                                "Vollständiger Trusted Advisor Zugang (50+ Checks, Business/Enterprise Support)"
                            ),
                            remediation=(
                                "Upgrade auf einen AWS Business- oder Enterprise-Support-Plan "
                                "für vollständigen Trusted Advisor Zugang mit automatisierten "
                                "Sicherheits- und Compliance-Checks."
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=f"DescribeTrustedAdvisorChecks returned {len(checks)} checks",
                        )
                    )

            except Exception as e:
                error_str = str(e)
                if "SubscriptionRequiredException" in error_str:
                    # Basic/Developer support — no Trusted Advisor API access at all
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Trusted Advisor Zugang (Basic/Developer Support)",
                            description=(
                                "AWS Trusted Advisor ist nicht per API verfügbar. Der Account "
                                "verwendet einen Basic- oder Developer-Support-Plan, der keinen "
                                "API-Zugriff auf Trusted Advisor bietet. "
                                "Hinweis: Fehlender Trusted-Advisor-Zugang bedeutet fehlende automatisierte "
                                "Best-Practice-Prüfungen des Cloud-Anbieters, keinen Lieferketten-Mangel "
                                "im engeren Sinne."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL,
                            severity=Severity.INFO,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:support:{session.account_id}:trusted-advisor",
                            resource_type="AWS::Support::TrustedAdvisor",
                            account_id=session.account_id,
                            current_state={"trusted_advisor_api_access": False},
                            expected_state="Business oder Enterprise Support Plan mit Trusted Advisor Zugang",
                            remediation=(
                                "Upgrade auf einen AWS Business- oder Enterprise-Support-Plan "
                                "für automatisierte Sicherheits- und Best-Practice-Checks."
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=(
                                "SubscriptionRequiredException — no Trusted Advisor API access "
                                "(Basic/Developer support plan)"
                            ),
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=f"Trusted Advisor Check fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Trusted Advisor Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckRamSharingPolicies(BaseCheck):
    """Check that AWS RAM (Resource Access Manager) sharing is controlled.

    RAM allows sharing resources across accounts. Without proper governance,
    sensitive resources could be shared with unauthorized external accounts.
    """

    check_id = "AWS-NR4-002"
    title = "RAM-Freigaben an externe Principals"
    description = (
        "Prüft ob aktive AWS-RAM-Ressourcenfreigaben externe Principals erlauben und damit "
        "Ressourcen mit Konten außerhalb der Organisation geteilt werden können."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["ram:GetResourceShares"]
    pruefgrenzen = (
        "Prüft nur aktive RAM-Ressourcenfreigaben. Nicht geprüft wird, an wen "
        "geteilt wird und ob die Freigaben geschäftlich begründet sind — das "
        "erfordert organisatorische Bewertung."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        region = session.regions[0]

        try:
            ram = session.client("ram", region=region)

            try:
                # Check for external shares (EXTERNAL resource owner)
                external_shares = ram.get_resource_shares(resourceOwner="SELF").get("resourceShares", [])

                # Filter for shares that allow external principals
                external_active = [
                    s
                    for s in external_shares
                    if s.get("allowExternalPrincipals", False) and s.get("status") == "ACTIVE"
                ]

                if not external_active:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine RAM-Shares mit externen Principals",
                            description=(
                                f"In Region {region} sind keine aktiven RAM Resource Shares vorhanden, "
                                f"die externe Principals erlauben — geteilte Ressourcen bleiben in der Organisation."
                            ),
                            region=region,
                            resource_id=f"arn:aws:ram:{region}:{session.account_id}:resource-share/*",
                            resource_type="AWS::RAM::ResourceShare",
                            account_id=session.account_id,
                            current_state={"external_shares_active": 0, "total_shares": len(external_shares)},
                            expected_state=(
                                "RAM Sharing nur innerhalb der Organisation (allowExternalPrincipals=false)"
                            ),
                            audit_evidence=(
                                f"GetResourceShares: {len(external_shares)} share(s), 0 active with external principals"
                            ),
                            iso27001_control="A.5.20 Addressing information security within supplier agreements",
                        )
                    )
                else:
                    for share in external_active:
                        share_name = share.get("name", "unknown")
                        share_arn = share.get("resourceShareArn", share_name)
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="RAM-Share erlaubt externe Principals",
                                description=(
                                    f"Die RAM Resource Share '{share_name}' in Region {region} erlaubt "
                                    f"externe Principals. Ressourcen können mit AWS-Konten außerhalb "
                                    f"der Organisation geteilt werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.20 Addressing information security within supplier agreements",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                region=region,
                                resource_id=share_arn,
                                resource_type="AWS::RAM::ResourceShare",
                                account_id=session.account_id,
                                current_state={
                                    "allow_external_principals": True,
                                    "share_name": share_name,
                                },
                                expected_state=(
                                    "RAM Sharing nur innerhalb der Organisation (allowExternalPrincipals=false)"
                                ),
                                remediation=(
                                    "Beschränken Sie RAM-Shares auf die Organisation: "
                                    "aws ram update-resource-share --resource-share-arn <arn> "
                                    "--no-allow-external-principals"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(f"GetResourceShares: {share_name} allowExternalPrincipals=true"),
                            )
                        )

            except Exception as e:
                error_str = str(e)
                if "UnknownEndpoint" in error_str or "Could not connect" in error_str:
                    errors.append(
                        CheckError(
                            message=f"RAM-API nicht erreichbar: {e}",
                            error_type="AWSClientError",
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=f"RAM Check fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"RAM Sharing Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOrganizationsExternalAccounts(BaseCheck):
    """Check that AWS Organizations properly isolates external accounts.

    Without Organizations, there's no centralized governance for multi-account
    environments, making it impossible to enforce supply chain security policies.
    """

    check_id = "AWS-NR4-003"
    title = "AWS Organizations mit allen Features aktiviert"
    description = (
        "Prüft ob der Account Teil einer AWS Organization mit FeatureSet=ALL ist — "
        "Voraussetzung für organisationsweite Sicherheitsrichtlinien (SCPs) gegenüber "
        "Drittanbieter-Konten."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["organizations:DescribeOrganization"]
    pruefgrenzen = (
        "Prüft nur, ob der Account Teil einer Organization ist. Die Isolation "
        "externer Konten selbst (OU-Struktur, Trennung) wird nicht inhaltlich bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            orgs = session.client("organizations", region="us-east-1")

            try:
                org = orgs.describe_organization().get("Organization", {})
                feature_set = org.get("FeatureSet", "")

                if feature_set == "ALL":
                    findings.append(
                        compliant_finding(
                            self,
                            title="Organizations mit allen Features aktiviert",
                            description=(
                                "AWS Organizations ist mit FeatureSet=ALL aktiviert — "
                                "SCPs und zentrale Sicherheitskontrollen sind durchsetzbar."
                            ),
                            region="global",
                            resource_id=org.get("Arn", f"arn:aws:organizations::{session.account_id}:organization"),
                            resource_type="AWS::Organizations::Organization",
                            account_id=session.account_id,
                            current_state={"feature_set": feature_set},
                            expected_state=("Organizations mit FeatureSet=ALL für vollständige Sicherheitskontrollen"),
                            audit_evidence="DescribeOrganization: FeatureSet=ALL",
                            iso27001_control="A.5.19 Information security in supplier relationships",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Organizations nicht mit allen Features aktiviert",
                            description=(
                                f"AWS Organizations hat FeatureSet='{feature_set}' statt 'ALL'. "
                                f"Ohne vollständige Features können SCPs und andere "
                                f"Sicherheitskontrollen nicht durchgesetzt werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Information security in supplier relationships",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=org.get("Arn", f"arn:aws:organizations::{session.account_id}:organization"),
                            resource_type="AWS::Organizations::Organization",
                            account_id=session.account_id,
                            current_state={"feature_set": feature_set},
                            expected_state="Organizations mit FeatureSet=ALL für vollständige Sicherheitskontrollen",
                            remediation=(
                                "Aktivieren Sie alle Features in AWS Organizations: "
                                "AWS Console → Organizations → Settings → Enable all features"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=f"DescribeOrganization: FeatureSet={feature_set}",
                        )
                    )

            except Exception as e:
                error_str = str(e)
                if "AWSOrganizationsNotInUseException" in error_str:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="AWS Organizations nicht aktiviert",
                            description=(
                                "AWS Organizations ist nicht aktiviert. Ohne Organizations "
                                "fehlt die zentrale Governance für Multi-Account-Umgebungen; "
                                "organisationsweite Sicherheitsrichtlinien gegenüber Drittanbieter-Konten "
                                "sind nicht durchsetzbar."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Information security in supplier relationships",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:organizations::{session.account_id}:*",
                            resource_type="AWS::Organizations::Organization",
                            account_id=session.account_id,
                            current_state={"organizations_enabled": False},
                            expected_state="AWS Organizations aktiviert (FeatureSet=ALL)",
                            remediation=(
                                "Erstellen Sie eine AWS Organization: "
                                "aws organizations create-organization --feature-set ALL"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence="DescribeOrganization: AWSOrganizationsNotInUseException",
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=f"Organizations Check fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Organizations External Accounts Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCrossAccountRoles(BaseCheck):
    """Check that IAM cross-account roles are audited and controlled.

    Cross-account roles allow external AWS accounts to assume roles in this account.
    These must be documented and reviewed as part of supply chain security.
    """

    check_id = "AWS-NR4-004"
    title = "IAM Cross-Account Roles auditiert"
    description = "Prüft ob IAM-Rollen mit Cross-Account Trust Relationships identifiziert und kontrolliert werden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:ListRoles"]
    pruefgrenzen = (
        "Prüft IAM-Rollen mit Cross-Account-Trust auf externe Account-IDs. "
        "Nicht bewertet wird, ob ein externer Trust legitim ist (z. B. beauftragter "
        "Dienstleister) — die Liste dient als Audit-Grundlage."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_roles")

            cross_account_roles = []
            wildcard_trust_roles = []
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName", "")
                    trust_policy = role.get("AssumeRolePolicyDocument", {})

                    # Skip AWS service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    for statement in trust_policy.get("Statement", []):
                        if statement.get("Effect") != "Allow":
                            continue
                        principal = statement.get("Principal", {})
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for p in aws_principals:
                            if p == "*" and not statement.get("Condition"):
                                # Unrestricted trust — any AWS account can assume the role
                                wildcard_trust_roles.append(
                                    {
                                        "role_name": role_name,
                                        "role_arn": role.get("Arn", ""),
                                    }
                                )
                            elif p == "*":
                                # "*" with a Condition (e.g. aws:PrincipalOrgID) — treated as
                                # cross-account trust; the condition itself is not evaluated
                                cross_account_roles.append(
                                    {
                                        "role_name": role_name,
                                        "role_arn": role.get("Arn", ""),
                                        "external_principal": "*",
                                    }
                                )
                            elif p.isdigit() and len(p) == 12 and p != session.account_id:
                                # Bare 12-digit account ID from a different account
                                cross_account_roles.append(
                                    {
                                        "role_name": role_name,
                                        "role_arn": role.get("Arn", ""),
                                        "external_principal": p,
                                    }
                                )
                            elif "::" in p and session.account_id not in p:
                                # ARN-form principal from a different account
                                cross_account_roles.append(
                                    {
                                        "role_name": role_name,
                                        "role_arn": role.get("Arn", ""),
                                        "external_principal": p,
                                    }
                                )

            if not cross_account_roles and not wildcard_trust_roles:
                findings.append(
                    compliant_finding(
                        self,
                        title="Keine Cross-Account Trust Relationships",
                        description=(
                            "Keine IAM-Rolle erlaubt externen AWS-Konten die Rollenübernahme — "
                            "es bestehen keine undokumentierten Lieferkettenabhängigkeiten über IAM."
                        ),
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:role/*",
                        resource_type="AWS::IAM::Role",
                        account_id=session.account_id,
                        current_state={"cross_account_roles": 0, "wildcard_trust_roles": 0},
                        expected_state=(
                            "Cross-Account Rollen dokumentiert, mit ExternalId und minimalem Berechtigungsumfang"
                        ),
                        audit_evidence="ListRoles: no roles with cross-account trust found",
                        iso27001_control="A.5.20, A.8.3 Information access restriction",
                    )
                )
            else:
                for wtr in wildcard_trust_roles:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAM-Rolle mit uneingeschränktem Trust (Principal *)",
                            description=(
                                f"Die IAM-Rolle '{wtr['role_name']}' erlaubt jedem AWS-Konto "
                                f"(Principal '*') die Rollenübernahme. Dies ist ein uneingeschränkter "
                                f"Trust ohne jede Zugriffsbeschränkung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.20, A.8.3 Information access restriction",
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=wtr["role_arn"],
                            resource_type="AWS::IAM::Role",
                            account_id=session.account_id,
                            current_state={
                                "role_name": wtr["role_name"],
                                "trust_principal": "*",
                            },
                            expected_state=(
                                "Cross-Account Rollen dokumentiert, mit ExternalId und minimalem Berechtigungsumfang"
                            ),
                            remediation=(
                                "Entfernen Sie den uneingeschränkten Trust umgehend: Setzen Sie den Principal "
                                "auf konkrete Konto-ARNs und ergänzen Sie eine ExternalId-Condition. "
                                "aws iam update-assume-role-policy --role-name <role> --policy-document <json>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(f"ListRoles: {wtr['role_name']} has unrestricted trust (Principal=*)"),
                        )
                    )
                for xar in cross_account_roles:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAM-Rolle mit Cross-Account Trust",
                            description=(
                                f"Die IAM-Rolle '{xar['role_name']}' erlaubt "
                                f"einem externen AWS-Konto die Rollenübernahme. Cross-Account "
                                f"Rollen müssen als Lieferkettenabhängigkeit dokumentiert und "
                                f"regelmäßig auditiert werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.20, A.8.3 Information access restriction",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=xar["role_arn"],
                            resource_type="AWS::IAM::Role",
                            account_id=session.account_id,
                            current_state={
                                "role_name": xar["role_name"],
                                "has_cross_account_trust": True,
                            },
                            expected_state=(
                                "Cross-Account Rollen dokumentiert, mit ExternalId und minimalem Berechtigungsumfang"
                            ),
                            remediation=(
                                "1. Dokumentieren Sie alle Cross-Account Rollen als Lieferkettenabhängigkeit. "
                                "2. Stellen Sie sicher, dass ExternalId als Condition gesetzt ist. "
                                "3. Wenden Sie Least-Privilege-Prinzip auf die Rollenberechtigungen an. "
                                "4. Überprüfen Sie regelmäßig die Trust Relationships."
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(f"ListRoles: {xar['role_name']} has cross-account trust"),
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Cross-Account Roles Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckScpForThirdPartyOus(BaseCheck):
    """Check that Service Control Policies exist for third-party OUs.

    Without SCPs, accounts in organizational units designated for third-party
    access have unrestricted permissions, violating supply chain security.
    """

    check_id = "AWS-NR4-005"
    title = "SCPs für Drittanbieter-OUs"
    description = (
        "Prüft ob Service Control Policies (SCPs) für die Einschränkung "
        "von Drittanbieter-Berechtigungen in AWS Organizations vorhanden sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["organizations:DescribeOrganization", "organizations:ListPolicies"]
    pruefgrenzen = (
        "Prüft nur die Existenz benutzerdefinierter SCPs in der Organization. "
        "Ob SCPs Drittanbieter-OUs tatsächlich einschränken (Inhalt, Zuordnung), "
        "wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            orgs = session.client("organizations", region="us-east-1")

            try:
                orgs.describe_organization()

                # Check for SCPs
                policies = orgs.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])

                # Filter out the default FullAWSAccess policy
                custom_scps = [p for p in policies if p.get("Name") != "FullAWSAccess"]

                if custom_scps:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Benutzerdefinierte SCPs vorhanden",
                            description=(
                                f"Es sind {len(custom_scps)} benutzerdefinierte Service Control "
                                f"Policies konfiguriert — Drittanbieter-Berechtigungen können "
                                f"organisationsweit eingeschränkt werden."
                            ),
                            region="global",
                            resource_id=(
                                f"arn:aws:organizations::{session.account_id}:policy/service_control_policy/*"
                            ),
                            resource_type="AWS::Organizations::Policy",
                            account_id=session.account_id,
                            current_state={"custom_scps": len(custom_scps)},
                            expected_state="Benutzerdefinierte SCPs für Drittanbieter-OUs konfiguriert",
                            audit_evidence=f"ListPolicies: {len(custom_scps)} custom SCP(s) found",
                            iso27001_control="A.5.19 Information security in supplier relationships",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine benutzerdefinierten SCPs für Drittanbieter",
                            description=(
                                "Es sind keine benutzerdefinierten Service Control Policies (SCPs) "
                                "konfiguriert. Ohne SCPs können Drittanbieter-Konten in der "
                                "Organisation uneingeschränkte Berechtigungen haben."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Information security in supplier relationships",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:organizations::{session.account_id}:policy/service_control_policy/*",
                            resource_type="AWS::Organizations::Policy",
                            account_id=session.account_id,
                            current_state={"custom_scps": 0},
                            expected_state="Benutzerdefinierte SCPs für Drittanbieter-OUs konfiguriert",
                            remediation=(
                                "Erstellen Sie SCPs zur Einschränkung von Drittanbieter-Berechtigungen: "
                                "aws organizations create-policy --name 'ThirdPartyRestrictions' "
                                "--type SERVICE_CONTROL_POLICY --content '<policy-json>'"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="ListPolicies: no custom SCPs found",
                        )
                    )

            except Exception as e:
                error_str = str(e)
                if "AWSOrganizationsNotInUseException" in error_str:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Organizations — SCPs nicht möglich",
                            description=(
                                "AWS Organizations ist nicht aktiviert. Ohne Organizations "
                                "können keine SCPs zur Einschränkung von Drittanbieter-"
                                "Berechtigungen konfiguriert werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Information security in supplier relationships",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:organizations::{session.account_id}:*",
                            resource_type="AWS::Organizations::Organization",
                            account_id=session.account_id,
                            current_state={"organizations_enabled": False, "scps_available": False},
                            expected_state="Organizations aktiviert mit SCPs für Drittanbieter",
                            remediation=(
                                "Aktivieren Sie AWS Organizations mit allen Features: "
                                "aws organizations create-organization --feature-set ALL"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence="AWSOrganizationsNotInUseException — no SCPs possible",
                        )
                    )
                elif "AccessDeniedException" in error_str:
                    errors.append(
                        CheckError(
                            message=(
                                "Kein Zugriff auf Organizations-Policies (AccessDeniedException) — "
                                "SCP-Status nicht prüfbar. Scan aus dem Management-Account oder als "
                                "delegierter Administrator ausführen."
                            ),
                            error_type="AccessDenied",
                        )
                    )
                else:
                    errors.append(
                        CheckError(
                            message=f"Organizations SCP Check fehlgeschlagen: {e}",
                            error_type="AWSClientError",
                        )
                    )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"SCP für Drittanbieter Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
