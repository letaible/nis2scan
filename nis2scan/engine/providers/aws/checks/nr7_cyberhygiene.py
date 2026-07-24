"""§30 Abs. 2 Nr. 7 — Grundlegende Verfahren der Cyberhygiene und Schulungen checks for AWS.

Checks IAM password policy and root account security hygiene.
(BSIG wording: basic training and security awareness)
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 7
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 7 BSIG — grundlegende Schulungen und Sensibilisierungsmaßnahmen "
    "im Bereich der Sicherheit in der Informationstechnik"
)
ISO_CONTROL = "A.5.17 Authentifizierungsinformationen"

MIN_PASSWORD_LENGTH = 14


class CheckIamPasswordPolicy(BaseCheck):
    """Check that IAM account password policy meets minimum security requirements."""

    check_id = "AWS-NR7-001"
    title = "IAM Password Policy"
    description = (
        f"Prüft ob die IAM-Passwort-Richtlinie Mindestanforderungen erfüllt "
        f"(≥{MIN_PASSWORD_LENGTH} Zeichen, Komplexität)."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:GetAccountPasswordPolicy"]
    pruefgrenzen = (
        "Prüft nur die IAM-Passwort-Richtlinie des Accounts. Föderierte Identitäten "
        "(SSO/IdP) unterliegen der Richtlinie des Identitätsanbieters und werden "
        "hier nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")

            try:
                policy = iam.get_account_password_policy().get("PasswordPolicy", {})

                issues: list[str] = []
                min_length = policy.get("MinimumPasswordLength", 0)
                if min_length < MIN_PASSWORD_LENGTH:
                    issues.append(f"MinimumPasswordLength={min_length} (Minimum: {MIN_PASSWORD_LENGTH})")
                if not policy.get("RequireUppercaseCharacters", False):
                    issues.append("RequireUppercaseCharacters=false")
                if not policy.get("RequireLowercaseCharacters", False):
                    issues.append("RequireLowercaseCharacters=false")
                if not policy.get("RequireNumbers", False):
                    issues.append("RequireNumbers=false")
                if not policy.get("RequireSymbols", False):
                    issues.append("RequireSymbols=false")

                if not issues:
                    findings.append(
                        compliant_finding(
                            self,
                            title="IAM-Passwort-Richtlinie erfüllt Anforderungen",
                            description=(
                                f"Die IAM-Passwort-Richtlinie erfüllt die Mindestanforderungen "
                                f"(Länge >= {MIN_PASSWORD_LENGTH}, Komplexität aktiviert)."
                            ),
                            region="global",
                            resource_id=f"arn:aws:iam::{session.account_id}:account-password-policy",
                            resource_type="AWS::IAM::AccountPasswordPolicy",
                            account_id=session.account_id,
                            current_state={
                                "minimum_password_length": min_length,
                                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                                "require_numbers": policy.get("RequireNumbers", False),
                                "require_symbols": policy.get("RequireSymbols", False),
                            },
                            expected_state=(
                                f"MinimumPasswordLength>={MIN_PASSWORD_LENGTH}, "
                                f"RequireUppercase=true, RequireLowercase=true, "
                                f"RequireNumbers=true, RequireSymbols=true"
                            ),
                            audit_evidence=(f"GetAccountPasswordPolicy: all requirements met (length={min_length})"),
                            iso27001_control=ISO_CONTROL,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAM-Passwort-Richtlinie unzureichend",
                            description=(
                                f"Die IAM-Passwort-Richtlinie erfüllt nicht die "
                                f"Mindestanforderungen: {'; '.join(issues)}"
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=ISO_CONTROL,
                            severity=Severity.HIGH,
                            provider=CloudProvider.AWS,
                            region="global",
                            resource_id=f"arn:aws:iam::{session.account_id}:account-password-policy",
                            resource_type="AWS::IAM::AccountPasswordPolicy",
                            account_id=session.account_id,
                            current_state={
                                "minimum_password_length": min_length,
                                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                                "require_numbers": policy.get("RequireNumbers", False),
                                "require_symbols": policy.get("RequireSymbols", False),
                            },
                            expected_state=(
                                f"MinimumPasswordLength>={MIN_PASSWORD_LENGTH}, "
                                f"RequireUppercase=true, RequireLowercase=true, "
                                f"RequireNumbers=true, RequireSymbols=true"
                            ),
                            remediation=(
                                "Aktualisieren Sie die IAM-Passwort-Richtlinie: "
                                "aws iam update-account-password-policy "
                                f"--minimum-password-length {MIN_PASSWORD_LENGTH} "
                                "--require-uppercase-characters "
                                "--require-lowercase-characters "
                                "--require-numbers --require-symbols"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"GetAccountPasswordPolicy: {'; '.join(issues)}",
                        )
                    )

            except iam.exceptions.NoSuchEntityException:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine IAM-Passwort-Richtlinie konfiguriert",
                        description=(
                            "Es ist keine benutzerdefinierte IAM-Passwort-Richtlinie konfiguriert. "
                            "Es gelten die AWS-Standardeinstellungen mit minimaler Komplexität."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control=ISO_CONTROL,
                        severity=Severity.HIGH,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:account-password-policy",
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        account_id=session.account_id,
                        current_state={"password_policy": "not_configured"},
                        expected_state=(
                            f"MinimumPasswordLength>={MIN_PASSWORD_LENGTH}, "
                            f"RequireUppercase=true, RequireLowercase=true, "
                            f"RequireNumbers=true, RequireSymbols=true"
                        ),
                        remediation=(
                            "Erstellen Sie eine IAM-Passwort-Richtlinie: "
                            "aws iam update-account-password-policy "
                            f"--minimum-password-length {MIN_PASSWORD_LENGTH} "
                            "--require-uppercase-characters --require-lowercase-characters "
                            "--require-numbers --require-symbols"
                        ),
                        remediation_effort="LOW",
                        audit_evidence="GetAccountPasswordPolicy: NoSuchEntity",
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"IAM Password Policy Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckRootAccessKeys(BaseCheck):
    """Check that the root account has no access keys."""

    check_id = "AWS-NR7-002"
    title = "Root Account Access Keys"
    description = "Prüft ob der Root-Account keine Access Keys besitzt."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AWS
    required_permissions = ["iam:GetAccountSummary"]
    pruefgrenzen = (
        "Prüft nur, ob Root-Access-Keys existieren. Root-MFA und Root-Nutzung werden in den NR10-Checks geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            iam = session.client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})

            access_keys = summary.get("AccountAccessKeysPresent", 0)
            if access_keys == 0:
                findings.append(
                    compliant_finding(
                        self,
                        title="Root-Account ohne Access Keys",
                        description="Der Root-Account besitzt keine Access Keys.",
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:root",
                        resource_type="AWS::IAM::Root",
                        account_id=session.account_id,
                        current_state={"root_access_keys_present": 0},
                        expected_state="Keine Access Keys für den Root-Account (AccountAccessKeysPresent=0)",
                        audit_evidence="GetAccountSummary: AccountAccessKeysPresent=0",
                        iso27001_control="A.5.17 Authentifizierungsinformationen, A.8.2 Privilegierte Zugangsrechte",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Root-Account hat Access Keys",
                        description=(
                            f"Der Root-Account besitzt {access_keys} Access Key(s). "
                            f"Root Access Keys stellen ein erhebliches Sicherheitsrisiko dar, "
                            f"da sie uneingeschränkte Rechte haben und nicht durch IAM-Policies "
                            f"eingeschränkt werden können."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.17 Authentifizierungsinformationen, A.8.2 Privilegierte Zugangsrechte",
                        severity=Severity.CRITICAL,
                        provider=CloudProvider.AWS,
                        region="global",
                        resource_id=f"arn:aws:iam::{session.account_id}:root",
                        resource_type="AWS::IAM::Root",
                        account_id=session.account_id,
                        current_state={"root_access_keys_present": access_keys},
                        expected_state="Keine Access Keys für den Root-Account (AccountAccessKeysPresent=0)",
                        remediation=(
                            "Löschen Sie SOFORT alle Root Access Keys. "
                            "AWS Console: Account → Security credentials → Access keys → Delete. "
                            "Verwenden Sie stattdessen IAM-Benutzer oder IAM-Rollen mit "
                            "minimalen Berechtigungen."
                        ),
                        remediation_effort="LOW",
                        audit_evidence=f"GetAccountSummary: AccountAccessKeysPresent={access_keys}",
                    )
                )

        except Exception as e:
            errors.append(
                CheckError(
                    message=f"Root Access Keys Check fehlgeschlagen: {e}",
                    error_type=type(e).__name__,
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
