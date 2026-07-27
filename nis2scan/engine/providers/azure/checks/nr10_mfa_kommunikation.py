"""§30 Abs. 2 Nr. 10 — MFA & gesicherte Kommunikation checks for Azure.

Checks MFA enforcement, phishing-resistant MFA, VPN/Bastion,
O365 TLS enforcement, and break-glass accounts.
"""

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

# Global Admin role template ID
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


class CheckMfaAllUsers(BaseCheck):
    """Check that MFA is enforced for all users via Conditional Access."""

    check_id = "AZ-NR10-001"
    title = "Entra ID MFA für alle Benutzer"
    description = "Prüft ob Multi-Faktor-Authentifizierung für alle Benutzer durchgesetzt wird."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft, ob eine aktive Conditional-Access-Policy MFA für alle Benutzer erzwingt "
        "(Graph API). Die individuelle MFA-Registrierung einzelner Benutzer wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            policies = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            )

            mfa_all_users = False
            excluded_count = 0
            for policy in policies:
                state = policy.get("state")
                if state and str(state).lower() != "enabled":
                    continue

                # Check if policy requires MFA
                grant = policy.get("grantControls")
                if not grant or not grant.get("builtInControls"):
                    continue
                requires_mfa = "mfa" in [str(c).lower() for c in grant.get("builtInControls")]
                if not requires_mfa:
                    continue

                # Check if policy targets all users
                conditions = policy.get("conditions")
                if not conditions or not conditions.get("users"):
                    continue
                users_cond = conditions.get("users")
                include_users = users_cond.get("includeUsers") or []
                if "All" not in include_users:
                    continue

                exclude_users = users_cond.get("excludeUsers") or []
                mfa_all_users = True
                excluded_count = len(exclude_users)
                break

            if mfa_all_users and excluded_count == 0:
                findings.append(
                    compliant_finding(
                        self,
                        title="MFA für alle Benutzer durchgesetzt",
                        description=("Eine aktive Conditional Access Policy erzwingt MFA für alle Benutzer."),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"mfa_all_users_policy": True, "excluded_users": 0},
                        expected_state="Conditional Access Policy mit MFA für alle Benutzer",
                        audit_evidence=(f"Graph API: {len(policies)} CA policies, MFA-for-all-users policy active"),
                        iso27001_control="A.8.5 Sichere Authentifizierung",
                    )
                )
            elif mfa_all_users and excluded_count > 0:
                findings.append(
                    compliant_finding(
                        self,
                        title="MFA für alle Benutzer durchgesetzt",
                        description=(
                            f"Eine aktive Conditional Access Policy hat MFA für alle Benutzer erzwungen, mit "
                            f"{excluded_count} ausgenommenen Objekten; Ausnahmen sind organisatorisch zu "
                            f"begründen (z. B. Break-Glass-Konten)."
                        ),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"mfa_all_users_policy": True, "excluded_users": excluded_count},
                        expected_state="Conditional Access Policy mit MFA für alle Benutzer",
                        audit_evidence=(
                            f"Graph API: {len(policies)} CA policies, MFA-for-all-users policy active "
                            f"with {excluded_count} excluded users"
                        ),
                        iso27001_control="A.8.5 Sichere Authentifizierung",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="MFA nicht für alle Benutzer durchgesetzt",
                        description=(
                            "Es gibt keine aktive Conditional Access Policy, die MFA für alle "
                            "Benutzer erzwingt. MFA ist eine der wirksamsten Maßnahmen gegen "
                            "Kontoübernahmen."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.5 Sichere Authentifizierung",
                        severity=Severity.CRITICAL,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"mfa_all_users_policy": False},
                        expected_state="Conditional Access Policy mit MFA für alle Benutzer",
                        remediation=(
                            "Erstellen Sie eine CA-Policy mit MFA-Anforderung für alle Benutzer: "
                            "Entra Admin Center → Schutz → Bedingter Zugriff → "
                            "Neue Richtlinie → Alle Benutzer → Gewähren: MFA erforderlich"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(f"Graph API: {len(policies)} CA policies, none requiring MFA for all users"),
                    )
                )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckPhishingResistantMfa(BaseCheck):
    """Check that phishing-resistant MFA (FIDO2/WHfB) is enabled."""

    check_id = "AZ-NR10-002"
    title = "Phishing-resistente MFA (FIDO2/Windows Hello)"
    description = "Prüft ob FIDO2 oder Windows Hello for Business als Authentifizierungsmethode aktiviert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft nur, ob phishing-resistente Methoden (FIDO2/Windows Hello) registriert "
        "sind. Ob sie bevorzugt erzwungen werden, wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            methods_policy = await graph.graph_get(
                session.credential, "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
            )

            fido2_enabled = False
            configs = methods_policy.get("authenticationMethodConfigurations") if methods_policy else None
            if configs:
                for config in configs:
                    config_id = str(config.get("id") or "").lower()
                    config_state = str(config.get("state") or "").lower()
                    if config_id == "fido2" and config_state == "enabled":
                        fido2_enabled = True
                        break
                    if config_id == "windowshelloforbusiness" and config_state == "enabled":
                        fido2_enabled = True
                        break

            if fido2_enabled:
                findings.append(
                    compliant_finding(
                        self,
                        title="Phishing-resistente MFA aktiviert",
                        description=(
                            "FIDO2 oder Windows Hello for Business ist als Authentifizierungsmethode aktiviert."
                        ),
                        region="global",
                        resource_id="/policies/authenticationMethodsPolicy",
                        resource_type="Microsoft.Graph/authenticationMethodsPolicy",
                        account_id=session.subscription_id,
                        current_state={"phishing_resistant_mfa": True},
                        expected_state="FIDO2 oder Windows Hello for Business aktiviert",
                        audit_evidence="Graph API: FIDO2 or WHfB enabled",
                        iso27001_control="A.8.5 Sichere Authentifizierung",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine Phishing-resistente MFA aktiviert",
                        description=(
                            "Weder FIDO2 noch Windows Hello for Business ist als "
                            "Authentifizierungsmethode aktiviert. Phishing-resistente MFA "
                            "bietet höheren Schutz als SMS/App-basierte MFA."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.5 Sichere Authentifizierung",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/policies/authenticationMethodsPolicy",
                        resource_type="Microsoft.Graph/authenticationMethodsPolicy",
                        account_id=session.subscription_id,
                        current_state={"fido2_enabled": False, "whfb_enabled": False},
                        expected_state="FIDO2 oder Windows Hello for Business aktiviert",
                        remediation=(
                            "Aktivieren Sie FIDO2: Entra Admin Center → Schutz → "
                            "Authentifizierungsmethoden → FIDO2-Sicherheitsschlüssel → Aktivieren"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence="Graph API: FIDO2 and WHfB both disabled/not found",
                    )
                )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpnBastion(BaseCheck):
    """Check that VPN Gateway or Bastion Host exists for admin access."""

    check_id = "AZ-NR10-003"
    title = "VPN Gateway / Bastion Host für Admin-Zugriff"
    description = "Prüft ob ein VPN Gateway oder Bastion Host für gesicherten Admin-Zugriff vorhanden ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Network/virtualNetworkGateways/read",
        "Microsoft.Network/bastionHosts/read",
    ]
    pruefgrenzen = (
        "Prüft nur Azure-eigene Zugangswege (VPN Gateway, Bastion). Drittanbieter-"
        "VPNs und Zero-Trust-Lösungen werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.network import NetworkManagementClient
                from azure.mgmt.resource.resources import ResourceManagementClient

                network_client = session.get_client(NetworkManagementClient, sub_id)
                resource_client = session.get_client(ResourceManagementClient, sub_id)

                # VPN Gateways have no subscription-wide list_all() — they can only be
                # listed per resource group. List resource groups first, then query each
                # one; a failing resource group is reported as a CheckError and never
                # silently skips the rest (Code-Health-Guideline).
                resource_groups = list(resource_client.resource_groups.list())
                vpn_gateways: list[Any] = []
                failed_resource_groups: list[str] = []
                for rg in resource_groups:
                    try:
                        vpn_gateways.extend(network_client.virtual_network_gateways.list(rg.name))
                    except Exception:
                        failed_resource_groups.append(rg.name)

                if failed_resource_groups:
                    failed_summary = ", ".join(failed_resource_groups[:5])
                    errors.append(
                        CheckError(
                            check_id=self.check_id,
                            error_type="VpnGatewayQueryFailed",
                            message=(
                                f"{len(failed_resource_groups)} von {len(resource_groups)} "
                                f"VPN-Gateway-Abfragen in Subscription {sub_id} fehlgeschlagen: "
                                f"{failed_summary}{'...' if len(failed_resource_groups) > 5 else ''}"
                            ),
                            region="global",
                        )
                    )

                # Check for Bastion hosts
                bastion_hosts = [
                    r for r in resource_client.resources.list(filter="resourceType eq 'Microsoft.Network/bastionHosts'")
                ]

                if vpn_gateways or bastion_hosts:
                    findings.append(
                        compliant_finding(
                            self,
                            title="VPN Gateway / Bastion Host vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(vpn_gateways)} VPN Gateway(s) und "
                                f"{len(bastion_hosts)} Bastion Host(s) für gesicherten Admin-Zugriff."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/virtualNetworkGateways",
                            account_id=sub_id,
                            current_state={
                                "vpn_gateways": len(vpn_gateways),
                                "bastion_hosts": len(bastion_hosts),
                            },
                            expected_state="VPN Gateway oder Bastion Host für Admin-Zugriff",
                            audit_evidence=(
                                f"virtual_network_gateways/bastionHosts: {len(vpn_gateways)} gateway(s), "
                                f"{len(bastion_hosts)} bastion host(s)"
                            ),
                            iso27001_control="A.8.20 Netzwerksicherheit",
                        )
                    )
                elif failed_resource_groups:
                    # Fail-safe (ADR-0016, legal review 27.07.2026): with partly
                    # failed resource-group queries and no gateway found in the
                    # REST, the subscription-wide "weder ... noch ..." statement
                    # would claim completeness we do not have. No finding — the
                    # CheckError above already reports the partial failure
                    # (same pattern as AZ-NR6-004, nr6_wirksamkeit.py).
                    pass
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein VPN Gateway / Bastion Host",
                            description=(
                                f"Subscription {sub_id} hat weder ein VPN Gateway "
                                "noch einen Bastion Host. Ohne gesicherten Admin-Zugang sind "
                                "Management-Verbindungen über das öffentliche Internet exponiert."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.20 Netzwerksicherheit",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/virtualNetworkGateways",
                            account_id=sub_id,
                            current_state={"vpn_gateways": 0, "bastion_hosts": 0},
                            expected_state="VPN Gateway oder Bastion Host für Admin-Zugriff",
                            remediation=(
                                "Erstellen Sie einen Bastion Host: "
                                "az network bastion create --name <bastion> "
                                "--resource-group <rg> --vnet-name <vnet> --location <loc>"
                            ),
                            remediation_effort="HIGH",
                            # This branch is only reachable with FULL coverage
                            # (failed_resource_groups is empty, see elif above),
                            # so the total count IS the successfully queried count.
                            audit_evidence=(
                                f"virtual_network_gateways.list(rg) across all {len(resource_groups)} "
                                "resource group(s), 0 failures: 0 gateways, "
                                "resources.list(bastionHosts): 0 hosts"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                        region="global",
                    )
                )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckO365TlsEnforcement(BaseCheck):
    """Check that Conditional Access enforces security requirements for O365 services."""

    check_id = "AZ-NR10-004"
    title = "Conditional Access für O365-Dienste"
    description = (
        "Prüft ob eine Conditional-Access-Policy Sicherheitsanforderungen (Gerätekonformität, "
        "genehmigte App oder MFA) für den Zugriff auf Office-365-Dienste erzwingt."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft nur tenant-seitige Conditional-Access-Anforderungen für O365-Dienste. Transport-TLS "
        "erfolgt plattformseitig durch Microsoft und ist tenant-seitig nicht prüfbar; die Sicherung "
        "von Sprach-, Video- und Textkommunikation ist nicht Gegenstand dieses Scans."
    )

    # Office 365 Exchange Online app ID
    O365_APP_IDS = {
        "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
        "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",  # Teams
        "Office365",  # All O365 apps
    }

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            policies = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            )

            o365_ca_found = False
            for policy in policies:
                state = policy.get("state")
                if state and str(state).lower() != "enabled":
                    continue

                conditions = policy.get("conditions")
                if not conditions or not conditions.get("applications"):
                    continue

                apps_cond = conditions.get("applications")
                include_apps = apps_cond.get("includeApplications") or []
                # Check if policy targets O365 apps
                targets_o365 = "All" in include_apps or any(app in self.O365_APP_IDS for app in include_apps)

                if targets_o365:
                    # Check if policy has device compliance or approved app requirement
                    grant = policy.get("grantControls")
                    if grant and grant.get("builtInControls"):
                        controls = [str(c).lower() for c in grant.get("builtInControls")]
                        if "compliantdevice" in controls or "approvedapplication" in controls or "mfa" in controls:
                            o365_ca_found = True
                            break

            if o365_ca_found:
                findings.append(
                    compliant_finding(
                        self,
                        title="CA-Policy für O365-Kommunikation aktiv",
                        description=(
                            "Eine aktive Conditional Access Policy erzwingt Sicherheitsanforderungen "
                            "für Office 365 Kommunikationsdienste."
                        ),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"o365_ca_policy": True},
                        expected_state="CA-Policy mit Sicherheitsanforderungen für O365-Dienste",
                        audit_evidence=f"Graph API: {len(policies)} CA policies, O365-targeting policy active",
                        iso27001_control="A.8.20 Netzwerksicherheit",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine CA-Policy für O365-Kommunikation",
                        description=(
                            "Es gibt keine Conditional Access Policy, die Sicherheitsanforderungen "
                            "(Geräte-Compliance, genehmigte Apps, MFA) für Office 365 "
                            "Kommunikationsdienste erzwingt."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.20 Netzwerksicherheit",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"o365_ca_policy": False},
                        expected_state="CA-Policy mit Sicherheitsanforderungen für O365-Dienste",
                        remediation=(
                            "Erstellen Sie eine CA-Policy für O365: "
                            "Entra Admin Center → Bedingter Zugriff → Neue Richtlinie → "
                            "Cloud-Apps: Office 365 → Gewähren: Gerätekonformität erforderlich"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=f"Graph API: {len(policies)} CA policies, none targeting O365",
                    )
                )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckBreakGlassAccounts(BaseCheck):
    """Check that emergency access (break-glass) accounts exist."""

    check_id = "AZ-NR10-005"
    title = "Emergency Access Accounts (Break Glass)"
    description = "Prüft ob Notfallzugangs-Konten (Break Glass) für den Notfall konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["User.Read.All", "RoleManagement.Read.Directory"]
    pruefgrenzen = (
        "Erkennt Konten mit permanenter Global-Admin-Rolle, die von mindestens einer "
        "Conditional-Access-Policy ausgeschlossen sind; Namensmuster werden nicht ausgewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            # Check for permanent Global Admin role assignments
            assignments = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
            )

            global_admin_assignments = [a for a in assignments if a.get("roleDefinitionId") == GLOBAL_ADMIN_ROLE_ID]

            # Check CA policies for excluded users (break-glass accounts are typically excluded)
            policies = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            )

            # Collect all excluded user IDs across CA policies
            excluded_user_ids: set[str] = set()
            for policy in policies:
                conditions = policy.get("conditions")
                users_cond = conditions.get("users") if conditions else None
                exclude_users = users_cond.get("excludeUsers") if users_cond else None
                if exclude_users:
                    for user_id in exclude_users:
                        excluded_user_ids.add(user_id)

            # A break-glass account is: (1) a permanent Global Admin, (2) excluded from CA
            # policies. Count all matches (Option A) instead of stopping at the first hit —
            # Microsoft recommends at least two break-glass accounts.
            break_glass_accounts = [a for a in global_admin_assignments if a.get("principalId") in excluded_user_ids]
            break_glass_count = len(break_glass_accounts)
            expected_state = "Mindestens zwei Break-Glass-Konten (permanente Global-Admin-Rolle mit CA-Ausschluss)"

            if break_glass_count >= 2:
                findings.append(
                    compliant_finding(
                        self,
                        title="Break-Glass-Konten erkannt",
                        description=(
                            f"{break_glass_count} Break-Glass-Konten erkannt (permanente Global-Admin-Rolle, "
                            f"von Conditional-Access-Policies ausgeschlossen)."
                        ),
                        region="global",
                        resource_id="/roleManagement/directory/roleAssignments",
                        resource_type="Microsoft.Graph/roleAssignments",
                        account_id=session.subscription_id,
                        current_state={
                            "global_admin_assignments": len(global_admin_assignments),
                            "break_glass_accounts": break_glass_count,
                        },
                        expected_state=expected_state,
                        audit_evidence=(
                            f"Graph API: {len(global_admin_assignments)} Global Admin assignments, "
                            f"{break_glass_count} Global-Admin-Konten mit CA-Ausschluss gefunden"
                        ),
                        iso27001_control="A.5.30, A.8.5 Notfallzugang",
                    )
                )
            elif break_glass_count == 1:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Nur ein Break-Glass-Konto erkannt",
                        description=(
                            "Es wurde nur ein Notfallzugangs-Konto (permanenter Global Admin, von "
                            "Conditional-Access-Policies ausgeschlossen) erkannt. Microsoft empfiehlt "
                            "mindestens zwei Break-Glass-Konten, um den Ausfall eines einzelnen Kontos "
                            "abzufedern."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.30, A.8.5 Notfallzugang",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/roleManagement/directory/roleAssignments",
                        resource_type="Microsoft.Graph/roleAssignments",
                        account_id=session.subscription_id,
                        current_state={
                            "global_admin_assignments": len(global_admin_assignments),
                            "break_glass_accounts": 1,
                        },
                        expected_state=expected_state,
                        remediation=(
                            "Erstellen Sie ein zweites Break-Glass-Konto: "
                            "1. Erstellen Sie ein weiteres Cloud-only-Konto mit starkem Passwort "
                            "2. Weisen Sie permanente Global-Admin-Rolle zu "
                            "3. Schließen Sie es von allen CA-Policies aus "
                            "4. Überwachen Sie Anmeldungen via Alert"
                        ),
                        remediation_effort="LOW",
                        audit_evidence=(
                            f"Graph API: {len(global_admin_assignments)} Global Admin assignments, "
                            f"{len(excluded_user_ids)} CA-excluded users, 1 Global-Admin-Konto mit "
                            f"CA-Ausschluss gefunden"
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine Break-Glass-Konten erkannt",
                        description=(
                            "Es wurden keine Notfallzugangs-Konten (Break Glass) erkannt. "
                            "Break-Glass-Konten sind permanente Global Admins, die von allen "
                            "Conditional Access Policies ausgeschlossen sind — für den Notfall."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.30, A.8.5 Notfallzugang",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/roleManagement/directory/roleAssignments",
                        resource_type="Microsoft.Graph/roleAssignments",
                        account_id=session.subscription_id,
                        current_state={
                            "global_admin_assignments": len(global_admin_assignments),
                            "ca_excluded_users": len(excluded_user_ids),
                            "break_glass_accounts": 0,
                        },
                        expected_state=expected_state,
                        remediation=(
                            "Erstellen Sie Break-Glass-Konten: "
                            "1. Erstellen Sie 2 Cloud-only-Konten mit starken Passwörtern "
                            "2. Weisen Sie permanente Global-Admin-Rolle zu "
                            "3. Schließen Sie sie von allen CA-Policies aus "
                            "4. Überwachen Sie Anmeldungen via Alert"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(
                            f"Graph API: {len(global_admin_assignments)} Global Admin assignments, "
                            f"{len(excluded_user_ids)} CA-excluded users, kein Global-Admin-Konto mit "
                            f"CA-Ausschluss gefunden"
                        ),
                    )
                )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
