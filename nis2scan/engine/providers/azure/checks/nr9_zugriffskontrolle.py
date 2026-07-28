"""§30 Abs. 2 Nr. 9 — Zugriffskontrolle & Asset-Management checks for Azure.

Checks Conditional Access, PIM, NSG rules, Storage public access,
Classic Admins, Guest Access Restrictions, and Stale Service Principals.
"""

from datetime import UTC, datetime, timedelta
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

# Open access patterns for NSG rules
OPEN_SOURCE_PREFIXES = {"*", "0.0.0.0/0", "Internet", "0.0.0.0", "<nw>/0"}
MAX_INACTIVE_DAYS = 90


class CheckConditionalAccess(BaseCheck):
    """Check that Entra ID Conditional Access policies exist."""

    check_id = "AZ-NR9-001"
    title = "Entra ID Conditional Access Policies"
    description = "Prüft ob Conditional Access Policies für Zugriffskontrolle konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft nur die Existenz aktivierter Conditional-Access-Policies (Graph API). "
        "Ob die Policies alle Benutzer und Risiken angemessen abdecken, wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            policies = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            )

            # Only state == "enabled" actually enforces access. Report-only policies
            # (enabledForReportingButNotEnforced) log but never block access, so they
            # do not count as positive evidence.
            enforced_policies = [p for p in policies if p.get("state") and str(p.get("state")).lower() == "enabled"]
            report_only_policies = [
                p
                for p in policies
                if p.get("state") and str(p.get("state")).lower() == "enabledforreportingbutnotenforced"
            ]

            if enforced_policies:
                findings.append(
                    compliant_finding(
                        self,
                        title="Conditional Access Policies aktiv",
                        description=(
                            f"Es sind {len(enforced_policies)} aktive Conditional Access Policies "
                            f"für risikobasierte Zugriffskontrolle konfiguriert."
                        ),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={
                            "total_policies": len(policies),
                            "enabled_policies": len(enforced_policies),
                        },
                        expected_state="Mindestens eine aktive Conditional Access Policy",
                        audit_evidence=(f"Graph API: {len(policies)} total policies, {len(enforced_policies)} enabled"),
                        iso27001_control="A.5.15 Zugriffskontrolle",
                    )
                )
            else:
                description = (
                    "Es sind keine aktiven Conditional Access Policies konfiguriert. "
                    "Ohne CA-Policies fehlt eine risikobasierte Zugriffskontrolle."
                )
                if report_only_policies:
                    description += (
                        " Es existieren ausschließlich Report-only-Richtlinien "
                        "(enabledForReportingButNotEnforced), die keine Zugriffe durchsetzen."
                    )
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine aktiven Conditional Access Policies",
                        description=description,
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.15 Zugriffskontrolle",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={
                            "total_policies": len(policies),
                            "enabled_policies": 0,
                            "report_only_policies": len(report_only_policies),
                        },
                        expected_state="Mindestens eine aktive Conditional Access Policy",
                        remediation=(
                            "Erstellen Sie Conditional Access Policies im Entra Admin Center: "
                            "Entra Admin Center → Schutz → Bedingter Zugriff → Neue Richtlinie"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(
                            f"Graph API: {len(policies)} total policies, 0 enabled, "
                            f"{len(report_only_policies)} report-only"
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


class CheckPim(BaseCheck):
    """Check that Privileged Identity Management (PIM) is configured."""

    check_id = "AZ-NR9-002"
    title = "Entra ID Privileged Identity Management (PIM)"
    description = "Prüft ob PIM für zeitlich begrenzte privilegierte Zugänge konfiguriert ist."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["RoleManagement.Read.Directory"]
    pruefgrenzen = (
        "Prüft nur, ob PIM-berechtigte Rollenzuweisungen existieren (erfordert "
        "Entra ID P2). Ohne P2-Lizenz ist der Check nicht auswertbar."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            eligible = await graph.graph_get_all(
                session.credential,
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances",
            )

            if eligible:
                findings.append(
                    compliant_finding(
                        self,
                        title="PIM konfiguriert",
                        description=(
                            f"Es sind {len(eligible)} PIM-berechtigte Rollenzuweisungen vorhanden — "
                            f"privilegierte Zugänge sind zeitlich begrenzt."
                        ),
                        region="global",
                        resource_id="/roleManagement/directory",
                        resource_type="Microsoft.Graph/roleEligibilityScheduleInstances",
                        account_id=session.subscription_id,
                        current_state={"eligible_role_assignments": len(eligible)},
                        expected_state="PIM-berechtigte Rollenzuweisungen statt permanenter Admin-Rollen",
                        audit_evidence=f"Graph API: {len(eligible)} eligible role schedule instances",
                        iso27001_control="A.8.2, A.8.18 Privilegierte Zugangsrechte",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Kein PIM konfiguriert",
                        description=(
                            "Es sind keine PIM-berechtigten Rollenzuweisungen vorhanden. "
                            "Ohne PIM haben privilegierte Benutzer permanente Admin-Rechte, "
                            "was das Risiko von Missbrauch erhöht."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.2, A.8.18 Privilegierte Zugangsrechte",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/roleManagement/directory",
                        resource_type="Microsoft.Graph/roleEligibilityScheduleInstances",
                        account_id=session.subscription_id,
                        current_state={"eligible_role_assignments": 0},
                        expected_state="PIM-berechtigte Rollenzuweisungen statt permanenter Admin-Rollen",
                        remediation=(
                            "Aktivieren Sie PIM im Entra Admin Center: "
                            "Entra Admin Center → Identitätsgovernance → Privileged Identity Management"
                        ),
                        remediation_effort="HIGH",
                        audit_evidence="Graph API: 0 eligible role schedule instances",
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


class CheckNsgOpenAccess(BaseCheck):
    """Check that NSG rules don't allow unrestricted inbound access."""

    check_id = "AZ-NR9-003"
    title = "NSG Rules — keine offenen Ports zu Internet"
    description = "Prüft ob Network Security Groups keine offenen Inbound-Regeln aus dem Internet haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Network/networkSecurityGroups/read"]
    pruefgrenzen = (
        "Prüft NSG-Regeln auf offene administrative Ports von Internet. Effektive "
        "Erreichbarkeit (Firewalls, Routing) wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.network import NetworkManagementClient

                network_client = session.get_client(NetworkManagementClient, sub_id)
                nsgs = list(network_client.network_security_groups.list_all())

                for nsg in nsgs:
                    open_rules = []
                    # Robustness fix (28.07.2026): network_security_groups.list_all() has
                    # been observed to come back with security_rules empty/unpopulated for
                    # NSGs that do have custom inbound rules (confirmed via Terraform-fixture
                    # instrumentation against real Azure test infrastructure -- a NSG with an
                    # open inbound SSH rule from "*" was silently reported as "compliant").
                    # A per-NSG get() call always returns the fully materialized rule set, so
                    # re-fetch defensively instead of trusting list_all()'s embedded rules at
                    # face value -- an empty result here is a false "compliant" verdict on a
                    # security-critical check (an unnoticed open port).
                    rules = nsg.security_rules or []
                    if not rules and nsg.id:
                        # Fail-safe (ADR-0016, legal review 28.07.2026, Auflage): if the
                        # re-fetch fails we must NOT silently fall back to the empty rule
                        # list — that would reproduce the exact false "compliant" verdict
                        # this fix exists to prevent, just via a new trigger. The NSG's
                        # rule state is then UNKNOWN, so emit an InconclusiveState
                        # CheckError and skip it (pattern: CheckStaleServicePrincipals /
                        # AZ-NR6-004 / AZ-NR10-003) — no finding of either kind.
                        try:
                            rg_name = nsg.id.split("/resourceGroups/")[1].split("/")[0]
                            full_nsg = network_client.network_security_groups.get(rg_name, nsg.name)
                            rules = full_nsg.security_rules or []
                        except Exception as refetch_exc:
                            logger.warning(
                                "az_nr9_003_nsg_refetch_failed",
                                nsg_name=nsg.name,
                                error=str(refetch_exc),
                            )
                            errors.append(
                                CheckError(
                                    check_id=self.check_id,
                                    error_type="InconclusiveState",
                                    message=(
                                        f"NSG {nsg.name}: Regelsatz konnte nicht ermittelt werden "
                                        f"(list_all lieferte keine Regeln, Nachladen fehlgeschlagen: "
                                        f"{refetch_exc}). Offene Ports sind nicht ausschließbar."
                                    ),
                                    region=nsg.location or "global",
                                )
                            )
                            continue
                    for rule in rules:
                        source_prefixes = getattr(rule, "source_address_prefixes", None) or []
                        is_open_source = rule.source_address_prefix in OPEN_SOURCE_PREFIXES or any(
                            p in OPEN_SOURCE_PREFIXES for p in source_prefixes
                        )
                        if (
                            rule.direction
                            and str(rule.direction).lower() == "inbound"
                            and rule.access
                            and str(rule.access).lower() == "allow"
                            and is_open_source
                        ):
                            open_rules.append(
                                {
                                    "name": rule.name,
                                    "port": str(rule.destination_port_range),
                                    "protocol": str(rule.protocol),
                                }
                            )

                    if not open_rules:
                        findings.append(
                            compliant_finding(
                                self,
                                title="NSG ohne offene Inbound-Regeln",
                                description=(
                                    f"NSG {nsg.name} hat keine Inbound-Regeln mit offener Quelle "
                                    f"(0.0.0.0/0, * oder Internet)."
                                ),
                                region=nsg.location or "global",
                                resource_id=nsg.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Network/networkSecurityGroups",
                                account_id=sub_id,
                                current_state={"open_inbound_rules": 0},
                                expected_state="Keine Inbound-Regeln mit Source 0.0.0.0/0 oder *",
                                audit_evidence=(
                                    f"network_security_groups.list_all(): {nsg.name} has no open inbound rules"
                                ),
                                iso27001_control="A.8.20, A.8.22 Netzwerksicherheit",
                            )
                        )
                    else:
                        rule_summary = ", ".join(f"{r['name']} (Port {r['port']})" for r in open_rules[:5])
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="NSG mit offenen Inbound-Regeln",
                                description=(
                                    f"NSG {nsg.name} in Subscription {sub_id} hat "
                                    f"{len(open_rules)} offene Inbound-Regeln aus dem Internet: "
                                    f"{rule_summary}."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.20, A.8.22 Netzwerksicherheit",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AZURE,
                                region=nsg.location or "global",
                                resource_id=nsg.id or f"/subscriptions/{sub_id}",
                                resource_type="Microsoft.Network/networkSecurityGroups",
                                account_id=sub_id,
                                current_state={
                                    "open_inbound_rules": open_rules[:10],
                                    # rule_summary above interpolates customer-chosen
                                    # NSG rule names into the description; the dict
                                    # list above is not collected (_collect_identifiers
                                    # only reads strings/lists-of-strings under a
                                    # suffixed key, never nested dict values). Suffix
                                    # key with a plain string list (ADR-0011);
                                    # _replace_in_state still rewrites the dicts too.
                                    "open_inbound_rule_name": [r["name"] for r in open_rules[:10]],
                                },
                                expected_state="Keine Inbound-Regeln mit Source 0.0.0.0/0 oder *",
                                remediation=(
                                    f"Schränken Sie die Quell-IP-Bereiche ein: "
                                    f"az network nsg rule update --nsg-name {nsg.name} "
                                    "--resource-group <rg> --name <rule-name> "
                                    "--source-address-prefixes <trusted-ip-range>"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"network_security_groups.list_all(): {nsg.name} "
                                    f"has {len(open_rules)} open inbound rules"
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


class CheckStoragePublicAccess(BaseCheck):
    """Check that Storage Accounts have public access disabled."""

    check_id = "AZ-NR9-004"
    title = "Storage Account — Private Access Only"
    description = "Prüft ob Storage Accounts keinen öffentlichen Zugriff erlauben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Storage/storageAccounts/read"]
    pruefgrenzen = (
        "Prüft nur die Netzwerkzugriffs-Einstellung der Storage Accounts. "
        "Berechtigungen auf Datenebene (SAS, Keys) werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.storage import StorageManagementClient

                storage_client = session.get_client(StorageManagementClient, sub_id)
                accounts = list(storage_client.storage_accounts.list())

                public_accounts = []
                for account in accounts:
                    is_public = False
                    public_access = str(account.public_network_access or "Enabled")
                    default_action = "Allow"
                    if account.network_rule_set:
                        default_action = str(account.network_rule_set.default_action or "Allow")

                    if public_access.lower() == "enabled" and default_action.lower() == "allow":
                        is_public = True

                    if is_public:
                        public_accounts.append(account.name)

                if accounts and not public_accounts:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Storage Accounts ohne öffentlichen Zugriff",
                            description=(
                                f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} "
                                f"haben öffentlichen Netzwerkzugriff deaktiviert oder eingeschränkt."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={"public_access_accounts": 0, "total_accounts": len(accounts)},
                            expected_state="Alle Storage Accounts mit deaktiviertem öffentlichen Zugriff",
                            audit_evidence=(f"storage_accounts.list(): 0/{len(accounts)} with public access enabled"),
                            iso27001_control="A.5.15, A.8.3 Zugriffskontrolle",
                        )
                    )
                elif public_accounts:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Storage Accounts mit öffentlichem Zugriff",
                            description=(
                                f"Subscription {sub_id} hat {len(public_accounts)} "
                                f"Storage Accounts mit öffentlichem Netzwerkzugriff: "
                                f"{', '.join(public_accounts[:5])}."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15, A.8.3 Zugriffskontrolle",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Storage/storageAccounts",
                            account_id=sub_id,
                            current_state={
                                "public_access_accounts": len(public_accounts),
                                # The description above interpolates the first 5
                                # storage account names via ", ".join(public_accounts).
                                # resource_id/account_id here only cover the
                                # subscription. Suffix key (ADR-0011) so the full
                                # list of account names gets pseudonymized.
                                "public_account_name": public_accounts,
                            },
                            expected_state="Alle Storage Accounts mit deaktiviertem öffentlichen Zugriff",
                            remediation=(
                                "Deaktivieren Sie öffentlichen Zugriff: "
                                "az storage account update --name <account> --resource-group <rg> "
                                "--default-action Deny --public-network-access Disabled"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"storage_accounts.list(): {len(public_accounts)}/{len(accounts)} "
                                "with public access enabled"
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


class CheckClassicAdmins(BaseCheck):
    """Check that no classic subscription administrators exist."""

    check_id = "AZ-NR9-005"
    title = "RBAC statt klassischer Subscription-Admin-Rollen"
    description = "Prüft ob klassische Subscription-Admin-Rollen (Co-Admins) noch verwendet werden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Authorization/classicAdministrators/read"]
    pruefgrenzen = (
        "Prüft nur auf klassische Administratorrollen. Die Angemessenheit der "
        "RBAC-Zuweisungen selbst wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.authorization import AuthorizationManagementClient

                auth_client = session.get_client(AuthorizationManagementClient, sub_id)
                classic_admins = list(auth_client.classic_administrators.list())

                # Filter for co-admins (not the service admin, which is always present)
                co_admins = [a for a in classic_admins if a.role and "CoAdministrator" in str(a.role)]

                if not co_admins:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine klassischen Co-Admin-Rollen",
                            description=(
                                f"Subscription {sub_id} verwendet keine klassischen "
                                f"Co-Administratoren — Zugriffssteuerung erfolgt über RBAC."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Authorization/classicAdministrators",
                            account_id=sub_id,
                            current_state={"co_administrators": 0},
                            expected_state="Keine klassischen Co-Admin-Rollen — nur RBAC",
                            audit_evidence="classic_administrators.list(): 0 co-administrators found",
                            iso27001_control="A.5.15 Zugriffskontrolle",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Klassische Co-Admin-Rollen aktiv",
                            description=(
                                f"Subscription {sub_id} hat {len(co_admins)} "
                                "klassische Co-Administratoren. Diese veralteten Rollen umgehen "
                                "RBAC und sollten durch moderne Rollenzuweisungen ersetzt werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Authorization/classicAdministrators",
                            account_id=sub_id,
                            current_state={"co_administrators": len(co_admins)},
                            expected_state="Keine klassischen Co-Admin-Rollen — nur RBAC",
                            remediation=(
                                "Entfernen Sie klassische Co-Admins und verwenden Sie RBAC: "
                                "Azure Portal → Subscriptions → <Sub> → Zugriffssteuerung (IAM) → "
                                "Klassische Administratoren"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(f"classic_administrators.list(): {len(co_admins)} co-administrators found"),
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


class CheckGuestAccessRestrictions(BaseCheck):
    """Check that guest user permissions are restricted."""

    check_id = "AZ-NR9-006"
    title = "Entra ID Guest Access Restrictions"
    description = "Prüft ob Gastbenutzer-Berechtigungen eingeschränkt sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft nur die Gastzugriffs-Einstellungen des Tenants (Graph API). "
        "Einzelne Gast-Berechtigungen werden in AZ-NR4-002 geprüft."
    )

    # Default role = same as members (most permissive)
    PERMISSIVE_GUEST_ROLE = "a0b1b346-4d3e-4e8b-98f8-753987be4970"

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            auth_policy = await graph.graph_get(
                session.credential, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
            )

            if auth_policy and auth_policy.get("guestUserRoleId"):
                guest_role = str(auth_policy.get("guestUserRoleId"))
                if guest_role != self.PERMISSIVE_GUEST_ROLE:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Gastbenutzer-Berechtigungen eingeschränkt",
                            description=(
                                "Gastbenutzer haben eingeschränkte Berechtigungen "
                                "(nicht dieselben Rechte wie Mitglieder)."
                            ),
                            region="global",
                            resource_id="/policies/authorizationPolicy",
                            resource_type="Microsoft.Graph/authorizationPolicy",
                            account_id=session.subscription_id,
                            current_state={"guest_user_role_id": guest_role},
                            expected_state=("Gastbenutzer-Rolle eingeschränkt (restricted guest oder most restricted)"),
                            audit_evidence=f"Graph API authorizationPolicy: guestUserRoleId={guest_role}",
                            iso27001_control="A.5.15 Zugriffskontrolle, A.5.16 Identitätsmanagement",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Gastbenutzer mit Mitglieder-Berechtigungen",
                            description=(
                                "Gastbenutzer haben dieselben Berechtigungen wie Mitglieder. "
                                "Externe Benutzer sollten eingeschränkte Rechte haben."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle, A.5.16 Identitätsmanagement",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id="/policies/authorizationPolicy",
                            resource_type="Microsoft.Graph/authorizationPolicy",
                            account_id=session.subscription_id,
                            current_state={"guest_user_role_id": guest_role},
                            expected_state="Gastbenutzer-Rolle eingeschränkt (restricted guest oder most restricted)",
                            remediation=(
                                "Schränken Sie Gastberechtigungen ein: "
                                "Entra Admin Center → Externe Identitäten → "
                                "Einstellungen für externe Zusammenarbeit → "
                                "Gastbenutzer-Zugriff einschränken"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"Graph API authorizationPolicy: guestUserRoleId={guest_role}",
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


class CheckStaleServicePrincipals(BaseCheck):
    """Check for service principals inactive for more than 90 days (Graph beta report)."""

    check_id = "AZ-NR9-007"
    title = "Inaktive Service Principals (>90 Tage)"
    description = "Prüft ob Service Principals existieren, die seit über 90 Tagen inaktiv sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Application.Read.All", "AuditLog.Read.All"]
    pruefgrenzen = (
        "Ermittelt die letzte Anmeldung je Service Principal über den "
        "Microsoft-Graph-Report servicePrincipalSignInActivities (Beta-Endpoint; "
        "von Microsoft ohne Produktions-Support bereitgestellt und jederzeit "
        "änderbar). Service Principals ohne Sign-in-Datensatz — z. B. nie "
        "verwendete oder solche außerhalb des Log-Horizonts des Tenants — "
        "werden als nicht bewertbar gemeldet, nie als konform. Service "
        "Principals aus den beiden Microsoft-eigenen Tenants (Microsoft "
        "Services, Microsoft-Erstanbieter-Apps) sind ausgenommen."
    )

    # Documented maximum page size for /servicePrincipals is 100.
    SP_URL = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,appOwnerOrganizationId&$top=100"
    SIGNIN_REPORT_URL = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities"
    # Microsoft-owned tenants hosting first-party apps (B1, legal review):
    # f8cdef31… = Microsoft Services, 72f988bf… = Microsoft first-party apps.
    MS_TENANT_IDS = frozenset(
        {
            "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
            "72f988bf-86f1-41af-91ab-2d7cd011db47",
        }
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            service_principals = await graph.graph_get_all(session.credential, self.SP_URL)
            activities = await graph.graph_get_all(session.credential, self.SIGNIN_REPORT_URL)

            last_sign_in_by_app: dict[str, datetime] = {}
            for activity in activities:
                app_id = activity.get("appId")
                last_raw = (activity.get("lastSignInActivity") or {}).get("lastSignInDateTime")
                if app_id and last_raw:
                    last_sign_in_by_app[app_id] = datetime.fromisoformat(last_raw)

            threshold = datetime.now(UTC) - timedelta(days=MAX_INACTIVE_DAYS)
            stale_count = 0
            evaluated_count = 0
            unknown_count = 0

            for sp in service_principals:
                # Skip Microsoft first-party apps (both MS-owned tenants)
                if sp.get("appOwnerOrganizationId") in self.MS_TENANT_IDS:
                    continue

                last_sign_in = last_sign_in_by_app.get(sp.get("appId", ""))
                if last_sign_in:
                    evaluated_count += 1
                    if last_sign_in < threshold:
                        stale_count += 1
                else:
                    # No report entry: never signed in or outside the tenant's
                    # log horizon — not evaluable (fail-safe, ADR-0016).
                    unknown_count += 1

            if evaluated_count and unknown_count == 0 and stale_count == 0:
                # Positive evidence only when every SP had sign-in data (ADR-0016)
                findings.append(
                    compliant_finding(
                        self,
                        title="Keine inaktiven Service Principals",
                        description=(
                            f"Alle {evaluated_count} geprüften Service Principals wurden innerhalb "
                            f"der letzten {MAX_INACTIVE_DAYS} Tage verwendet."
                        ),
                        region="global",
                        resource_id="/servicePrincipals",
                        resource_type="Microsoft.Graph/servicePrincipals",
                        account_id=session.subscription_id,
                        current_state={"stale_service_principals": 0, "evaluated": evaluated_count},
                        expected_state=f"Keine Service Principals > {MAX_INACTIVE_DAYS} Tage inaktiv",
                        audit_evidence=(
                            f"Graph beta report servicePrincipalSignInActivities: "
                            f"0/{evaluated_count} service principals inactive > {MAX_INACTIVE_DAYS} days"
                        ),
                        iso27001_control="A.5.15 Zugriffskontrolle",
                    )
                )
            elif stale_count > 0:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Inaktive Service Principals gefunden",
                        description=(
                            f"Es wurden {stale_count} Service Principals gefunden, die seit über "
                            f"{MAX_INACTIVE_DAYS} Tagen nicht verwendet wurden. "
                            "Nicht genutzte Identitäten sollten bereinigt werden."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.15 Zugriffskontrolle",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/servicePrincipals",
                        resource_type="Microsoft.Graph/servicePrincipals",
                        account_id=session.subscription_id,
                        current_state={"stale_service_principals": stale_count},
                        expected_state=f"Keine Service Principals > {MAX_INACTIVE_DAYS} Tage inaktiv",
                        remediation=(
                            "Überprüfen und entfernen bzw. deaktivieren Sie nicht genutzte "
                            "Service Principals: Entra Admin Center → Unternehmensanwendungen; "
                            "letzte Nutzung über Anmeldeprotokolle → "
                            "Dienstprinzipal-Anmeldungen abgleichen"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(
                            f"Graph beta report servicePrincipalSignInActivities: "
                            f"{stale_count}/{evaluated_count} evaluated "
                            f"service principals inactive > {MAX_INACTIVE_DAYS} days"
                        ),
                    )
                )

            if unknown_count > 0:
                errors.append(
                    CheckError(
                        check_id=self.check_id,
                        error_type="InconclusiveState",
                        message=(
                            f"{unknown_count} Service Principal(s) ohne Eintrag im Graph-Report "
                            "servicePrincipalSignInActivities — nicht bewertbar (z. B. nie "
                            "angemeldet oder außerhalb des Log-Horizonts des Tenants)"
                        ),
                        region="global",
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
