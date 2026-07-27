"""§30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for Azure.

Checks Lighthouse Delegations, Guest Users with Conditional Access,
Private Endpoints, Service Principal Credentials, and Marketplace Image Trust.
"""

from datetime import UTC, datetime, timedelta
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

MAX_CREDENTIAL_AGE_DAYS = 90


class CheckLighthouseDelegations(BaseCheck):
    """Check that Azure Lighthouse delegations are audited."""

    check_id = "AZ-NR4-001"
    title = "Lighthouse Delegations geprüft"
    description = "Prüft ob Azure Lighthouse-Delegierungen für verwaltete Dienstleister kontrolliert werden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.ManagedServices/registrationAssignments/read"]
    pruefgrenzen = (
        "Prüft nur registrierte Lighthouse-Delegationen. Ob eine Delegation an einen "
        "Dienstleister legitim und vertraglich geregelt ist, ist organisatorisch zu bewerten."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource.resources import ResourceManagementClient

                resource_client = session.get_client(ResourceManagementClient, sub_id)
                delegations = [
                    r
                    for r in resource_client.resources.list(
                        filter="resourceType eq 'Microsoft.ManagedServices/registrationAssignments'"
                    )
                ]

                if not delegations:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine Lighthouse-Delegierungen",
                            description=(
                                f"Subscription {sub_id} hat keine Azure Lighthouse-Delegierungen — "
                                f"kein externer Dienstleister-Zugriff über Lighthouse."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.ManagedServices/registrationAssignments",
                            account_id=sub_id,
                            current_state={"lighthouse_delegations": 0},
                            expected_state="Alle Lighthouse-Delegierungen dokumentiert und genehmigt",
                            audit_evidence="resources.list(): 0 Lighthouse delegations found",
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Lighthouse-Delegierungen vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(delegations)} "
                                "Lighthouse-Delegierungen. Diese ermöglichen externen Dienstleistern "
                                "Zugriff und sollten regelmäßig überprüft werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.ManagedServices/registrationAssignments",
                            account_id=sub_id,
                            current_state={"lighthouse_delegations": len(delegations)},
                            expected_state="Alle Lighthouse-Delegierungen dokumentiert und genehmigt",
                            remediation=(
                                "Überprüfen Sie alle Lighthouse-Delegierungen: "
                                "Azure Portal → Dienstanbieter → Delegierungen prüfen. "
                                "Entfernen Sie nicht autorisierte Delegierungen."
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(f"resources.list(): {len(delegations)} Lighthouse delegations found"),
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


class CheckGuestUsersConditionalAccess(BaseCheck):
    """Check that guest users are covered by Conditional Access policies."""

    check_id = "AZ-NR4-002"
    title = "Guest Users (B2B) mit Conditional Access"
    description = "Prüft ob B2B-Gastbenutzer durch Conditional Access Policies abgesichert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["User.Read.All", "Policy.Read.All"]
    pruefgrenzen = (
        "Prüft Gastkonten gegen Conditional-Access-Policies. Ohne Gastkonten liefert "
        "der Check kein Ergebnis (Nicht anwendbar). Die inhaltliche Angemessenheit "
        "der Policies wird nicht bewertet. Policies, die Gäste ausschließlich über "
        "Gruppenzuordnung erfassen, werden nicht erkannt (konservative Wertung)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            # Check for guest users (paginated — a tenant may have more than one page of users)
            users = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/users?$select=id,userType&$top=999"
            )
            guest_users = [u for u in users if u.get("userType") and str(u.get("userType")).lower() == "guest"]

            if not guest_users:
                return CheckResult(check_id=self.check_id, findings=findings, errors=errors)

            # Check if any CA policy targets guest users (paginated)
            policies = await graph.graph_get_all(
                session.credential, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            )

            guest_ca_found = False
            for policy in policies:
                if policy.get("state") and str(policy.get("state")).lower() == "enabled":
                    conditions = policy.get("conditions")
                    users_cond = conditions.get("users") if conditions else None
                    if users_cond:
                        include_users = users_cond.get("includeUsers") or []
                        include_guest = users_cond.get("includeGuestsOrExternalUsers")
                        if "All" in include_users or "GuestsOrExternalUsers" in include_users or include_guest:
                            guest_ca_found = True
                            break

            if guest_ca_found:
                findings.append(
                    compliant_finding(
                        self,
                        title="Gastbenutzer durch Conditional Access abgesichert",
                        description=(
                            f"Es gibt {len(guest_users)} Gastbenutzer und mindestens eine aktive "
                            f"Conditional Access Policy, die Gastbenutzer einschließt."
                        ),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"guest_users": len(guest_users), "guest_ca_policy_found": True},
                        expected_state="Conditional Access Policy für Gastbenutzer",
                        audit_evidence=(
                            f"Graph API: {len(guest_users)} guest users, CA policy targeting guests active"
                        ),
                        iso27001_control=(
                            "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Gastbenutzer ohne Conditional Access",
                        description=(
                            f"Es gibt {len(guest_users)} Gastbenutzer, aber keine Conditional Access "
                            "Policy, die explizit Gastbenutzer einschließt. Externe Benutzer sollten "
                            "denselben Sicherheitsanforderungen unterliegen."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control=(
                            "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                        ),
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={"guest_users": len(guest_users), "guest_ca_policies": 0},
                        expected_state="Conditional Access Policy für Gastbenutzer",
                        remediation=(
                            "Erstellen Sie eine CA-Policy für Gastbenutzer: "
                            "Entra Admin Center → Schutz → Bedingter Zugriff → "
                            "Neue Richtlinie → Benutzer: Gäste und externe Benutzer"
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(f"Graph API: {len(guest_users)} guest users, no CA policy targeting guests"),
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


class CheckPrivateEndpoints(BaseCheck):
    """Check that PaaS services use private endpoints."""

    check_id = "AZ-NR4-003"
    title = "Private Endpoints für PaaS-Dienste"
    description = "Prüft ob PaaS-Dienste über Private Endpoints abgesichert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Network/privateEndpoints/read"]
    pruefgrenzen = (
        "Prüft nur, ob PaaS-Dienste Private Endpoints nutzen. Nicht jede öffentliche "
        "PaaS-Anbindung ist ein Lieferketten-Risiko — Bewertung im Kontext nötig."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.network import NetworkManagementClient

                network_client = session.get_client(NetworkManagementClient, sub_id)
                private_endpoints = list(network_client.private_endpoints.list_by_subscription())

                if private_endpoints:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Private Endpoints konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat {len(private_endpoints)} Private Endpoint(s) "
                                f"konfiguriert — private Anbindung von PaaS-Diensten wird genutzt."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/privateEndpoints",
                            account_id=sub_id,
                            current_state={"private_endpoints": len(private_endpoints)},
                            expected_state="Private Endpoints für kritische PaaS-Dienste",
                            audit_evidence=(
                                f"private_endpoints.list_by_subscription() returned "
                                f"{len(private_endpoints)} endpoint(s)"
                            ),
                            iso27001_control="A.5.19, A.8.22 Netzwerk-Isolation",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Private Endpoints konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat keine Private Endpoints. Sofern PaaS-Dienste "
                                "(z. B. Storage, SQL, Key Vault) genutzt werden, erfolgt deren Anbindung "
                                "ohne Private Endpoints über öffentliche Endpunkte."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19, A.8.22 Netzwerk-Isolation",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Network/privateEndpoints",
                            account_id=sub_id,
                            current_state={"private_endpoints": 0},
                            expected_state="Private Endpoints für kritische PaaS-Dienste",
                            remediation=(
                                "Erstellen Sie Private Endpoints für PaaS-Dienste: "
                                "az network private-endpoint create --name <pe-name> "
                                "--resource-group <rg> --vnet-name <vnet> --subnet <subnet> "
                                "--private-connection-resource-id <resource-id>"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence="private_endpoints.list_by_subscription() returned 0 endpoints",
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


class CheckServicePrincipalCredentials(BaseCheck):
    """Check that service principal credentials are rotated regularly."""

    check_id = "AZ-NR4-004"
    title = "Service Principal Credentials rotiert"
    description = "Prüft ob Service Principal Credentials regelmäßig rotiert werden."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Application.Read.All"]
    pruefgrenzen = (
        "Prüft nur das Alter der Client-Secrets (password credentials) von App-Registrierungen; "
        "Zertifikate (key credentials) werden nicht bewertet. Workload Identity Federation ohne "
        "Secrets wird als konform gewertet. Tenants ohne App-Registrierungen liefern kein "
        "Ergebnis (Nicht anwendbar)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from nis2scan.engine.providers.azure import graph

            # Paginated — a tenant may have more than one page of app registrations
            applications = await graph.graph_get_all(
                session.credential,
                "https://graph.microsoft.com/v1.0/applications?$select=id,displayName,passwordCredentials&$top=999",
            )

            threshold = datetime.now(UTC) - timedelta(days=MAX_CREDENTIAL_AGE_DAYS)
            old_creds_count = 0

            for app in applications:
                password_creds = app.get("passwordCredentials") or []
                for cred in password_creds:
                    start_raw = cred.get("startDateTime")
                    if start_raw and datetime.fromisoformat(start_raw) < threshold:
                        old_creds_count += 1
                        break  # Count each app once

            if applications and old_creds_count == 0:
                findings.append(
                    compliant_finding(
                        self,
                        title="Service Principal Credentials aktuell",
                        description=(
                            f"Alle {len(applications)} Anwendungen haben Credentials jünger als "
                            f"{MAX_CREDENTIAL_AGE_DAYS} Tage."
                        ),
                        region="global",
                        resource_id="/applications",
                        resource_type="Microsoft.Graph/applications",
                        account_id=session.subscription_id,
                        current_state={"apps_with_old_credentials": 0, "applications": len(applications)},
                        expected_state=f"Alle Credentials jünger als {MAX_CREDENTIAL_AGE_DAYS} Tage",
                        audit_evidence=(
                            f"Graph API: 0/{len(applications)} apps with credentials > {MAX_CREDENTIAL_AGE_DAYS} days"
                        ),
                        iso27001_control=(
                            "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                        ),
                    )
                )
            elif old_creds_count > 0:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Service Principal Credentials nicht rotiert",
                        description=(
                            f"Es gibt {old_creds_count} Anwendungen mit Credentials älter als "
                            f"{MAX_CREDENTIAL_AGE_DAYS} Tage. Langlebige Credentials erhöhen das "
                            "Kompromittierungsrisiko."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control=(
                            "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                        ),
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/applications",
                        resource_type="Microsoft.Graph/applications",
                        account_id=session.subscription_id,
                        current_state={"apps_with_old_credentials": old_creds_count},
                        expected_state=f"Alle Credentials jünger als {MAX_CREDENTIAL_AGE_DAYS} Tage",
                        remediation=(
                            "Rotieren Sie abgelaufene Credentials: "
                            "az ad app credential reset --id <app-id> --years 1. "
                            "Verwenden Sie Managed Identities wo möglich."
                        ),
                        remediation_effort="MEDIUM",
                        audit_evidence=(
                            f"Graph API: {old_creds_count}/{len(applications)} apps "
                            f"with credentials > {MAX_CREDENTIAL_AGE_DAYS} days"
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


class CheckMarketplaceImageTrust(BaseCheck):
    """Check that VMs use trusted marketplace images."""

    check_id = "AZ-NR4-005"
    title = "VM-Images von bekannten Publishern"
    description = "Prüft die Image-Publisher vorhandener VMs gegen eine feste Liste bekannter Publisher."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Compute/virtualMachines/read"]
    pruefgrenzen = (
        "Prüft die Image-Publisher vorhandener VMs gegen eine feste Liste bekannter Publisher. "
        "Ob eine Azure Policy den Bezug von Marketplace-Images einschränkt, wird nicht geprüft; "
        "VMs aus Custom Images (ohne Publisher) werden nicht bewertet. Die Vertrauenswürdigkeit "
        "einzelner Images wird nicht bewertet. Subscriptions ohne VMs liefern kein Ergebnis "
        "(Nicht anwendbar)."
    )

    # Well-known trusted publishers
    TRUSTED_PUBLISHERS = {
        "Canonical",
        "MicrosoftWindowsServer",
        "MicrosoftWindowsDesktop",
        "RedHat",
        "SUSE",
        "Oracle",
        "center-for-internet-security-inc",
        "microsoftcblmariner",
    }

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.compute import ComputeManagementClient

                compute_client = session.get_client(ComputeManagementClient, sub_id)
                vms = list(compute_client.virtual_machines.list_all())

                untrusted_vms = []
                for vm in vms:
                    if vm.storage_profile and vm.storage_profile.image_reference:
                        ref = vm.storage_profile.image_reference
                        publisher = ref.publisher or ""
                        if publisher and publisher not in self.TRUSTED_PUBLISHERS:
                            untrusted_vms.append({"name": vm.name, "publisher": publisher})

                if vms and not untrusted_vms:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine VMs mit unbekannten Image-Publishern",
                            description=(
                                f"In Subscription {sub_id} wurden keine VMs mit Marketplace-Images "
                                f"von unbekannten Publishern gefunden ({len(vms)} VM(s) geprüft)."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/virtualMachines",
                            account_id=sub_id,
                            current_state={"untrusted_image_vms": 0, "total_vms": len(vms)},
                            expected_state="Nur VMs mit Images von vertrauenswürdigen Publishern",
                            audit_evidence=(f"virtual_machines.list_all(): 0/{len(vms)} with untrusted publishers"),
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                        )
                    )
                elif untrusted_vms:
                    vm_summary = ", ".join(f"{v['name']} ({v['publisher']})" for v in untrusted_vms[:5])
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="VMs mit nicht-vertrauenswürdigen Images",
                            description=(
                                f"Subscription {sub_id} hat {len(untrusted_vms)} "
                                f"VMs mit Marketplace-Images von unbekannten Publishern: {vm_summary}."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Compute/virtualMachines",
                            account_id=sub_id,
                            current_state={
                                "untrusted_image_vms": len(untrusted_vms),
                                # vm_summary above interpolates VM names into the
                                # description; resource_id/account_id here only
                                # cover the subscription. Suffix key (ADR-0011) so
                                # the names get pseudonymized. Deliberately SINGULAR
                                # ("_name") — the deny-list regex matches the key's
                                # end, so a later plural "fix" would reopen the leak.
                                "untrusted_vm_name": [v["name"] for v in untrusted_vms],
                            },
                            expected_state="Nur VMs mit Images von vertrauenswürdigen Publishern",
                            remediation=(
                                "Überprüfen Sie die Image-Quellen und verwenden Sie nur "
                                "vertrauenswürdige Publisher. Setzen Sie Azure Policy für "
                                "erlaubte VM-Images ein."
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"virtual_machines.list_all(): {len(untrusted_vms)}/{len(vms)} "
                                "with untrusted publishers"
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
