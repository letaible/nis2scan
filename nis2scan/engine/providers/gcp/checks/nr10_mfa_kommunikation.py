"""§30 Abs. 2 Nr. 10 — Multi-Faktor-Authentifizierung und gesicherte Kommunikation checks for GCP.

Checks Two-Step Verification, IAP Admin Access, VPN Gateways,
OS Login 2FA, and Secure Identity (LDAP).
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


class CheckTwoStepVerification(BaseCheck):
    """Prüft ob Zwei-Faktor-Authentifizierung erzwungen wird."""

    check_id = "GCP-NR10-001"
    title = "Zwei-Faktor-Authentifizierung (2SV) erzwungen"
    description = (
        "Prüft ob die Zwei-Faktor-Authentifizierung für Google Workspace oder Cloud Identity Benutzer erzwungen wird."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["admin.directory.users.list"]
    pruefgrenzen = (
        "Prüft nur Google-Workspace-/Cloud-Identity-Benutzer über das Admin SDK. "
        "Ohne Workspace-Admin-Berechtigung ist die Prüfung nicht möglich und liefert "
        "kein Ergebnis (Nicht anwendbar) — die 2FA-Durchsetzung ist dann manuell "
        "nachzuweisen. MFA außerhalb von Google (VPN, lokale Systeme) wird nie geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                # Admin SDK requires Workspace admin privileges
                # This may not be accessible for all projects
                service = session.service("admin", "directory_v1")
                users: list[dict[str, Any]] = []
                page_token: str | None = None
                while True:
                    request_kwargs: dict[str, Any] = {
                        "customer": "my_customer",
                        "maxResults": 100,
                        "projection": "full",
                    }
                    if page_token:
                        request_kwargs["pageToken"] = page_token
                    page = service.users().list(**request_kwargs).execute()
                    users.extend(page.get("users", []))
                    page_token = page.get("nextPageToken")
                    if not page_token:
                        break

                if not users:
                    # No exception in scope here — the API succeeded but returned no
                    # evaluable users. UnverifiableState is the repo-wide marker for
                    # "nicht bewertbar" (same as AWS-NR8-001 empty rules).
                    errors.append(
                        CheckError(
                            message=(f"Projekt {project_id}: keine Benutzer abrufbar — nicht bewertbar"),
                            error_type="UnverifiableState",
                        )
                    )
                    continue

                users_without_2sv = [u for u in users if not u.get("isEnforcedIn2Sv", False)]

                if not users_without_2sv:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Zwei-Faktor-Authentifizierung für alle Benutzer erzwungen",
                            description=(
                                f"Projekt {project_id}: Alle {len(users)} Benutzer haben "
                                f"eine erzwungene Zwei-Faktor-Authentifizierung (2SV)."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/users",
                            resource_type="gcp.admin.User",
                            account_id=project_id,
                            current_state={
                                "total_users": len(users),
                                "users_without_2sv": 0,
                            },
                            expected_state=("Alle Benutzer mit erzwungener Zwei-Faktor-Authentifizierung (2SV)"),
                            audit_evidence=(f"admin.users.list(): 0/{len(users)} users without enforced 2SV"),
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Benutzer ohne erzwungene 2-Faktor-Authentifizierung",
                            description=(
                                f"Projekt {project_id}: "
                                f"{len(users_without_2sv)} von {len(users)} "
                                "Benutzern haben keine erzwungene Zwei-Faktor-"
                                "Authentifizierung. Ohne MFA sind Konten anfällig "
                                "für Credential-basierte Angriffe."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/users",
                            resource_type="gcp.admin.User",
                            account_id=project_id,
                            current_state={
                                "total_users": len(users),
                                "users_without_2sv": len(users_without_2sv),
                            },
                            expected_state=("Alle Benutzer mit erzwungener Zwei-Faktor-Authentifizierung (2SV)"),
                            remediation=(
                                "Erzwingen Sie 2SV in der Google Admin Console:\n"
                                "1. Öffnen Sie admin.google.com > Sicherheit > "
                                "Authentifizierung > 2-Faktor-Authentifizierung\n"
                                "2. Aktivieren Sie 'Erzwingen' für alle Organisationseinheiten\n"
                                "3. Setzen Sie eine Frist für die 2SV-Registrierung"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"admin.users.list(): {len(users_without_2sv)}/{len(users)} users without enforced 2SV"
                            ),
                        )
                    )
            except Exception as exc:
                error_msg = str(exc).lower()
                if (
                    "not enabled" in error_msg
                    or "403" in error_msg
                    or "permission" in error_msg
                    or "not found" in error_msg
                ):
                    # Admin SDK requires Workspace admin; log as info
                    logger.info(
                        "admin.directory.not_accessible",
                        project=project_id,
                        hint="Admin SDK requires Google Workspace admin privileges",
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIapAdminAccess(BaseCheck):
    """Prüft ob IAP für administrativen Zugriff konfiguriert ist."""

    check_id = "GCP-NR10-002"
    title = "IAP für administrativen Zugriff"
    description = (
        "Prüft ob Identity-Aware Proxy (IAP) für den administrativen "
        "Zugriff auf Ressourcen konfiguriert ist, anstatt direkten "
        "SSH- oder VPN-Zugriff zu verwenden."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["iap.tunnelInstances.getIamPolicy"]
    pruefgrenzen = (
        "Prüft nur IAP-Tunnelrichtlinien für Admin-Zugriff. Andere MFA-gesicherte Zugriffswege werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("iap", "v1")
                # getIamPolicy/setIamPolicy/testIamPermissions are top-level RPCs in
                # the IAP API (id "iap.getIamPolicy", no resource segment) — the
                # discovery client exposes them on the synthetic `v1()` resource, NOT
                # under projects().iap_tunnel() (real-API-verified 27.07.2026:
                # projects().iap_tunnel() has no getIamPolicy attribute at all).
                result = (
                    service.v1()
                    .getIamPolicy(
                        resource=f"projects/{project_id}/iap_tunnel",
                        body={},
                    )
                    .execute()
                )
                bindings = result.get("bindings", [])

                if bindings:
                    findings.append(
                        compliant_finding(
                            self,
                            title="IAP-Tunnel-IAM-Richtlinie vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(bindings)} IAP-Tunnel-Richtlinie(n) für "
                                f"administrativen Zugriff. Ob MFA tatsächlich wirkt, hängt von der "
                                f"2SV-/Access-Context-Konfiguration ab und wird hier nicht verifiziert."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/iap_tunnel",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_tunnel_bindings": len(bindings)},
                            expected_state="IAP-Tunnel-IAM-Richtlinie vorhanden",
                            audit_evidence=f"iap_tunnel.getIamPolicy() returned {len(bindings)} bindings",
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein IAP für administrativen Zugriff konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "IAP-Tunnel-Richtlinien für administrativen Zugriff. "
                                "IAP bietet Multi-Faktor-Authentifizierung und "
                                "kontextabhängige Zugriffskontrolle für SSH/RDP. "
                                "IAP ist einer von mehreren möglichen gesicherten Admin-Zugriffswegen; "
                                "alternative Wege prüft GCP-NR10-003."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/iap_tunnel",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_tunnel_bindings": 0},
                            expected_state="IAP-Tunnel-IAM-Richtlinie vorhanden",
                            remediation=(
                                "Konfigurieren Sie IAP für administrativen Zugriff:\n"
                                "1. gcloud services enable iap.googleapis.com "
                                "--project=<PROJECT_ID>\n"
                                "2. gcloud iap tunnel instances add-iam-policy-binding "
                                "--project=<PROJECT_ID> "
                                "--member=user:<ADMIN_EMAIL> "
                                "--role=roles/iap.tunnelResourceAccessor\n"
                                "3. Verwenden Sie 'gcloud compute ssh <INSTANCE> "
                                "--tunnel-through-iap' für SSH-Zugriff"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="iap_tunnel.getIamPolicy() returned 0 bindings",
                        )
                    )
            except Exception as exc:
                error_msg = str(exc).lower()
                # Only explicit service-disabled signals count as "not enabled";
                # a bare 403/permission error is an unknown state -> CheckError
                # (same classification as GCP-NR10-003 and GCP-NR9-003).
                if "not enabled" in error_msg or "has not been used" in error_msg or "service_disabled" in error_msg:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAP API nicht aktiviert",
                            description=(
                                f"Projekt {project_id}: Die IAP-Tunnel-Richtlinie konnte nicht "
                                "abgerufen werden, weil die IAP API nicht aktiviert ist. IAP ist "
                                "einer von mehreren möglichen gesicherten Admin-Zugriffswegen "
                                "(alternative Wege prüft GCP-NR10-003); ob MFA für administrative "
                                "Zugriffe anderweitig gewährleistet ist, wird hier nicht bewertet."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/iap",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_api_enabled": False},
                            expected_state="IAP API aktiviert und konfiguriert",
                            remediation=(
                                "Aktivieren Sie die IAP API:\n"
                                "gcloud services enable iap.googleapis.com "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"IAP API returned error: {type(exc).__name__}",
                        )
                    )
                elif "403" in error_msg or "permission" in error_msg:
                    errors.append(
                        CheckError(
                            message=f"Projekt {project_id}: IAP-Status nicht prüfbar (Berechtigung/API): {exc}",
                            error_type=type(exc).__name__,
                        )
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpnGateways(BaseCheck):
    """Prüft ob VPN-Gateways für sichere Konnektivität vorhanden sind."""

    check_id = "GCP-NR10-003"
    title = "VPN-Gateways für sichere Konnektivität"
    description = (
        "Prüft ob VPN-Gateways oder IAP für sichere Konnektivität "
        "konfiguriert sind, um verschlüsselte Kommunikationskanäle "
        "sicherzustellen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.vpnGateways.list", "iap.tunnelInstances.getIamPolicy"]
    pruefgrenzen = "Prüft nur GCP-eigene VPN-Gateways und IAP-Tunnel. Drittanbieter-VPNs werden nicht erkannt."

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import VpnGatewaysClient

                client = VpnGatewaysClient(credentials=session.credentials)
                vpn_gateways_by_region = client.aggregated_list(
                    request={"project": project_id},
                )

                has_vpn = False
                vpn_count = 0
                for _region, scoped_list in vpn_gateways_by_region:
                    if scoped_list.vpn_gateways:
                        has_vpn = True
                        vpn_count += len(scoped_list.vpn_gateways)

                if has_vpn:
                    findings.append(
                        compliant_finding(
                            self,
                            title="VPN-Gateways für sichere Konnektivität vorhanden",
                            description=(
                                f"Projekt {project_id} hat {vpn_count} VPN-Gateway(s) "
                                f"für verschlüsselte Kommunikationskanäle konfiguriert."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/vpnGateways",
                            resource_type="gcp.compute.VpnGateway",
                            account_id=project_id,
                            current_state={"vpn_gateways": vpn_count},
                            expected_state=("VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"),
                            audit_evidence=(f"vpnGateways.aggregated_list() returned {vpn_count} gateways"),
                            iso27001_control="A.8.20 Netzwerksicherheit",
                        )
                    )
                else:
                    # Also check if IAP is available as alternative
                    has_iap = False
                    iap_status_unknown = False
                    try:
                        iap_service = session.service("iap", "v1")
                        # Same fix as CheckIapAdminAccess/CheckIdentityAwareProxy:
                        # getIamPolicy is a top-level IAP RPC exposed on the
                        # synthetic v1() resource, not projects().iap_tunnel()
                        # (real-API-verified 27.07.2026).
                        iap_result = (
                            iap_service.v1()
                            .getIamPolicy(
                                resource=f"projects/{project_id}/iap_tunnel",
                                body={},
                            )
                            .execute()
                        )
                        has_iap = bool(iap_result.get("bindings", []))
                    except Exception as iap_exc:
                        iap_status_unknown = True
                        errors.append(
                            CheckError(
                                message=f"Projekt {project_id}: IAP-Status nicht prüfbar: {iap_exc}",
                                error_type=type(iap_exc).__name__,
                            )
                        )

                    if has_iap:
                        findings.append(
                            compliant_finding(
                                self,
                                title="IAP-Tunnel als sichere Konnektivitätslösung vorhanden",
                                description=(
                                    f"Projekt {project_id} hat zwar keine VPN-Gateways, aber "
                                    f"IAP-Tunnel für verschlüsselte administrative Zugriffe "
                                    f"konfiguriert."
                                ),
                                region="global",
                                resource_id=f"projects/{project_id}/vpnGateways",
                                resource_type="gcp.compute.VpnGateway",
                                account_id=project_id,
                                current_state={
                                    "vpn_gateways": 0,
                                    "iap_configured": True,
                                },
                                expected_state=("VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"),
                                audit_evidence=(
                                    "vpnGateways.aggregated_list() returned 0 gateways, IAP tunnel bindings present"
                                ),
                                iso27001_control="A.8.20 Netzwerksicherheit",
                            )
                        )
                    elif iap_status_unknown:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Keine VPN-Gateways konfiguriert",
                                description=(
                                    f"Projekt {project_id} hat keine VPN-Gateways konfiguriert. Der "
                                    "IAP-Status konnte nicht geprüft werden (siehe Fehlermeldung) und "
                                    "wird hier nicht als Nachweis gewertet."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.20 Netzwerksicherheit",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"projects/{project_id}/vpnGateways",
                                resource_type="gcp.compute.VpnGateway",
                                account_id=project_id,
                                current_state={
                                    "vpn_gateways": 0,
                                    "iap_configured": "unbekannt",
                                },
                                expected_state=("VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"),
                                remediation=(
                                    "Konfigurieren Sie ein VPN-Gateway:\n"
                                    "gcloud compute vpn-gateways create <GATEWAY_NAME> "
                                    "--network=<NETWORK> --region=<REGION> "
                                    "--project=<PROJECT_ID>\n"
                                    "Prüfen Sie zusätzlich den IAP-Status manuell, da die automatische "
                                    "Prüfung fehlgeschlagen ist."
                                ),
                                remediation_effort="HIGH",
                                audit_evidence=(
                                    "vpnGateways.aggregated_list() returned 0 gateways, IAP-Status nicht prüfbar"
                                ),
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Keine VPN-Gateways oder IAP konfiguriert",
                                description=(
                                    f"Projekt {project_id} hat weder "
                                    "VPN-Gateways noch IAP-Tunnel konfiguriert. "
                                    "Ohne sichere Konnektivitätslösungen sind "
                                    "administrative Zugriffe nicht verschlüsselt."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.20 Netzwerksicherheit",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"projects/{project_id}/vpnGateways",
                                resource_type="gcp.compute.VpnGateway",
                                account_id=project_id,
                                current_state={
                                    "vpn_gateways": 0,
                                    "iap_configured": False,
                                },
                                expected_state=("VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"),
                                remediation=(
                                    "Konfigurieren Sie ein VPN-Gateway:\n"
                                    "gcloud compute vpn-gateways create <GATEWAY_NAME> "
                                    "--network=<NETWORK> --region=<REGION> "
                                    "--project=<PROJECT_ID>\n"
                                    "Oder verwenden Sie IAP-Tunnel als Alternative:\n"
                                    "gcloud services enable iap.googleapis.com "
                                    "--project=<PROJECT_ID>"
                                ),
                                remediation_effort="HIGH",
                                audit_evidence=(
                                    "vpnGateways.aggregated_list() returned 0 gateways, IAP tunnel not configured"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOsLoginWith2fa(BaseCheck):
    """Prüft ob OS Login mit 2FA aktiviert ist."""

    check_id = "GCP-NR10-004"
    title = "OS Login mit Zwei-Faktor-Authentifizierung"
    description = (
        "Prüft ob OS Login und OS Login 2FA in den Projekt-Metadaten "
        "aktiviert sind, um Multi-Faktor-Authentifizierung für "
        "SSH-Zugriff auf VMs zu erzwingen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.projects.get"]
    pruefgrenzen = (
        "Prüft nur die Projekt-Metadaten (enable-oslogin/-2fa). Instanz-Metadaten "
        "können die Projekteinstellung überschreiben und werden nicht einzeln geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import ProjectsClient

                client = ProjectsClient(credentials=session.credentials)
                project = client.get(request={"project": project_id})

                # Check common instance metadata. Note: the proto field is `items`
                # (real-API-verified 27.07.2026: `items_` raises "Unknown field for
                # Metadata: items_" — proto-plus does not trailing-underscore this
                # field, unlike Python-reserved-word fields).
                metadata_items = {}
                if project.common_instance_metadata and project.common_instance_metadata.items:
                    for item in project.common_instance_metadata.items:
                        metadata_items[item.key] = item.value

                os_login = metadata_items.get("enable-oslogin", "").upper()
                os_login_2fa = metadata_items.get("enable-oslogin-2fa", "").upper()

                if os_login == "TRUE" and os_login_2fa == "TRUE":
                    findings.append(
                        compliant_finding(
                            self,
                            title="OS Login mit 2FA aktiviert",
                            description=(
                                f"Projekt {project_id} erzwingt OS Login mit "
                                f"Zwei-Faktor-Authentifizierung für SSH-Zugriff auf VMs."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/metadata",
                            resource_type="gcp.compute.ProjectMetadata",
                            account_id=project_id,
                            current_state={
                                "enable-oslogin": "TRUE",
                                "enable-oslogin-2fa": "TRUE",
                            },
                            expected_state=("enable-oslogin=TRUE und enable-oslogin-2fa=TRUE in den Projekt-Metadaten"),
                            audit_evidence=(
                                "project.commonInstanceMetadata: enable-oslogin=TRUE, enable-oslogin-2fa=TRUE"
                            ),
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="OS Login 2FA nicht aktiviert",
                            description=(
                                f"Projekt {project_id} hat "
                                f"enable-oslogin={'aktiviert' if os_login == 'TRUE' else 'deaktiviert'} "
                                f"und enable-oslogin-2fa={'aktiviert' if os_login_2fa == 'TRUE' else 'deaktiviert'}. "
                                "Ohne OS Login 2FA fehlt die Multi-Faktor-"
                                "Authentifizierung für SSH-Zugriff auf VMs."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.5 Sichere Authentifizierung",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/metadata",
                            resource_type="gcp.compute.ProjectMetadata",
                            account_id=project_id,
                            current_state={
                                "enable-oslogin": os_login or "nicht gesetzt",
                                "enable-oslogin-2fa": os_login_2fa or "nicht gesetzt",
                            },
                            expected_state=("enable-oslogin=TRUE und enable-oslogin-2fa=TRUE in den Projekt-Metadaten"),
                            remediation=(
                                "Aktivieren Sie OS Login mit 2FA:\n"
                                "gcloud compute project-info add-metadata "
                                "--metadata enable-oslogin=TRUE,enable-oslogin-2fa=TRUE "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"project.commonInstanceMetadata: "
                                f"enable-oslogin={os_login or 'not set'}, "
                                f"enable-oslogin-2fa={os_login_2fa or 'not set'}"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecureLdap(BaseCheck):
    """Prüft ob sicherheitsbezogen benannte Cloud-Identity-Gruppen existieren."""

    check_id = "GCP-NR10-005"
    title = "Sicherheitsbezogen benannte Cloud-Identity-Gruppen"
    description = (
        "Prüft ob Cloud-Identity-Gruppen mit sicherheitsbezogener Benennung existieren "
        "(Schlüsselwortabgleich im Anzeigenamen)."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudidentity.groups.list"]
    pruefgrenzen = (
        "Heuristische Prüfung: erkennt nur, ob sicherheitsbezogen benannte Gruppen anhand "
        "eines Namensmusters existieren. Secure LDAP wird nicht geprüft — der Nachweis ist "
        "über die Attestierungs-Checkliste zu führen. Einrichtungen ohne Cloud Identity "
        "liefern kein Ergebnis (Nicht anwendbar)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("cloudidentity", "v1")
                result = service.groups().list(parent="customers/my_customer").execute()
                groups = result.get("groups", [])

                # Check if security-related groups exist
                security_groups = [
                    g
                    for g in groups
                    if any(
                        keyword in g.get("displayName", "").lower()
                        for keyword in ["security", "sicherheit", "admin", "mfa"]
                    )
                ]

                if security_groups:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Sicherheitsbezogen benannte Cloud-Identity-Gruppen vorhanden",
                            description=(
                                f"Projekt {project_id}: {len(security_groups)} von {len(groups)} "
                                f"Cloud-Identity-Gruppen haben einen Namen, der auf Sicherheitsfunktionen "
                                f"hindeutet; Konfiguration und Nutzung werden nicht geprüft."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/cloudidentity",
                            resource_type="gcp.cloudidentity.Group",
                            account_id=project_id,
                            current_state={
                                "total_groups": len(groups),
                                "security_groups": len(security_groups),
                            },
                            expected_state=(
                                "Mindestens eine sicherheitsbezogen benannte Cloud-Identity-Gruppe vorhanden"
                            ),
                            audit_evidence=(
                                f"groups.list() returned {len(groups)} groups, {len(security_groups)} security-related"
                            ),
                            iso27001_control="A.8.5 Sichere Authentifizierung, A.8.20 Netzwerksicherheit",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine sicherheitsbezogen benannten Cloud-Identity-Gruppen",
                            description=(
                                f"Projekt {project_id}: keine sicherheitsbezogen benannten Gruppen erkannt "
                                f"({len(groups)} Gruppen insgesamt). Anders benannte Sicherheitsstrukturen "
                                f"werden nicht erkannt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.5 Sichere Authentifizierung, A.8.20 Netzwerksicherheit",
                            severity=Severity.LOW,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/cloudidentity",
                            resource_type="gcp.cloudidentity.Group",
                            account_id=project_id,
                            current_state={
                                "total_groups": len(groups),
                                "security_groups": 0,
                            },
                            expected_state=(
                                "Mindestens eine sicherheitsbezogen benannte Cloud-Identity-Gruppe vorhanden"
                            ),
                            remediation=(
                                "Benennen Sie sicherheitsrelevante Gruppen konsistent, z. B. mit "
                                "'security', 'admin' oder 'mfa' im Anzeigenamen, um sie auffindbar zu machen."
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"groups.list() returned {len(groups)} groups, 0 security-related",
                        )
                    )
            except Exception as exc:
                error_msg = str(exc).lower()
                if (
                    "not enabled" in error_msg
                    or "403" in error_msg
                    or "permission" in error_msg
                    or "not found" in error_msg
                    # Real-API-verified 27.07.2026: a GCP-only project/organization
                    # with no associated Cloud Identity or Workspace customer makes
                    # "customers/my_customer" unresolvable, and the API answers with
                    # a bare "400 Request contains an invalid argument." — not a
                    # code defect (that parent literal is the documented value for
                    # "the caller's own Cloud Identity customer"), but an
                    # environment precondition this check cannot satisfy itself.
                    # Deliberately narrow (legal review 27.07.2026, Auflage 2):
                    # "invalid argument" alone would also swallow FUTURE real
                    # request-building defects as "nicht anwendbar" — require the
                    # cloudidentity endpoint in the error text (HttpError embeds
                    # the request URL) so only THIS documented situation matches.
                    or ("invalid argument" in error_msg and "cloudidentity.googleapis.com" in error_msg)
                ):
                    # Cloud Identity not accessible — not applicable for this setup, not a defect
                    errors.append(
                        CheckError(
                            message=(
                                # No edition/tier claim (legal review 27.07.2026,
                                # Auflage 1): the groups API works with Cloud
                                # Identity FREE as well — the precondition is a
                                # Cloud-Identity-/Workspace-Kunde existing at all,
                                # not a paid edition (the earlier "Premium" wording
                                # was already retired once in W4 batch 10).
                                f"Projekt {project_id}: Cloud Identity nicht zugänglich — für dieses Projekt/"
                                f"diese Organisation ist kein Cloud-Identity- oder Google-Workspace-Kunde "
                                f"auflösbar. Nicht anwendbar: {exc}"
                            ),
                            error_type=type(exc).__name__,
                        )
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
