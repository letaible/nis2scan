"""§30 Abs. 2 Nr. 9 — Zugriffskontrolle und Anlagenmanagement checks for GCP.

Checks IAM Least Privilege, Service Account Hygiene, Identity-Aware Proxy,
VPC Firewall Rules, Storage Bucket Public Access, Org Constraints,
Inactive Principals, and VPC Service Controls.
"""

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

OVERLY_BROAD_ROLES = ["roles/owner", "roles/editor"]
MAX_SA_KEY_AGE_DAYS = 90
IMPORTANT_ORG_CONSTRAINTS = [
    "iam.allowedPolicyMemberDomains",
    "compute.restrictSharedVpcSubnetworks",
    "compute.disableSerialPortAccess",
    "iam.disableServiceAccountKeyCreation",
    "compute.requireOsLogin",
]


class CheckIamLeastPrivilege(BaseCheck):
    """Prüft ob übermäßig breite IAM-Rollen auf Projektebene vergeben sind."""

    check_id = "GCP-NR9-001"
    title = "IAM Least-Privilege-Prinzip"
    description = "Prüft ob auf Projektebene übermäßig breite Rollen wie roles/owner oder roles/editor vergeben sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["resourcemanager.projects.getIamPolicy"]
    pruefgrenzen = (
        "Prüft nur roles/owner und roles/editor auf Projektebene. Zu breite "
        "benutzerdefinierte Rollen und Ordner-/Organisationsebene werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("cloudresourcemanager", "v1")
                policy = (
                    service.projects()
                    .getIamPolicy(
                        resource=project_id,
                        body={"options": {"requestedPolicyVersion": 3}},
                    )
                    .execute()
                )
                bindings = policy.get("bindings", [])

                broad_bindings = [b for b in bindings if b.get("role", "") in OVERLY_BROAD_ROLES]
                if not broad_bindings:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine übermäßig breiten IAM-Rollen",
                            description=(
                                f"Projekt {project_id} vergibt weder roles/owner noch "
                                f"roles/editor auf Projektebene ({len(bindings)} Binding(s) geprüft)."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/iam",
                            resource_type="gcp.iam.Binding",
                            account_id=project_id,
                            current_state={
                                "bindings_checked": len(bindings),
                                "broad_role_bindings": 0,
                            },
                            expected_state=(
                                "Verwendung spezifischer, eingeschränkter Rollen "
                                "anstelle von roles/owner oder roles/editor"
                            ),
                            audit_evidence=(
                                f"getIamPolicy() returned {len(bindings)} bindings, "
                                f"none with {', '.join(OVERLY_BROAD_ROLES)}"
                            ),
                            iso27001_control="A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung",
                        )
                    )

                for binding in broad_bindings:
                    role = binding.get("role", "")
                    if role in OVERLY_BROAD_ROLES:
                        member_count = len(binding.get("members", []))
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Übermäßig breite IAM-Rolle vergeben",
                                description=(
                                    f"Projekt {project_id} hat "
                                    f"{member_count} Mitglieder mit der Rolle "
                                    f"'{role}'. Diese Rolle gewährt umfassende "
                                    "Berechtigungen und verstößt gegen das "
                                    "Least-Privilege-Prinzip."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"projects/{project_id}/iam",
                                resource_type="gcp.iam.Binding",
                                account_id=project_id,
                                current_state={
                                    "role": role,
                                    "member_count": member_count,
                                },
                                expected_state=(
                                    "Verwendung spezifischer, eingeschränkter Rollen "
                                    "anstelle von roles/owner oder roles/editor"
                                ),
                                remediation=(
                                    "Ersetzen Sie breite Rollen durch spezifische Rollen:\n"
                                    "gcloud projects remove-iam-policy-binding <PROJECT_ID> "
                                    "--member=<MEMBER> --role=<BROAD_ROLE>\n"
                                    "gcloud projects add-iam-policy-binding <PROJECT_ID> "
                                    "--member=<MEMBER> --role=<SPECIFIC_ROLE>\n"
                                    "Nutzen Sie den IAM Recommender für Empfehlungen."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(f"getIamPolicy() binding: role={role}, members={member_count}"),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckServiceAccountHygiene(BaseCheck):
    """Prüft ob Service-Account-Schlüssel älter als 90 Tage sind."""

    check_id = "GCP-NR9-002"
    title = "Service-Account-Schlüsselhygiene"
    description = "Prüft ob Service-Account-Schlüssel regelmäßig rotiert werden und nicht älter als 90 Tage sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["iam.serviceAccounts.list", "iam.serviceAccountKeys.list"]
    pruefgrenzen = (
        "Prüft nur das Alter nutzerverwalteter Service-Account-Schlüssel. "
        "Google-verwaltete Schlüssel rotieren automatisch und sind nicht Gegenstand."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("iam", "v1")
                sa_result = service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
                service_accounts = sa_result.get("accounts", [])
                now = datetime.now(UTC)

                for sa in service_accounts:
                    sa_email = sa.get("email", "")
                    sa_name = sa.get("name", "")

                    keys_result = (
                        service.projects()
                        .serviceAccounts()
                        .keys()
                        .list(name=sa_name, keyTypes="USER_MANAGED")
                        .execute()
                    )
                    keys = keys_result.get("keys", [])

                    if not keys:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Service-Account ohne nutzerverwaltete Schlüssel",
                                description=(
                                    f"Service-Account {sa_email} in Projekt {project_id} hat "
                                    f"keine nutzerverwalteten Schlüssel — es besteht kein "
                                    f"Rotationsrisiko."
                                ),
                                region="global",
                                resource_id=f"serviceAccounts/{sa_email}",
                                resource_type="gcp.iam.ServiceAccount",
                                account_id=project_id,
                                current_state={"user_managed_keys": 0},
                                expected_state=(
                                    f"Keine oder regelmäßig rotierte Service-Account-Schlüssel "
                                    f"(maximal {MAX_SA_KEY_AGE_DAYS} Tage alt)"
                                ),
                                audit_evidence="keys.list(keyTypes=USER_MANAGED) returned 0 keys",
                                iso27001_control="A.5.15 Zugriffskontrolle",
                            )
                        )
                        continue

                    for key in keys:
                        valid_after = key.get("validAfterTime", "")
                        if not valid_after:
                            continue

                        try:
                            key_created = datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            continue

                        age_days = (now - key_created).days
                        if age_days <= MAX_SA_KEY_AGE_DAYS:
                            key_id = key.get("name", "")
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Service-Account-Schlüssel aktuell",
                                    description=(
                                        f"Service-Account {sa_email} in Projekt {project_id} hat "
                                        f"einen Schlüssel, der {age_days} Tage alt ist "
                                        f"(Grenzwert: {MAX_SA_KEY_AGE_DAYS} Tage)."
                                    ),
                                    region="global",
                                    resource_id=f"serviceAccounts/{sa_email}/keys/{key_id}",
                                    resource_type="gcp.iam.ServiceAccountKey",
                                    account_id=project_id,
                                    current_state={
                                        "key_age_days": age_days,
                                        "max_allowed_days": MAX_SA_KEY_AGE_DAYS,
                                    },
                                    expected_state=(
                                        f"Service-Account-Schlüssel nicht älter als {MAX_SA_KEY_AGE_DAYS} Tage"
                                    ),
                                    audit_evidence=(
                                        f"key.validAfterTime={valid_after}, age={age_days}d, max={MAX_SA_KEY_AGE_DAYS}d"
                                    ),
                                    iso27001_control="A.5.15 Zugriffskontrolle",
                                )
                            )
                        elif age_days > MAX_SA_KEY_AGE_DAYS:
                            sa_id = sa_email
                            key_id = key.get("name", "")
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="Service-Account-Schlüssel zu alt",
                                    description=(
                                        f"Service-Account {sa_id} in Projekt "
                                        f"{project_id} hat einen "
                                        f"Schlüssel ({key_id}), der {age_days} Tage "
                                        f"alt ist (Grenzwert: {MAX_SA_KEY_AGE_DAYS} Tage)."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.5.15 Zugriffskontrolle",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.GCP,
                                    region="global",
                                    resource_id=f"serviceAccounts/{sa_id}/keys/{key_id}",
                                    resource_type="gcp.iam.ServiceAccountKey",
                                    account_id=project_id,
                                    current_state={
                                        "key_age_days": age_days,
                                        "max_allowed_days": MAX_SA_KEY_AGE_DAYS,
                                    },
                                    expected_state=(
                                        f"Service-Account-Schlüssel nicht älter als {MAX_SA_KEY_AGE_DAYS} Tage"
                                    ),
                                    remediation=(
                                        "Rotieren Sie den Service-Account-Schlüssel:\n"
                                        "1. gcloud iam service-accounts keys create "
                                        "new-key.json --iam-account=<SA_EMAIL>\n"
                                        "2. Aktualisieren Sie die Anwendung mit dem neuen Schlüssel\n"
                                        "3. gcloud iam service-accounts keys delete <KEY_ID> "
                                        "--iam-account=<SA_EMAIL>\n"
                                        "Empfehlung: Verwenden Sie Workload Identity Federation "
                                        "anstelle von Schlüsseln."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=(
                                        f"key.validAfterTime={valid_after}, age={age_days}d, max={MAX_SA_KEY_AGE_DAYS}d"
                                    ),
                                )
                            )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckIdentityAwareProxy(BaseCheck):
    """Prüft ob Identity-Aware Proxy (IAP) aktiviert ist."""

    check_id = "GCP-NR9-003"
    title = "Identity-Aware Proxy konfiguriert"
    description = (
        "Prüft ob Identity-Aware Proxy (IAP) für das Projekt "
        "konfiguriert ist, um kontextabhängige Zugriffskontrolle zu ermöglichen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["iap.tunnelInstances.getIamPolicy"]
    pruefgrenzen = (
        "Prüft nur IAP-Tunnelrichtlinien auf Existenz von IAM-Bindungen und auf "
        "öffentliche Mitglieder (allUsers/allAuthenticatedUsers). Die inhaltliche "
        "Wirksamkeit der Zugriffskontrolle wird nicht bewertet. Andere "
        "Zero-Trust-Zugriffslösungen werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("iap", "v1")
                result = (
                    service.projects()
                    .iap_tunnel()
                    .getIamPolicy(
                        resource=f"projects/{project_id}/iap_tunnel",
                        body={},
                    )
                    .execute()
                )
                bindings = result.get("bindings", [])

                public_members: set[str] = set()
                for binding in bindings:
                    for member in binding.get("members", []):
                        if member in ("allUsers", "allAuthenticatedUsers"):
                            public_members.add(member)

                if public_members:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="IAP-Zugriff öffentlich freigegeben",
                            description=(
                                f"Projekt {project_id} hat eine IAP-Tunnelrichtlinie mit dem "
                                f"öffentlichen Mitglied {', '.join(sorted(public_members))}. IAP ist "
                                f"damit faktisch für alle offen."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/iap_tunnel",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={
                                "iap_bindings": len(bindings),
                                "public_members": sorted(public_members),
                            },
                            expected_state="Keine IAP-Bindungen für allUsers oder allAuthenticatedUsers",
                            remediation=(
                                "Entfernen Sie die öffentliche IAP-Bindung:\n"
                                "gcloud iap tunnel instances remove-iam-policy-binding "
                                "--project=<PROJECT_ID> "
                                f"--member={sorted(public_members)[0]} "
                                "--role=roles/iap.tunnelResourceAccessor"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"iap_tunnel.getIamPolicy() bindings include public member(s): {sorted(public_members)}"
                            ),
                        )
                    )
                elif bindings:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Identity-Aware Proxy konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(bindings)} IAM-Bindung(en) für IAP "
                                f"vorhanden, keine davon für allUsers oder allAuthenticatedUsers."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/iap_tunnel",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_bindings": len(bindings)},
                            expected_state="IAM-Bindungen für IAP vorhanden, ohne öffentliche Mitglieder",
                            audit_evidence=(
                                f"iap_tunnel.getIamPolicy() returned {len(bindings)} bindings, none public"
                            ),
                            iso27001_control="A.5.15 Zugriffskontrolle",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Identity-Aware Proxy nicht konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "IAP-Tunnelrichtlinien konfiguriert. Ohne IAP "
                                "fehlt die kontextabhängige Zugriffskontrolle "
                                "für administrative Zugriffe."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/iap_tunnel",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_bindings": 0},
                            expected_state=(
                                "IAP-Tunnelrichtlinien konfiguriert für kontextabhängige Zugriffskontrolle"
                            ),
                            remediation=(
                                "Konfigurieren Sie Identity-Aware Proxy:\n"
                                "gcloud iap tunnel instances add-iam-policy-binding "
                                "--project=<PROJECT_ID> "
                                "--member=user:<EMAIL> "
                                "--role=roles/iap.tunnelResourceAccessor"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="iap_tunnel.getIamPolicy() returned 0 bindings",
                        )
                    )
            except Exception as exc:
                error_msg = str(exc).lower()
                # Only explicit deactivation signals count as "not enabled";
                # a bare 403/permission error is an unknown state -> CheckError
                # (same classification as GCP-NR6-002/-003 and GCP-NR9-007).
                if "not enabled" in error_msg or "accessnotconfigured" in error_msg:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Identity-Aware Proxy nicht aktiviert",
                            description=(f"Projekt {project_id} hat die IAP-API nicht aktiviert."),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/iap",
                            resource_type="gcp.iap.TunnelInstance",
                            account_id=project_id,
                            current_state={"iap_enabled": False},
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
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpcFirewallRules(BaseCheck):
    """Prüft ob Firewallregeln zu permissive sind."""

    check_id = "GCP-NR9-004"
    title = "VPC-Firewallregeln restriktiv"
    description = "Prüft ob VPC-Firewallregeln den SSH- oder RDP-Zugriff von 0.0.0.0/0 erlauben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.firewalls.list"]
    pruefgrenzen = (
        "Prüft Ingress-Firewallregeln auf offenes SSH/RDP von 0.0.0.0/0. Nur aktive "
        "Allow-Regeln werden bewertet; deaktivierte Regeln (disabled) und "
        "Deny-Regeln werden übersprungen. Effektive Erreichbarkeit (Routing, "
        "Ziel-Tags) wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import FirewallsClient

                client = FirewallsClient(credentials=session.credentials)
                firewalls = client.list(
                    request={"project": project_id},
                )

                for fw in firewalls:
                    # Only check ALLOW rules
                    if fw.direction != "INGRESS":
                        continue
                    if getattr(fw, "disabled", False):
                        continue
                    if not (fw.allowed or []):
                        # Deny-only rule — out of scope, only ALLOW rules are evaluated
                        continue

                    source_ranges = list(fw.source_ranges) if fw.source_ranges else []
                    open_to_world = "0.0.0.0/0" in source_ranges

                    # Check if rule allows SSH (22) or RDP (3389)
                    sensitive_ports = set()
                    if open_to_world:
                        for allowed in fw.allowed or []:
                            for port in allowed.ports or []:
                                if port == "22" or port == "3389":
                                    sensitive_ports.add(port)
                                elif "-" in port:
                                    parts = port.split("-")
                                    try:
                                        low, high = int(parts[0]), int(parts[1])
                                        if low <= 22 <= high:
                                            sensitive_ports.add("22")
                                        if low <= 3389 <= high:
                                            sensitive_ports.add("3389")
                                    except (ValueError, IndexError):
                                        pass

                    if not open_to_world or not sensitive_ports:
                        fw_id = fw.name or ""
                        findings.append(
                            compliant_finding(
                                self,
                                title="Firewallregel ohne offenen SSH/RDP-Zugriff",
                                description=(
                                    f"Firewallregel {fw_id} in Projekt {project_id} erlaubt "
                                    f"keinen SSH- oder RDP-Zugriff von 0.0.0.0/0."
                                ),
                                region="global",
                                resource_id=f"firewalls/{fw_id}",
                                resource_type="gcp.compute.Firewall",
                                account_id=project_id,
                                current_state={
                                    "open_to_world": open_to_world,
                                    "exposed_sensitive_ports": [],
                                },
                                expected_state=(
                                    "SSH- und RDP-Zugriff nur von vertrauenswürdigen IP-Bereichen oder über IAP-Tunnel"
                                ),
                                audit_evidence=(
                                    f"firewall ingress rule: 0.0.0.0/0={open_to_world}, no SSH/RDP ports exposed"
                                ),
                                iso27001_control="A.8.20 Netzwerksicherheit, A.8.22 Netzwerksegmentierung",
                            )
                        )
                    else:
                        fw_id = fw.name or ""
                        port_names = {
                            "22": "SSH",
                            "3389": "RDP",
                        }
                        exposed = ", ".join(f"{port_names.get(p, p)} (Port {p})" for p in sorted(sensitive_ports))
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Firewallregel erlaubt offenen Zugriff",
                                description=(
                                    f"Firewallregel {fw_id} in Projekt "
                                    f"{project_id} erlaubt {exposed} "
                                    "von 0.0.0.0/0. Dies exponiert administrative "
                                    "Zugangspunkte dem gesamten Internet."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.20 Netzwerksicherheit, A.8.22 Netzwerksegmentierung",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"firewalls/{fw_id}",
                                resource_type="gcp.compute.Firewall",
                                account_id=project_id,
                                current_state={
                                    "source_ranges": ["0.0.0.0/0"],
                                    "exposed_ports": sorted(sensitive_ports),
                                },
                                expected_state=(
                                    "SSH- und RDP-Zugriff nur von vertrauenswürdigen IP-Bereichen oder über IAP-Tunnel"
                                ),
                                remediation=(
                                    "Schränken Sie die Firewallregel ein:\n"
                                    "gcloud compute firewall-rules update <RULE_NAME> "
                                    "--source-ranges=<TRUSTED_IP_RANGE> "
                                    "--project=<PROJECT_ID>\n"
                                    "Oder verwenden Sie IAP für SSH/RDP-Zugriff:\n"
                                    "gcloud compute ssh <INSTANCE> --tunnel-through-iap"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"firewall.source_ranges=['0.0.0.0/0'], exposed_ports={sorted(sensitive_ports)}"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckStorageBucketPublicAccess(BaseCheck):
    """Prüft ob Storage-Buckets öffentlich zugänglich sind."""

    check_id = "GCP-NR9-005"
    title = "Storage-Buckets nicht öffentlich zugänglich"
    description = (
        "Prüft ob Cloud Storage Buckets IAM-Richtlinien haben, "
        "die allUsers oder allAuthenticatedUsers Zugriff gewähren."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["storage.buckets.list", "storage.buckets.getIamPolicy"]
    pruefgrenzen = (
        "Prüft Bucket-IAM auf allUsers/allAuthenticatedUsers. Buckets, deren "
        "IAM-Policy nicht lesbar ist, werden als Fehler erfasst und liefern "
        "keinen Positivnachweis. Objekt-ACLs (bei deaktiviertem Uniform "
        "Bucket-Level Access) werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import storage  # type: ignore[attr-defined]

                client = storage.Client(
                    credentials=session.credentials,
                    project=project_id,
                )
                buckets = list(client.list_buckets())

                for bucket in buckets:
                    try:
                        policy = bucket.get_iam_policy()
                    except Exception as exc:
                        # ADR-0016: an unreadable bucket policy is an unknown state, not
                        # a silent skip — record it so the gap is visible in the report,
                        # and never fabricate a compliant finding for this bucket.
                        errors.append(
                            CheckError(
                                message=(
                                    f"IAM-Policy für Bucket {bucket.name} in Projekt {project_id} nicht abrufbar: {exc}"
                                ),
                                error_type=type(exc).__name__,
                                region=bucket.location or "global",
                            )
                        )
                        continue

                    public_members = set()
                    for binding in policy.bindings:
                        for member in binding.get("members", []):
                            if member in ("allUsers", "allAuthenticatedUsers"):
                                public_members.add(member)

                    if not public_members:
                        bucket_id = bucket.name
                        findings.append(
                            compliant_finding(
                                self,
                                title="Storage-Bucket nicht öffentlich zugänglich",
                                description=(
                                    f"Bucket {bucket_id} in Projekt {project_id} gewährt "
                                    f"weder allUsers noch allAuthenticatedUsers Zugriff."
                                ),
                                region=bucket.location or "global",
                                resource_id=f"buckets/{bucket_id}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={"public_members": []},
                                expected_state=(
                                    "Keine öffentlichen Zugriffsberechtigungen "
                                    "(weder allUsers noch allAuthenticatedUsers)"
                                ),
                                audit_evidence="bucket.get_iam_policy() contains no public members",
                                iso27001_control="A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung",
                            )
                        )
                    else:
                        bucket_id = bucket.name
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Öffentlich zugänglicher Storage-Bucket",
                                description=(
                                    f"Bucket {bucket_id} in Projekt "
                                    f"{project_id} ist öffentlich "
                                    f"zugänglich über {', '.join(public_members)}. "
                                    "Öffentliche Buckets können zu Datenverlust führen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung",
                                severity=Severity.CRITICAL,
                                provider=CloudProvider.GCP,
                                region=bucket.location or "global",
                                resource_id=f"buckets/{bucket_id}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={
                                    "public_members": sorted(public_members),
                                },
                                expected_state=(
                                    "Keine öffentlichen Zugriffsberechtigungen "
                                    "(weder allUsers noch allAuthenticatedUsers)"
                                ),
                                remediation=(
                                    "Entfernen Sie den öffentlichen Zugriff:\n"
                                    "gcloud storage buckets remove-iam-policy-binding "
                                    "gs://<BUCKET_NAME> --member=allUsers "
                                    "--role=<ROLE>\n"
                                    "Aktivieren Sie den Public Access Prevention:\n"
                                    "gcloud storage buckets update gs://<BUCKET_NAME> "
                                    "--public-access-prevention=enforced"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"bucket.get_iam_policy() contains public members: {sorted(public_members)}"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOrgConstraints(BaseCheck):
    """Prüft ob wichtige organisationsweite Einschränkungen definiert sind."""

    check_id = "GCP-NR9-006"
    title = "Organisationsweite Zugriffskontroll-Einschränkungen"
    description = (
        "Prüft ob wichtige Org Policy Constraints für die Zugriffskontrolle "
        "wie iam.allowedPolicyMemberDomains und "
        "compute.disableSerialPortAccess konfiguriert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["orgpolicy.policies.list"]
    pruefgrenzen = (
        "Prüft die Projekt-Policies gegen eine feste Liste von Zugriffskontroll-"
        "Constraints. Organisationsebene kann unerkannt bleiben (vgl. GCP-NR7-001)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("orgpolicy", "v2")
                result = service.projects().policies().list(parent=f"projects/{project_id}").execute()
                policies = result.get("policies", [])

                # Extract constraint names from policies that are actually enforced.
                # IMPORTANT_ORG_CONSTRAINTS mixes boolean constraints (enforced via
                # rules[].enforce) and LIST constraints (iam.allowedPolicyMemberDomains,
                # compute.restrictSharedVpcSubnetworks — enforced via rules[].values /
                # denyAll, never via enforce). allowAll neutralises a list constraint
                # (equivalent to the default / overriding inherited restrictions) and
                # therefore does NOT count as enforcement.
                active_constraints = set()
                for policy in policies:
                    constraint_name = policy.get("name", "").split("/")[-1]
                    rules = policy.get("spec", {}).get("rules", [])
                    if any(rule.get("enforce") is True or "values" in rule or rule.get("denyAll") for rule in rules):
                        active_constraints.add(constraint_name)

                # Exact match, not substring (B-9-12)
                found_constraints = [c for c in IMPORTANT_ORG_CONSTRAINTS if c in active_constraints]

                if found_constraints:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Organisationsweite Zugriffskontroll-Einschränkungen aktiv",
                            description=(
                                f"Projekt {project_id} erzwingt {len(found_constraints)} "
                                f"empfohlene Org Policy Constraint(s) für die Zugriffskontrolle: "
                                f"{', '.join(found_constraints)}."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/orgpolicies",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={
                                "total_policies": len(policies),
                                "access_control_constraints_found": len(found_constraints),
                            },
                            expected_state=(
                                "Organisationsweite Constraints wie "
                                "iam.allowedPolicyMemberDomains und "
                                "compute.disableSerialPortAccess konfiguriert"
                            ),
                            audit_evidence=(
                                f"policies.list() returned {len(policies)} policies, "
                                f"{len(found_constraints)} matching access control constraints"
                            ),
                            iso27001_control="A.5.15 Zugriffskontrolle",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine organisationsweiten Zugriffskontroll-Einschränkungen",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "der empfohlenen Org Policy Constraints für die "
                                "Zugriffskontrolle konfiguriert."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/orgpolicies",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={
                                "total_policies": len(policies),
                                "access_control_constraints_found": 0,
                                "expected_constraints": IMPORTANT_ORG_CONSTRAINTS,
                            },
                            expected_state=(
                                "Organisationsweite Constraints wie "
                                "iam.allowedPolicyMemberDomains und "
                                "compute.disableSerialPortAccess konfiguriert"
                            ),
                            remediation=(
                                "Setzen Sie Zugriffskontroll-Org Policies:\n"
                                "gcloud org-policies set-policy policy.yaml "
                                "--project=<PROJECT_ID>\n"
                                "Geprüfte Constraints:\n"
                                "- constraints/iam.allowedPolicyMemberDomains\n"
                                "- constraints/compute.restrictSharedVpcSubnetworks\n"
                                "- constraints/compute.disableSerialPortAccess\n"
                                "- constraints/iam.disableServiceAccountKeyCreation\n"
                                "- constraints/compute.requireOsLogin"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"policies.list() returned {len(policies)} policies, "
                                "none matching access control constraints"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckInactivePrincipals(BaseCheck):
    """Prüft ob inaktive IAM-Principals via Recommender identifiziert werden."""

    check_id = "GCP-NR9-007"
    title = "Inaktive IAM-Principals"
    description = (
        "Prüft über den IAM Recommender, ob inaktive Principals mit "
        "ungenutzten Zugriffsberechtigungen identifiziert wurden."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["recommender.iamPolicyRecommendations.list"]
    pruefgrenzen = (
        "Stützt sich auf den IAM Recommender von Google. Ist die Recommender-API "
        "nicht aktiviert (accessNotConfigured), liefert der Check kein Ergebnis "
        "(Nicht anwendbar) — inaktive Principals sind dann manuell zu prüfen. "
        "Fehlende Berechtigungen (403/PERMISSION_DENIED) werden als Fehler gemeldet. "
        "Bewertet nur, was der Recommender als ungenutzt erkennt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("recommender", "v1")
                result = (
                    service.projects()
                    .locations()
                    .recommenders()
                    .recommendations()
                    .list(
                        parent=(f"projects/{project_id}/locations/-/recommenders/google.iam.policy.Recommender"),
                    )
                    .execute()
                )
                recommendations = result.get("recommendations", [])

                # Filter for recommendations about removing unused access
                inactive_recs = [
                    r
                    for r in recommendations
                    if "REMOVE" in r.get("recommenderSubtype", "").upper()
                    or "unused" in r.get("description", "").lower()
                ]

                if not inactive_recs:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine inaktiven IAM-Principals",
                            description=(
                                f"Der IAM Recommender meldet für Projekt {project_id} keine "
                                f"Empfehlungen zum Entfernen ungenutzter Zugriffsberechtigungen."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/iam-recommender",
                            resource_type="gcp.recommender.Recommendation",
                            account_id=project_id,
                            current_state={
                                "total_recommendations": len(recommendations),
                                "unused_access_recommendations": 0,
                            },
                            expected_state=("Keine ungenutzten Zugriffsberechtigungen für inaktive Principals"),
                            audit_evidence=(
                                f"IAM Recommender returned {len(recommendations)} recommendations, "
                                f"none about unused access"
                            ),
                            iso27001_control="A.5.15 Zugriffskontrolle, A.5.18 Zugriffsrechte",
                        )
                    )

                for rec in inactive_recs:
                    rec_id = rec.get("name", "")
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Inaktiver IAM-Principal mit ungenutztem Zugriff",
                            description=(
                                f"Projekt {project_id} hat eine "
                                f"Recommender-Empfehlung ({rec_id}) zum Entfernen "
                                "ungenutzter Zugriffsberechtigungen. Inaktive "
                                "Principals erhöhen die Angriffsfläche."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.15 Zugriffskontrolle, A.5.18 Zugriffsrechte",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"recommendations/{rec_id}",
                            resource_type="gcp.recommender.Recommendation",
                            account_id=project_id,
                            current_state={
                                "recommendation_subtype": rec.get("recommenderSubtype", ""),
                                "priority": rec.get("priority", ""),
                            },
                            expected_state=("Keine ungenutzten Zugriffsberechtigungen für inaktive Principals"),
                            remediation=(
                                "Überprüfen und entfernen Sie ungenutzte Berechtigungen:\n"
                                "gcloud recommender recommendations list "
                                "--recommender=google.iam.policy.Recommender "
                                "--project=<PROJECT_ID> --location=-\n"
                                "gcloud recommender recommendations mark-claimed "
                                "<RECOMMENDATION_ID> --recommender=google.iam.policy.Recommender "
                                "--project=<PROJECT_ID> --location=<LOCATION>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"IAM Recommender found recommendation: subtype={rec.get('recommenderSubtype', '')}"
                            ),
                        )
                    )
            except Exception as exc:
                error_msg = str(exc).lower()
                if "not enabled" in error_msg or "accessnotconfigured" in error_msg:
                    logger.info(
                        "recommender.not_accessible",
                        project=project_id,
                    )
                else:
                    errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpcServiceControls(BaseCheck):
    """Prüft ob VPC Service Controls Perimeter konfiguriert sind."""

    check_id = "GCP-NR9-008"
    title = "VPC Service Controls Perimeter vorhanden"
    description = (
        "Prüft ob VPC Service Controls konfiguriert sind, um den Zugriff "
        "auf GCP-Dienste einzuschränken und Datenexfiltration zu verhindern."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["accesscontextmanager.accessPolicies.list", "accesscontextmanager.servicePerimeters.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von VPC-Service-Controls-Perimetern. Ohne "
        "Organisations-Berechtigung ist die Prüfung nicht möglich; die "
        "Perimeter-Konfiguration selbst wird nicht inhaltlich bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        # Access Context Manager is organization-scoped: one query covers the whole
        # scan (same pattern as GCP-NR4-005) — no per-project iteration, or the same
        # org-level state would be reported once per project.
        project_id = session.project_id
        try:
            service = session.service("accesscontextmanager", "v1")
            result = service.accessPolicies().list().execute()
            policies = result.get("accessPolicies", [])

            has_perimeters = False
            for policy in policies:
                policy_name = policy.get("name", "")
                perimeters_result = service.accessPolicies().servicePerimeters().list(parent=policy_name).execute()
                perimeters = perimeters_result.get("servicePerimeters", [])
                if perimeters:
                    has_perimeters = True
                    break

            if has_perimeters:
                findings.append(
                    compliant_finding(
                        self,
                        title="VPC Service Controls Perimeter vorhanden",
                        description=(
                            "Es ist mindestens ein VPC Service Controls Perimeter konfiguriert — "
                            "Datenexfiltration aus GCP-Diensten wird eingeschränkt."
                        ),
                        region="global",
                        resource_id=f"projects/{project_id}",
                        resource_type="gcp.accesscontextmanager.ServicePerimeter",
                        account_id=project_id,
                        current_state={"vpc_sc_perimeters_found": True},
                        expected_state="Mindestens ein VPC Service Controls Perimeter konfiguriert",
                        audit_evidence="accessPolicies.servicePerimeters.list() returned >=1 perimeter",
                        iso27001_control="A.8.22 Netzwerksegmentierung",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine VPC Service Controls Perimeter",
                        description=(
                            f"Projekt {project_id} hat keine "
                            "VPC Service Controls Perimeter. Ohne VPC Service Controls fehlt eine "
                            "zusätzliche Barriere gegen Datenexfiltration über Dienst-APIs."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.22 Netzwerksegmentierung",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.GCP,
                        region="global",
                        resource_id=f"projects/{project_id}",
                        resource_type="gcp.accesscontextmanager.ServicePerimeter",
                        account_id=project_id,
                        current_state={"vpc_sc_perimeters": 0},
                        expected_state="Mindestens ein VPC Service Controls Perimeter konfiguriert",
                        remediation=(
                            "Erstellen Sie einen VPC Service Controls Perimeter: "
                            "gcloud access-context-manager perimeters create <NAME> "
                            "--title='Produktionsperimeter' "
                            "--resources=projects/<PROJECT_NUMBER> "
                            "--restricted-services='storage.googleapis.com' "
                            "--policy=<POLICY_ID>"
                        ),
                        remediation_effort="HIGH",
                        audit_evidence="accessPolicies.servicePerimeters.list() returned 0 perimeters",
                    )
                )
        except Exception as exc:
            # VPC SC is org-level; may fail for project-only accounts
            logger.warning(
                "VPC Service Controls check skipped",
                error=str(exc),
                hint="VPC SC requires organization-level access",
            )
            errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
