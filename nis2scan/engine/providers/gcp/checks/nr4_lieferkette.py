"""§30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for GCP.

Checks Cross-Project IAM Bindings, Service Account Keys, GKE Workload Identity,
Binary Authorization, and VPC Service Controls for supply chain security.
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

# Domains of provider-managed service agents — never a foreign-project supply-chain
# relationship even though they end in "gserviceaccount.com".
_PROVIDER_MANAGED_SA_DOMAINS = {
    "developer.gserviceaccount.com",
    "appspot.gserviceaccount.com",
    "cloudservices.gserviceaccount.com",
}
_IAM_SA_DOMAIN_SUFFIX = ".iam.gserviceaccount.com"


def _is_foreign_project_service_account(member: str, project_ids: list[str]) -> bool:
    """Return True only for a serviceAccount member whose project is not in project_ids.

    Only genuine per-project service accounts (<project>.iam.gserviceaccount.com) are
    evaluated. Provider-managed service agents — the Compute Engine default SA
    (developer.gserviceaccount.com), the App Engine default SA
    (appspot.gserviceaccount.com), the Google APIs SA (cloudservices.gserviceaccount.com),
    and per-service "-system"/"-robot" agents (e.g. compute-system.iam.gserviceaccount.com,
    container-engine-robot.iam.gserviceaccount.com) are provider-managed, not a
    foreign-project relationship.
    """
    if not member.startswith("serviceAccount:"):
        return False
    email = member[len("serviceAccount:") :]
    if "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    if domain in _PROVIDER_MANAGED_SA_DOMAINS:
        return False
    if not domain.endswith(_IAM_SA_DOMAIN_SUFFIX):
        return False
    # Google-managed service agents: service-<project-number>@gcp-sa-<service>.iam...,
    # service-<nr>@compute-system.iam..., dataflow/serverless robots etc.
    if local.startswith("service-") and local.removeprefix("service-").isdigit():
        return False
    project_candidate = domain[: -len(_IAM_SA_DOMAIN_SUFFIX)]
    if project_candidate.startswith("gcp-sa-"):
        return False
    if project_candidate.endswith("-system") or project_candidate.endswith("-robot"):
        return False
    if project_candidate.endswith("-prod") and "robot" in project_candidate:
        return False
    return project_candidate not in project_ids


class CheckCrossProjectBindings(BaseCheck):
    """Prüft ob IAM-Bindungen projektfremde Service Accounts enthalten."""

    check_id = "GCP-NR4-001"
    title = "Projektfremde Service Accounts in IAM-Bindungen"
    description = "Prüft ob die IAM-Policy des Projekts Bindungen für projektfremde Service Accounts enthält."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["resourcemanager.projects.getIamPolicy"]
    pruefgrenzen = (
        "Prüft nur Service-Account-Mitglieder auf projektfremde Herkunft (Vergleich des "
        "E-Mail-Suffixes). Nutzer-, Gruppen- und Domain-Mitglieder sowie die "
        "Organisationszugehörigkeit werden nicht bewertet; ob ein externer Zugriff "
        "legitim ist (Dienstleister), ist organisatorisch zu bewerten."
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

                external_members: list[str] = []
                for binding in bindings:
                    for member in binding.get("members", []):
                        if _is_foreign_project_service_account(member, session.project_ids):
                            external_members.append(member)

                if not external_members:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Keine projektfremden IAM-Bindungen",
                            description=(
                                f"Die IAM-Policy von Projekt {project_id} enthält keine "
                                f"Bindungen für projektfremde Service Accounts."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudresourcemanager.Project",
                            account_id=project_id,
                            current_state={"external_bindings": 0},
                            expected_state=(
                                "Keine projektfremden IAM-Bindungen oder nur dokumentierte "
                                "und genehmigte Lieferantenzugriffe"
                            ),
                            audit_evidence="getIamPolicy() found 0 foreign-project service account member(s)",
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Projektfremde IAM-Bindungen gefunden",
                            description=(
                                f"Projekt {project_id} hat "
                                f"{len(external_members)} IAM-Bindung(en) für "
                                "projektfremde Service Accounts. Projektfremde Zugriffe erhöhen das "
                                "Risiko in der Lieferkette."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudresourcemanager.Project",
                            account_id=project_id,
                            current_state={
                                "external_bindings": len(external_members),
                                # Key suffix _email (ADR-0011 deny-list) so the EXTERN report
                                # profile pseudonymizes these member strings — they embed a
                                # service-account e-mail address (CODE-1). Deliberately
                                # SINGULAR: the deny-list regex requires the string to END
                                # with _email, so a "grammatical fix" to _emails would
                                # silently reopen the leak (legal-reviewer hint, 2026-07-24).
                                "external_member_email": [m for m in external_members[:5]],
                            },
                            expected_state=(
                                "Keine projektfremden IAM-Bindungen oder nur dokumentierte "
                                "und genehmigte Lieferantenzugriffe"
                            ),
                            remediation=(
                                "Überprüfen Sie projektfremde IAM-Bindungen: "
                                "gcloud projects get-iam-policy <PROJECT_ID> "
                                "--format=json | Entfernen Sie nicht autorisierte "
                                "projektfremde Zugriffe mit: gcloud projects "
                                "remove-iam-policy-binding <PROJECT_ID> "
                                "--member=<MEMBER> --role=<ROLE>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"getIamPolicy() found {len(external_members)} foreign-project "
                                f"service account member(s)"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckServiceAccountKeys(BaseCheck):
    """Prüft ob benutzerverwaltete Service-Account-Schlüssel existieren."""

    check_id = "GCP-NR4-002"
    title = "Benutzerverwaltete Service-Account-Schlüssel"
    description = (
        "Prüft ob Service Accounts benutzerverwaltete Schlüssel haben, "
        "die ein Sicherheitsrisiko in der Lieferkette darstellen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["iam.serviceAccountKeys.list", "iam.serviceAccounts.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz nutzerverwalteter Service-Account-Schlüssel. "
        "Schlüsselalter wird in GCP-NR9-002 geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("iam", "v1")
                sa_result = service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
                service_accounts = sa_result.get("accounts", [])

                for sa in service_accounts:
                    sa_email = sa.get("email", "unknown")
                    sa_name = sa.get("name", "")

                    keys_result = (
                        service.projects()
                        .serviceAccounts()
                        .keys()
                        .list(name=sa_name, keyTypes=["USER_MANAGED"])
                        .execute()
                    )
                    user_keys = keys_result.get("keys", [])

                    if not user_keys:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Keine benutzerverwalteten SA-Schlüssel",
                                description=(
                                    f"Service Account {sa_email} in Projekt {project_id} "
                                    f"hat keine benutzerverwalteten Schlüssel."
                                ),
                                region="global",
                                resource_id=f"projects/{project_id}/serviceAccounts/{sa_email}",
                                resource_type="gcp.iam.ServiceAccountKey",
                                account_id=project_id,
                                current_state={"user_managed_keys": 0},
                                expected_state=(
                                    "Keine benutzerverwalteten Schlüssel; stattdessen "
                                    "Workload Identity oder kurzlebige Tokens verwenden"
                                ),
                                audit_evidence=f"keys.list() found 0 USER_MANAGED keys for {sa_email}",
                                iso27001_control=(
                                    "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                                ),
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Benutzerverwaltete SA-Schlüssel gefunden",
                                description=(
                                    f"Service Account {sa_email} in "
                                    f"Projekt {project_id} hat "
                                    f"{len(user_keys)} benutzerverwaltete(n) Schlüssel. "
                                    "Benutzerverwaltete Schlüssel stellen ein erhöhtes "
                                    "Sicherheitsrisiko dar und sollten vermieden werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control=(
                                    "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen"
                                ),
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"projects/{project_id}/serviceAccounts/{sa_email}",
                                resource_type="gcp.iam.ServiceAccountKey",
                                account_id=project_id,
                                current_state={"user_managed_keys": len(user_keys)},
                                expected_state=(
                                    "Keine benutzerverwalteten Schlüssel; stattdessen "
                                    "Workload Identity oder kurzlebige Tokens verwenden"
                                ),
                                remediation=(
                                    "Löschen Sie benutzerverwaltete Schlüssel: "
                                    "gcloud iam service-accounts keys delete <KEY_ID> "
                                    "--iam-account=<SA_EMAIL> --project=<PROJECT_ID>. "
                                    "Verwenden Sie stattdessen Workload Identity Federation."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(
                                    f"keys.list() found {len(user_keys)} USER_MANAGED key(s) for {sa_email}"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckWorkloadIdentity(BaseCheck):
    """Prüft ob GKE-Cluster Workload Identity konfiguriert haben."""

    check_id = "GCP-NR4-003"
    title = "GKE Workload Identity konfiguriert"
    description = "Prüft ob GKE-Cluster Workload Identity für sichere Dienstkontozuordnung konfiguriert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["container.clusters.list"]
    pruefgrenzen = (
        "Prüft nur, ob GKE-Cluster Workload Identity aktiviert haben. "
        "Projekte ohne GKE liefern kein Ergebnis (Nicht anwendbar)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import container_v1

                client = container_v1.ClusterManagerClient(
                    credentials=session.credentials,
                )
                response = client.list_clusters(
                    request={"parent": f"projects/{project_id}/locations/-"},
                )
                clusters = response.clusters or []

                for cluster in clusters:
                    wi_config = cluster.workload_identity_config
                    if wi_config and wi_config.workload_pool:
                        findings.append(
                            compliant_finding(
                                self,
                                title="GKE-Cluster mit Workload Identity",
                                description=(
                                    f"GKE-Cluster {cluster.name} in Projekt {project_id} "
                                    f"hat Workload Identity konfiguriert."
                                ),
                                region=cluster.location or "global",
                                resource_id=f"projects/{project_id}/clusters/{cluster.name}",
                                resource_type="gcp.container.Cluster",
                                account_id=project_id,
                                current_state={"workload_identity_enabled": True},
                                expected_state="Workload Identity für den GKE-Cluster aktiviert",
                                audit_evidence=(f"list_clusters() cluster {cluster.name} workload_pool configured"),
                                iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="GKE-Cluster ohne Workload Identity",
                                description=(
                                    f"GKE-Cluster {cluster.name} in "
                                    f"Projekt {project_id} hat keine "
                                    "Workload Identity konfiguriert. Ohne Workload Identity greifen Pods "
                                    "auf die Identität des Node-Service-Accounts zu oder benötigen "
                                    "exportierte Service-Account-Schlüssel — beides erschwert eine "
                                    "feingranulare Zugriffskontrolle für Drittanbieter-Workloads."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region=cluster.location or "global",
                                resource_id=f"projects/{project_id}/clusters/{cluster.name}",
                                resource_type="gcp.container.Cluster",
                                account_id=project_id,
                                current_state={"workload_identity_enabled": False},
                                expected_state="Workload Identity für den GKE-Cluster aktiviert",
                                remediation=(
                                    "Aktivieren Sie Workload Identity: "
                                    "gcloud container clusters update <CLUSTER_NAME> "
                                    "--workload-pool=<PROJECT_ID>.svc.id.goog "
                                    "--zone=<ZONE> --project=<PROJECT_ID>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(
                                    f"list_clusters() cluster {cluster.name}: workload_pool not configured"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckBinaryAuthorization(BaseCheck):
    """Prüft ob Binary Authorization aktiviert ist."""

    check_id = "GCP-NR4-004"
    title = "Binary Authorization konfiguriert"
    description = (
        "Prüft ob Binary Authorization für die Überprüfung von Container-Images vor dem Deployment konfiguriert ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["binaryauthorization.policy.get"]
    pruefgrenzen = (
        "Prüft nur den evaluationMode der Default-Admission-Rule (ALWAYS_ALLOW gilt als "
        "Mangel). Cluster-spezifische Regeln, Attestor-Inhalte und Ausnahmen "
        "(exemptedImages) werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("binaryauthorization", "v1")
                # The API requires the "/policy" suffix on the resource name
                # (pattern "^projects/[^/]+/policy$") — real-API-verified 27.07.2026:
                # a bare "projects/<id>" raises a client-side TypeError for not
                # matching that pattern before the request is ever sent.
                policy = service.projects().getPolicy(name=f"projects/{project_id}/policy").execute()

                default_rule = policy.get("defaultAdmissionRule", {})
                evaluation_mode = default_rule.get("evaluationMode", "ALWAYS_ALLOW")

                if evaluation_mode != "ALWAYS_ALLOW":
                    findings.append(
                        compliant_finding(
                            self,
                            title="Binary Authorization aktiv",
                            description=(
                                f"Projekt {project_id} prüft Container-Images vor dem Deployment "
                                f"(evaluationMode={evaluation_mode})."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.binaryauthorization.Policy",
                            account_id=project_id,
                            current_state={"evaluation_mode": evaluation_mode},
                            expected_state=(
                                "Binary Authorization mit evaluationMode REQUIRE_ATTESTATION oder ALWAYS_DENY"
                            ),
                            audit_evidence=(f"getPolicy() defaultAdmissionRule.evaluationMode={evaluation_mode}"),
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Binary Authorization erlaubt alle Images",
                            description=(
                                f"Projekt {project_id} hat Binary "
                                "Authorization mit evaluationMode=ALWAYS_ALLOW "
                                "konfiguriert. Ohne Überprüfung können unsichere "
                                "Container-Images deployed werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.19 Informationssicherheit in Lieferantenbeziehungen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.binaryauthorization.Policy",
                            account_id=project_id,
                            current_state={"evaluation_mode": evaluation_mode},
                            expected_state=(
                                "Binary Authorization mit evaluationMode REQUIRE_ATTESTATION oder ALWAYS_DENY"
                            ),
                            remediation=(
                                "Konfigurieren Sie Binary Authorization: "
                                "gcloud container binauthz policy export > policy.yaml "
                                "# Ändern Sie evaluationMode auf REQUIRE_ATTESTATION "
                                "gcloud container binauthz policy import policy.yaml "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=f"getPolicy() defaultAdmissionRule.evaluationMode={evaluation_mode}",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckVpcServiceControlsSupplyChain(BaseCheck):
    """Prüft ob VPC Service Controls gegen Datenexfiltration in der Lieferkette konfiguriert sind."""

    check_id = "GCP-NR4-005"
    title = "VPC Service Controls für Lieferkettensicherheit"
    description = (
        "Prüft ob VPC Service Controls konfiguriert sind, um "
        "Datenexfiltration durch Drittanbieter-Zugriffe zu verhindern."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["accesscontextmanager.accessPolicies.list", "accesscontextmanager.servicePerimeters.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von VPC-Service-Controls-Perimetern (wie GCP-NR9-008, "
        "hier unter Lieferketten-Blickwinkel). Erfordert Organisations-Berechtigung. "
        "Ob ein gefundener Perimeter das gescannte Projekt einschließt, wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

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
                project_id = session.project_id
                findings.append(
                    compliant_finding(
                        self,
                        title="VPC Service Controls für Lieferkettensicherheit aktiv",
                        description=(
                            "Mindestens ein VPC Service Controls Perimeter ist in der Organisation konfiguriert."
                        ),
                        region="global",
                        resource_id=f"projects/{project_id}",
                        resource_type="gcp.accesscontextmanager.ServicePerimeter",
                        account_id=project_id,
                        current_state={"vpc_sc_perimeters_found": True},
                        expected_state=(
                            "VPC Service Controls Perimeter zum Schutz vor Datenexfiltration durch Drittanbieter"
                        ),
                        audit_evidence="accessPolicies.servicePerimeters.list() returned >=1 perimeter",
                        iso27001_control="A.5.19, A.8.22 Netzwerksegmentierung",
                    )
                )
            else:
                project_id = session.project_id
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Keine VPC Service Controls für Lieferkettensicherheit",
                        description=(
                            f"Projekt {project_id} hat keine "
                            "VPC Service Controls Perimeter. Ohne VPC SC können "
                            "Lieferanten mit Projektzugriff Daten aus GCP-Diensten "
                            "exfiltrieren."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.19, A.8.22 Netzwerksegmentierung",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.GCP,
                        region="global",
                        resource_id=f"projects/{project_id}",
                        resource_type="gcp.accesscontextmanager.ServicePerimeter",
                        account_id=project_id,
                        current_state={"vpc_sc_perimeters": 0},
                        expected_state=(
                            "VPC Service Controls Perimeter zum Schutz vor Datenexfiltration durch Drittanbieter"
                        ),
                        remediation=(
                            "Erstellen Sie einen VPC Service Controls Perimeter: "
                            "gcloud access-context-manager perimeters create <NAME> "
                            "--title='Lieferkettenperimeter' "
                            "--resources=projects/<PROJECT_NUMBER> "
                            "--restricted-services='storage.googleapis.com,"
                            "bigquery.googleapis.com' "
                            "--policy=<POLICY_ID>"
                        ),
                        remediation_effort="HIGH",
                        audit_evidence="accessPolicies.servicePerimeters.list() returned 0 perimeters",
                    )
                )
        except Exception as exc:
            logger.warning(
                "VPC Service Controls supply chain check skipped",
                error=str(exc),
                hint="VPC SC requires organization-level access",
            )
            errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
