"""§30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for GCP.

Checks Container Analysis, OS Config Patch Management, Web Security Scanner,
Artifact Registry Scanning, and GKE Node Versions.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 5
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und "
    "Wartung von informationstechnischen Systemen, Komponenten und Prozessen, "
    "einschließlich Management und Offenlegung von Schwachstellen"
)


class CheckContainerAnalysis(BaseCheck):
    """Prüft ob Container Analysis / Artifact Analysis aktiviert ist."""

    check_id = "GCP-NR5-001"
    title = "Container Analysis aktiviert"
    description = (
        "Prüft ob Container Analysis (Artifact Analysis) für die "
        "automatische Schwachstellenerkennung in Container-Images aktiviert ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["containeranalysis.occurrences.list"]
    pruefgrenzen = (
        "Prüft nur, ob durchgeführte Image-Scans (DISCOVERY-Occurrences) belegt sind. "
        "Ob die API formal aktiviert ist, sowie Scan-Ergebnisse und deren Behebung "
        "werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("containeranalysis", "v1")
                # DISCOVERY occurrences record that an image scan was performed —
                # unlike VULNERABILITY occurrences, they exist regardless of whether
                # any vulnerability was actually found, so they are the correct
                # evidence for "scanning is active" (B-Nr.5-14).
                result = (
                    service.projects()
                    .occurrences()
                    .list(
                        parent=f"projects/{project_id}",
                        filter='kind="DISCOVERY"',
                        pageSize=1,
                    )
                    .execute()
                )
                occurrences = result.get("occurrences", [])

                if occurrences:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Container Analysis aktiv",
                            description=(
                                f"Projekt {project_id} hat DISCOVERY-Occurrences in Container "
                                f"Analysis — durchgeführte Image-Scans sind belegt, unabhängig "
                                f"davon, ob dabei Schwachstellen gefunden wurden."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.containeranalysis.Occurrence",
                            account_id=project_id,
                            current_state={"discovery_occurrences_found": True},
                            expected_state=(
                                "Container Analysis aktiviert mit automatischem Schwachstellenscan für Container-Images"
                            ),
                            audit_evidence=(
                                "occurrences.list(kind=DISCOVERY) returned >=1 result — "
                                "DISCOVERY occurrences belegen durchgeführte Image-Scans"
                            ),
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Container Analysis nicht aktiv",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "DISCOVERY-Occurrences in Container Analysis. "
                                "Entweder ist die API nicht aktiviert oder es werden "
                                "keine Container-Images gescannt. Sofern das Projekt keine "
                                "Container-Images verwendet, ist dieser Befund gegenstandslos."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.containeranalysis.Occurrence",
                            account_id=project_id,
                            current_state={"discovery_occurrences": 0},
                            expected_state=(
                                "Container Analysis aktiviert mit automatischem Schwachstellenscan für Container-Images"
                            ),
                            remediation=(
                                "Aktivieren Sie die Container Analysis API: "
                                "gcloud services enable containeranalysis.googleapis.com "
                                "--project=<PROJECT_ID>. "
                                "Aktivieren Sie automatisches Scanning in Artifact Registry."
                            ),
                            remediation_effort="LOW",
                            audit_evidence="occurrences.list(kind=DISCOVERY) returned 0 results",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOsConfigPatchManagement(BaseCheck):
    """Prüft ob OS Config Patch-Deployments konfiguriert sind."""

    check_id = "GCP-NR5-002"
    title = "OS Config Patch-Management konfiguriert"
    description = (
        "Prüft ob OS Config Patch-Deployments für die automatische Aktualisierung von VM-Instanzen konfiguriert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["osconfig.patchDeployments.list"]
    pruefgrenzen = (
        "Prüft nur, ob OS-Config-Patch-Deployments existieren. Ob Patches "
        "tatsächlich zeitnah installiert werden, wird nicht verifiziert."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("osconfig", "v1")
                result = service.projects().patchDeployments().list(parent=f"projects/{project_id}").execute()
                deployments = result.get("patchDeployments", [])

                if deployments:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Automatisches Patch-Management konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(deployments)} OS Config "
                                f"Patch-Deployment(s) für die automatische VM-Aktualisierung."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.osconfig.PatchDeployment",
                            account_id=project_id,
                            current_state={"patch_deployments": len(deployments)},
                            expected_state=(
                                "Mindestens ein Patch-Deployment für die regelmäßige Aktualisierung von VMs"
                            ),
                            audit_evidence=f"patchDeployments.list() returned {len(deployments)} deployment(s)",
                            iso27001_control=(
                                "A.8.8 Management technischer Schwachstellen, A.8.9 Konfigurationsmanagement"
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein automatisches Patch-Management",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "OS Config Patch-Deployments. Ohne automatisches "
                                "Patch-Management bleiben Schwachstellen in "
                                "VM-Betriebssystemen unbehoben. Sofern das Projekt keine "
                                "Compute-Engine-VM-Instanzen betreibt, ist dieser Befund "
                                "gegenstandslos."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control=(
                                "A.8.8 Management technischer Schwachstellen, A.8.9 Konfigurationsmanagement"
                            ),
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.osconfig.PatchDeployment",
                            account_id=project_id,
                            current_state={"patch_deployments": 0},
                            expected_state=(
                                "Mindestens ein Patch-Deployment für die regelmäßige Aktualisierung von VMs"
                            ),
                            remediation=(
                                "Erstellen Sie ein Patch-Deployment: "
                                "gcloud compute os-config patch-deployments create "
                                "<NAME> --project=<PROJECT_ID> "
                                "--instance-filter-all "
                                "--recurring-schedule-frequency=weekly "
                                "--recurring-schedule-day-of-week=SUNDAY "
                                "--recurring-schedule-time-of-day='02:00'"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="patchDeployments.list() returned 0 deployments",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckWebSecurityScanner(BaseCheck):
    """Prüft ob Web Security Scanner Konfigurationen existieren."""

    check_id = "GCP-NR5-003"
    title = "Web Security Scanner konfiguriert"
    description = (
        "Prüft ob Web Security Scanner für die automatische Schwachstellenerkennung in Webanwendungen konfiguriert ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["websecurityscanner.scanconfigs.list"]
    pruefgrenzen = (
        "Prüft nur, ob Web-Security-Scanner-Konfigurationen existieren. Nur für "
        "App-Engine-/Compute-Web-Workloads relevant; Scan-Ergebnisse werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("websecurityscanner", "v1")
                result = service.projects().scanConfigs().list(parent=f"projects/{project_id}").execute()
                scan_configs = result.get("scanConfigs", [])

                if scan_configs:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Web Security Scanner konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(scan_configs)} Web Security "
                                f"Scanner Konfiguration(en) für Webanwendungs-Scans."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.websecurityscanner.ScanConfig",
                            account_id=project_id,
                            current_state={"scan_configs": len(scan_configs)},
                            expected_state=("Mindestens eine Web Security Scanner Konfiguration für Webanwendungen"),
                            audit_evidence=f"scanConfigs.list() returned {len(scan_configs)} config(s)",
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Web Security Scanner konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Web Security Scanner Konfigurationen. Ohne "
                                "automatisches Scanning werden Schwachstellen "
                                "in Webanwendungen nicht erkannt. Sofern das Projekt keine "
                                "über App Engine oder Compute Engine bereitgestellten "
                                "Webanwendungen betreibt, ist dieser Befund nicht anwendbar."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                            severity=Severity.LOW,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.websecurityscanner.ScanConfig",
                            account_id=project_id,
                            current_state={"scan_configs": 0},
                            expected_state=("Mindestens eine Web Security Scanner Konfiguration für Webanwendungen"),
                            remediation=(
                                "Erstellen Sie eine Scan-Konfiguration: "
                                "gcloud alpha web-security-scanner scan-configs "
                                "create --display-name='Webapp Scan' "
                                "--starting-urls='https://app.example.com' "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="scanConfigs.list() returned 0 configs",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckArtifactRegistryScanning(BaseCheck):
    """Prüft ob Artifact Registry Repositories für die zentrale Artefaktverwaltung existieren."""

    check_id = "GCP-NR5-004"
    title = "Artifact Registry Repositories vorhanden"
    description = "Prüft ob Artifact Registry Repositories für die zentrale Verwaltung von Artefakten vorhanden sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["artifactregistry.repositories.list"]
    pruefgrenzen = (
        "Prüft nur die Nutzung von Artifact Registry (statt veralteter Container "
        "Registry). Die Sicherheit der abgelegten Artefakte wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("artifactregistry", "v1")
                # Unlike Compute Engine, Artifact Registry does not support the "-"
                # aggregation wildcard for locations (real-API-verified 27.07.2026:
                # the server rejects it with 400 "Invalid project name"). Locations
                # must be enumerated explicitly and queried one at a time.
                location_ids: list[str] = []
                page_token = ""
                while True:
                    loc_request: dict[str, Any] = {"name": f"projects/{project_id}"}
                    if page_token:
                        loc_request["pageToken"] = page_token
                    loc_response = service.projects().locations().list(**loc_request).execute()
                    location_ids.extend(loc.get("locationId", "") for loc in loc_response.get("locations", []))
                    page_token = loc_response.get("nextPageToken", "")
                    if not page_token:
                        break

                # One location's failure must not discard evidence already
                # gathered from the other ~45 locations (ADR-0016 fail-safe) —
                # each location gets its own CheckError instead of aborting the
                # whole per-project iteration.
                repositories: list[dict[str, Any]] = []
                for location_id in location_ids:
                    if not location_id:
                        continue
                    try:
                        repo_page_token = ""
                        while True:
                            repo_request: dict[str, Any] = {
                                "parent": f"projects/{project_id}/locations/{location_id}",
                            }
                            if repo_page_token:
                                repo_request["pageToken"] = repo_page_token
                            repo_response = service.projects().locations().repositories().list(**repo_request).execute()
                            repositories.extend(repo_response.get("repositories", []))
                            repo_page_token = repo_response.get("nextPageToken", "")
                            if not repo_page_token:
                                break
                    except Exception as loc_exc:
                        errors.append(
                            CheckError(
                                message=(
                                    f"Projekt {project_id}, Location {location_id}: "
                                    f"Artifact-Registry-Repositories nicht abrufbar: {loc_exc}"
                                ),
                                error_type=type(loc_exc).__name__,
                                region=location_id,
                            )
                        )

                if repositories:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Artifact Registry Repositories vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(repositories)} Artifact Registry "
                                f"Repository/Repositories für zentrale Artefaktverwaltung."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.artifactregistry.Repository",
                            account_id=project_id,
                            current_state={"repositories": len(repositories)},
                            expected_state=(
                                "Mindestens ein Artifact Registry Repository für die zentrale Artefaktverwaltung"
                            ),
                            audit_evidence=f"repositories.list() returned {len(repositories)} repositories",
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Artifact Registry Repositories",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Artifact Registry Repositories. Ohne zentrale "
                                "Artefaktverwaltung fehlt die Kontrolle über "
                                "verwendete Container-Images und Pakete. Sofern das Projekt "
                                "keine Container-Images oder Pakete verwendet, ist dieser "
                                "Befund gegenstandslos."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.8 Management technischer Schwachstellen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.artifactregistry.Repository",
                            account_id=project_id,
                            current_state={"repositories": 0},
                            expected_state=(
                                "Mindestens ein Artifact Registry Repository für die zentrale Artefaktverwaltung"
                            ),
                            remediation=(
                                "Erstellen Sie ein Artifact Registry Repository: "
                                "gcloud artifacts repositories create <NAME> "
                                "--repository-format=docker "
                                "--location=europe-west3 "
                                "--project=<PROJECT_ID>. "
                                "Aktivieren Sie Container Analysis für automatisches Scanning."
                            ),
                            remediation_effort="LOW",
                            audit_evidence="repositories.list() returned 0 repositories",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


def _parse_gke_version(version: str) -> tuple[int, int, int]:
    """Parse a GKE version string ("X.Y.Z-gke.N") into a comparable integer tuple.

    The "-gke.N" (or any other) suffix is ignored. Raises ValueError if the
    numeric prefix is not exactly three dot-separated integers — string
    comparison of raw version strings is lexicographic and silently wrong
    (e.g. "1.28.9" > "1.28.15"), so callers must not fall back to it.
    """
    numeric_part = version.split("-", 1)[0]
    parts = numeric_part.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"Unexpected GKE version format: {version!r}")
    major, minor, patch = (int(p) for p in parts)
    return (major, minor, patch)


class CheckGkeNodeVersions(BaseCheck):
    """Prüft ob GKE-Cluster und Nodes aktuelle Versionen verwenden."""

    check_id = "GCP-NR5-005"
    title = "GKE Node-Versionen aktuell"
    description = (
        "Prüft ob GKE-Cluster Node-Versionen verwenden, die nicht älter "
        "als die Master-Version sind, um bekannte Schwachstellen zu vermeiden."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["container.clusters.list"]
    pruefgrenzen = (
        "Prüft GKE-Node-Versionen gegen die Master-Version. Projekte ohne GKE liefern kein "
        "Ergebnis (Nicht anwendbar). Cluster ohne gemeldete Master-/Node-Version werden "
        "nicht bewertet."
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
                    master_version = cluster.current_master_version or ""
                    node_version = cluster.current_node_version or ""

                    if not master_version or not node_version:
                        continue  # No Prüfobjekt without both reported versions

                    try:
                        master_tuple = _parse_gke_version(master_version)
                        node_tuple = _parse_gke_version(node_version)
                    except ValueError as e:
                        errors.append(
                            CheckError(
                                message=(
                                    f"GKE-Cluster {cluster.name} in Projekt {project_id}: "
                                    f"Version nicht auswertbar (master={master_version!r}, "
                                    f"node={node_version!r}): {e}"
                                ),
                                error_type=type(e).__name__,
                            )
                        )
                        continue

                    if node_tuple >= master_tuple:
                        findings.append(
                            compliant_finding(
                                self,
                                title="GKE Node-Version aktuell",
                                description=(
                                    f"GKE-Cluster {cluster.name} in Projekt {project_id} "
                                    f"hat eine aktuelle Node-Version ({node_version})."
                                ),
                                region=cluster.location or "global",
                                resource_id=f"projects/{project_id}/clusters/{cluster.name}",
                                resource_type="gcp.container.Cluster",
                                account_id=project_id,
                                current_state={
                                    "master_version": master_version,
                                    "node_version": node_version,
                                },
                                expected_state=("Node-Version entspricht mindestens der Master-Version des Clusters"),
                                audit_evidence=(
                                    f"list_clusters() cluster {cluster.name}"
                                    f" master={master_version} node={node_version}"
                                ),
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="GKE Node-Version veraltet",
                                description=(
                                    f"GKE-Cluster {cluster.name} in "
                                    f"Projekt {project_id} hat eine "
                                    f"Node-Version die älter als die Master-Version ist. "
                                    "Veraltete Node-Versionen können bekannte "
                                    "Schwachstellen enthalten."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.8 Management technischer Schwachstellen",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region=cluster.location or "global",
                                resource_id=f"projects/{project_id}/clusters/{cluster.name}",
                                resource_type="gcp.container.Cluster",
                                account_id=project_id,
                                current_state={
                                    "master_version": master_version,
                                    "node_version": node_version,
                                },
                                expected_state=("Node-Version entspricht mindestens der Master-Version des Clusters"),
                                remediation=(
                                    "Aktualisieren Sie die Node-Version: "
                                    "gcloud container clusters upgrade "
                                    "<CLUSTER_NAME> --node-pool=default-pool "
                                    "--cluster-version=<MASTER_VERSION> "
                                    "--zone=<ZONE> --project=<PROJECT_ID>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(
                                    f"list_clusters() cluster {cluster.name}"
                                    f" master={master_version} node={node_version}"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
