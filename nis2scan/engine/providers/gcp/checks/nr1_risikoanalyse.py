"""§30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for GCP.

Checks Security Command Center, Organization Policies, Audit Logging,
and Cloud Asset Inventory.
"""

from typing import Any

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

BSIG_30_NR = 1
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
)


class CheckSecurityCommandCenter(BaseCheck):
    """Prüft ob Security Command Center in GCP-Projekten aktiviert ist."""

    check_id = "GCP-NR1-001"
    title = "Security Command Center aktiviert"
    description = (
        "Prüft ob das Google Cloud Security Command Center (SCC) aktiviert ist "
        "und Sicherheitsquellen konfiguriert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["securitycenter.sources.list"]
    pruefgrenzen = (
        "Prüft nur, ob das Security Command Center per API zugänglich ist. "
        "Aktivierte Tier-Stufe (Standard/Premium) und Bearbeitung der Befunde "
        "werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import securitycenter_v1

                client = securitycenter_v1.SecurityCenterClient(
                    credentials=session.credentials,
                )
                sources = list(
                    client.list_sources(
                        request={"parent": f"projects/{project_id}"},
                    )
                )

                if sources:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Security Command Center aktiviert",
                            description=(
                                f"Projekt {project_id} hat {len(sources)} SCC-Quelle(n) — "
                                f"zentrale Sicherheitsbewertung ist aktiv."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.securitycenter.Source",
                            account_id=project_id,
                            current_state={"scc_sources": len(sources)},
                            expected_state="Security Command Center mit mindestens einer aktiven Quelle",
                            audit_evidence=f"list_sources() returned {len(sources)} source(s)",
                            iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Security Command Center nicht aktiviert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "SCC-Quellen konfiguriert. Ohne SCC fehlt die "
                                "zentrale Sicherheitsbewertung und Bedrohungserkennung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.1 Informationssicherheitsrichtlinien",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.securitycenter.Source",
                            account_id=project_id,
                            current_state={"scc_sources": 0},
                            expected_state="Security Command Center mit mindestens einer aktiven Quelle",
                            remediation=(
                                "Aktivieren Sie das Security Command Center: "
                                "gcloud scc settings update --project=<PROJECT_ID> "
                                "--enable-scc"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="list_sources() returned 0 sources",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckOrgPolicies(BaseCheck):
    """Prüft ob Organisationsrichtlinien für das Projekt definiert sind."""

    check_id = "GCP-NR1-002"
    title = "Organisationsrichtlinien vorhanden"
    description = "Prüft ob GCP Organization Policies für die Durchsetzung von Sicherheitsstandards konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["orgpolicy.policy.get"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Organisationsrichtlinien. Inhalt und Angemessenheit werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("orgpolicy", "v2")
                result = service.projects().policies().list(parent=f"projects/{project_id}").execute()
                policies = result.get("policies", [])

                if policies:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Organisationsrichtlinien vorhanden",
                            description=(
                                f"Projekt {project_id} hat {len(policies)} Organization "
                                f"Policies zur Durchsetzung von Sicherheitsstandards."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={"organization_policies": len(policies)},
                            expected_state="Mindestens eine Organisationsrichtlinie konfiguriert",
                            audit_evidence=f"policies.list() returned {len(policies)} policies",
                            iso27001_control="A.5.1, A.5.2 Informationssicherheitsrichtlinien",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Organisationsrichtlinien definiert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Organization Policies. Ohne Richtlinien werden "
                                "Sicherheitsstandards nicht automatisch durchgesetzt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.1, A.5.2 Informationssicherheitsrichtlinien",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={"organization_policies": 0},
                            expected_state="Mindestens eine Organisationsrichtlinie konfiguriert",
                            remediation=(
                                "Erstellen Sie Organization Policies: "
                                "gcloud org-policies set-policy policy.yaml "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="policies.list() returned 0 policies",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckAuditLogConfig(BaseCheck):
    """Prüft ob Audit-Logging für alle Dienste (allServices) im Projekt konfiguriert ist."""

    check_id = "GCP-NR1-003"
    title = "Audit-Logging konfiguriert"
    description = (
        "Prüft ob Cloud Audit Logs für alle Dienste (allServices) in der IAM-Policy des Projekts aktiviert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["resourcemanager.projects.getIamPolicy"]
    pruefgrenzen = (
        "Prüft nur, ob in der IAM-Policy ein Audit-Log-Eintrag mit service=allServices vorhanden ist. "
        "Loginhalte, Aufbewahrungsfristen und Auswertung der Logs werden nicht geprüft."
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
                audit_configs = policy.get("auditConfigs", [])
                has_all_services = any(ac.get("service") == "allServices" for ac in audit_configs)

                if has_all_services:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Audit-Logging konfiguriert",
                            description=(
                                f"Projekt {project_id} hat unter {len(audit_configs)} "
                                f"Audit-Log-Konfiguration(en) in der IAM-Policy einen Eintrag für allServices."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudresourcemanager.Project",
                            account_id=project_id,
                            current_state={"audit_configs": len(audit_configs), "has_all_services": True},
                            expected_state="Audit-Log-Konfiguration mit allServices vorhanden",
                            audit_evidence=(
                                f"getIamPolicy() returned {len(audit_configs)} auditConfigs, "
                                "including one with service=allServices"
                            ),
                            iso27001_control="A.8.15 Logging",
                        )
                    )
                elif audit_configs:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Audit-Logs nicht für alle Dienste konfiguriert",
                            description=(
                                f"Im Projekt '{project_id}' sind Audit-Log-Konfigurationen nur für einzelne "
                                "Dienste hinterlegt, nicht für alle Dienste (allServices)."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.15 Logging",
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudresourcemanager.Project",
                            account_id=project_id,
                            current_state={"audit_configs": len(audit_configs), "has_all_services": False},
                            expected_state="Audit-Log-Konfiguration mit allServices vorhanden",
                            remediation=(
                                "Aktivieren Sie Data Access Audit Logs für allServices: "
                                "gcloud projects set-iam-policy <PROJECT_ID> "
                                "policy.json (mit auditConfigs für allServices)"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"getIamPolicy() returned {len(audit_configs)} auditConfigs, "
                                "none with service=allServices"
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Audit-Logging nicht konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Audit-Log-Konfiguration in der IAM-Policy. "
                                "Ohne Audit-Logs fehlt der vollständige Prüfpfad."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.15 Logging",
                            severity=Severity.CRITICAL,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudresourcemanager.Project",
                            account_id=project_id,
                            current_state={"audit_configs": 0, "has_all_services": False},
                            expected_state="Audit-Log-Konfiguration mit allServices vorhanden",
                            remediation=(
                                "Aktivieren Sie Data Access Audit Logs: "
                                "gcloud projects set-iam-policy <PROJECT_ID> "
                                "policy.json (mit auditConfigs für allServices)"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="getIamPolicy() returned no auditConfigs",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckAssetInventory(BaseCheck):
    """Prüft ob Cloud Asset Inventory Feeds konfiguriert sind."""

    check_id = "GCP-NR1-004"
    title = "Cloud Asset Inventory Feeds konfiguriert"
    description = (
        "Prüft ob Cloud Asset Inventory Feeds für die kontinuierliche "
        "Überwachung von Ressourcenänderungen eingerichtet sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudasset.feeds.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Asset-Inventory-Feeds. Ob die Feeds in eine "
        "Risikoanalyse einfließen, ist organisatorisch nachzuweisen."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import asset_v1

                client = asset_v1.AssetServiceClient(
                    credentials=session.credentials,
                )
                # Unlike most List* RPCs in this SDK, ListFeeds is not paginated —
                # it returns a single ListFeedsResponse with a `feeds` field, not an
                # iterable page iterator (real-API-verified 27.07.2026: iterating the
                # response object directly raises "'ListFeedsResponse' object is not
                # iterable").
                feeds = list(
                    client.list_feeds(
                        request={"parent": f"projects/{project_id}"},
                    ).feeds
                )

                if feeds:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Cloud Asset Inventory Feeds konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(feeds)} Asset Inventory Feed(s) — "
                                f"Ressourcenänderungen werden kontinuierlich überwacht."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudasset.Feed",
                            account_id=project_id,
                            current_state={"asset_feeds": len(feeds)},
                            expected_state="Mindestens ein Asset Inventory Feed konfiguriert",
                            audit_evidence=f"list_feeds() returned {len(feeds)} feed(s)",
                            iso27001_control="A.8.9 Konfigurationsmanagement",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Cloud Asset Inventory Feeds",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Asset Inventory Feeds. Ohne Feeds werden "
                                "Ressourcenänderungen nicht automatisch überwacht."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.9 Konfigurationsmanagement",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.cloudasset.Feed",
                            account_id=project_id,
                            current_state={"asset_feeds": 0},
                            expected_state="Mindestens ein Asset Inventory Feed konfiguriert",
                            remediation=(
                                "Erstellen Sie einen Asset Inventory Feed: "
                                "gcloud asset feeds create <FEED_ID> "
                                "--project=<PROJECT_ID> "
                                "--asset-types='compute.googleapis.com/Instance' "
                                "--pubsub-topic=projects/<PROJECT_ID>/topics/<TOPIC>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="list_feeds() returned 0 feeds",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
