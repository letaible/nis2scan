"""§30 Abs. 2 Nr. 8 — Kryptografie und Verschlüsselung checks for GCP.

Checks KMS Key Rotation, CMEK Encryption, SSL Policies, Cloud SQL SSL,
Disk Encryption, and Certificate Manager.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 8
BSIG_30_TEXT = "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"

MAX_ROTATION_DAYS = 365
MAX_ROTATION_SECONDS = MAX_ROTATION_DAYS * 24 * 3600


class CheckKmsKeyRotation(BaseCheck):
    """Prüft ob KMS-Schlüssel regelmäßig rotiert werden."""

    check_id = "GCP-NR8-001"
    title = "KMS-Schlüsselrotation"
    description = "Prüft ob Cloud KMS-Schlüssel eine Rotationsperiode von maximal 365 Tagen haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudkms.cryptoKeys.list", "cloudkms.keyRings.list"]
    pruefgrenzen = (
        "Prüft nur symmetrische KMS-Schlüssel (ENCRYPT_DECRYPT) auf Rotation. "
        "Asymmetrische Schlüssel und importiertes Material rotieren anders und "
        "werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import kms_v1

                client = kms_v1.KeyManagementServiceClient(
                    credentials=session.credentials,
                )
                # Cloud KMS does not support the "-" aggregation wildcard for
                # locations (real-API-verified 27.07.2026: the server rejects it
                # with NotFound "The request concerns location '-' but was sent to
                # location 'global'"). Locations must be enumerated explicitly via
                # the Locations mixin (list_locations does not auto-paginate — it
                # returns a raw ListLocationsResponse, unlike list_key_rings below).
                location_ids: list[str] = []
                page_token = ""
                while True:
                    loc_request: dict[str, Any] = {"name": f"projects/{project_id}"}
                    if page_token:
                        loc_request["page_token"] = page_token
                    loc_response = client.list_locations(request=loc_request)
                    location_ids.extend(location.location_id for location in loc_response.locations)
                    page_token = loc_response.next_page_token
                    if not page_token:
                        break

                # List all key rings across all locations. One location's failure
                # must not discard evidence already gathered from the other ~70
                # locations (ADR-0016 fail-safe) — each location gets its own
                # CheckError instead of aborting the whole per-project iteration.
                key_rings: list[Any] = []
                for location_id in location_ids:
                    try:
                        key_rings.extend(
                            client.list_key_rings(
                                request={"parent": f"projects/{project_id}/locations/{location_id}"},
                            )
                        )
                    except Exception as loc_exc:
                        errors.append(
                            CheckError(
                                message=(
                                    f"Projekt {project_id}, Location {location_id}: "
                                    f"KMS-Key-Rings nicht abrufbar: {loc_exc}"
                                ),
                                error_type=type(loc_exc).__name__,
                                region=location_id,
                            )
                        )

                for key_ring in key_rings:
                    crypto_keys = list(
                        client.list_crypto_keys(
                            request={"parent": key_ring.name},
                        )
                    )

                    for key in crypto_keys:
                        # Only check ENCRYPT_DECRYPT keys (symmetric)
                        if key.purpose != kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT:
                            continue

                        rotation_period = key.rotation_period
                        has_rotation = rotation_period and rotation_period.total_seconds() > 0
                        rotation_days: int | None = (
                            int(rotation_period.total_seconds() / 86400) if has_rotation else None
                        )

                        if has_rotation and rotation_period.total_seconds() <= MAX_ROTATION_SECONDS:
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="KMS-Schlüssel mit Rotation",
                                    description=(
                                        f"KMS-Schlüssel {key.name} hat eine Rotationsperiode von "
                                        f"{rotation_days} Tagen (Maximum: {MAX_ROTATION_DAYS})."
                                    ),
                                    region="global",
                                    resource_id=f"keys/{key.name}",
                                    resource_type="gcp.cloudkms.CryptoKey",
                                    account_id=project_id,
                                    current_state={
                                        "rotation_period_days": rotation_days,
                                        "has_rotation": True,
                                        # Full KMS path incl. key ring (ADR-0011): the
                                        # key ring segment is a customer-chosen,
                                        # identifying name not covered by resource_id's
                                        # tail (which is only the key name).
                                        "kms_key_name": key.name,
                                    },
                                    expected_state=f"Rotationsperiode von maximal {MAX_ROTATION_DAYS} Tagen",
                                    audit_evidence=(
                                        f"CryptoKey rotation_period={rotation_days}d, max_allowed={MAX_ROTATION_DAYS}d"
                                    ),
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        elif not has_rotation or rotation_period.total_seconds() > MAX_ROTATION_SECONDS:
                            key_id = key.name
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="KMS-Schlüssel ohne ausreichende Rotation",
                                    description=(
                                        f"KMS-Schlüssel {key_id} in Projekt "
                                        f"{project_id} hat keine "
                                        f"Rotationsperiode oder sie überschreitet "
                                        f"{MAX_ROTATION_DAYS} Tage."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.GCP,
                                    region="global",
                                    resource_id=f"keys/{key_id}",
                                    resource_type="gcp.cloudkms.CryptoKey",
                                    account_id=project_id,
                                    current_state={
                                        "rotation_period_days": rotation_days,
                                        "has_rotation": has_rotation,
                                        # Same rationale as the compliant branch above:
                                        # the key ring name in the path is not covered
                                        # by any other collected identifier.
                                        "kms_key_name": key_id,
                                    },
                                    expected_state=(f"Rotationsperiode von maximal {MAX_ROTATION_DAYS} Tagen"),
                                    remediation=(
                                        "Setzen Sie eine Rotationsperiode von höchstens 365 Tagen "
                                        "(empfohlen: 90 Tage): gcloud kms keys update <KEY_NAME> "
                                        "--keyring=<KEYRING> --location=<LOCATION> "
                                        "--rotation-period=90d --next-rotation-time=<ISO-ZEITPUNKT>"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=(
                                        f"CryptoKey rotation_period={rotation_days}d, max_allowed={MAX_ROTATION_DAYS}d"
                                    ),
                                )
                            )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCmekEncryption(BaseCheck):
    """Prüft ob Compute-Disks CMEK-Verschlüsselung verwenden."""

    check_id = "GCP-NR8-002"
    title = "CMEK-Verschlüsselung für Compute-Disks"
    description = (
        "Prüft ob Persistent Disks Customer-Managed Encryption Keys (CMEK) "
        "verwenden anstatt der Standard-Google-verwalteten Schlüssel."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.disks.list"]
    pruefgrenzen = (
        "Prüft nur, ob Compute-Disks CMEK nutzen. Fehlendes CMEK ist eine "
        "Härtungsempfehlung — die GCP-Standardverschlüsselung ist immer aktiv."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import DisksClient

                client = DisksClient(credentials=session.credentials)
                disks_by_zone = client.aggregated_list(
                    request={"project": project_id},
                )

                for zone, scoped_list in disks_by_zone:
                    if not scoped_list.disks:
                        continue
                    for disk in scoped_list.disks:
                        has_cmek = disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name
                        if has_cmek:
                            disk_id = disk.name or disk.self_link or ""
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Disk mit CMEK-Verschlüsselung",
                                    description=(
                                        f"Disk {disk_id} in Projekt {project_id} verwendet einen "
                                        f"Customer-Managed Encryption Key."
                                    ),
                                    region=zone if zone else "global",
                                    resource_id=f"disks/{disk_id}",
                                    resource_type="gcp.compute.Disk",
                                    account_id=project_id,
                                    current_state={"encryption": "cmek", "cmek": True},
                                    expected_state=("Disk mit Customer-Managed Encryption Key (CMEK) verschlüsselt"),
                                    audit_evidence="disk.disk_encryption_key.kms_key_name is set",
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        elif disk.disk_encryption_key and getattr(disk.disk_encryption_key, "sha256", None):
                            # Customer-supplied encryption key (CSEK) — the disk is
                            # explicitly encrypted with a caller-provided key, distinct
                            # from both CMEK and Google-managed defaults (B-Nr.8-12).
                            disk_id = disk.name or disk.self_link or ""
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Disk mit kundengeliefertem Verschlüsselungsschlüssel (CSEK)",
                                    description=(
                                        f"Disk {disk_id} in Projekt {project_id} verwendet einen "
                                        f"kundengelieferten Verschlüsselungsschlüssel (CSEK)."
                                    ),
                                    region=zone if zone else "global",
                                    resource_id=f"disks/{disk_id}",
                                    resource_type="gcp.compute.Disk",
                                    account_id=project_id,
                                    current_state={"encryption": "csek", "cmek": False},
                                    expected_state=("Disk mit Customer-Managed Encryption Key (CMEK) verschlüsselt"),
                                    audit_evidence="disk.disk_encryption_key.sha256 is set (CSEK)",
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        else:
                            disk_id = disk.name or disk.self_link or ""
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="Disk ohne CMEK-Verschlüsselung",
                                    description=(
                                        f"Disk {disk_id} in Projekt "
                                        f"{project_id} verwendet "
                                        "Google-verwaltete Verschlüsselungsschlüssel "
                                        "anstatt CMEK. CMEK bietet zusätzliche "
                                        "Kontrolle über den Schlüssellebenszyklus."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.MEDIUM,
                                    provider=CloudProvider.GCP,
                                    region=zone if zone else "global",
                                    resource_id=f"disks/{disk_id}",
                                    resource_type="gcp.compute.Disk",
                                    account_id=project_id,
                                    current_state={
                                        "encryption": "google-managed",
                                        "cmek": False,
                                    },
                                    expected_state=("Disk mit Customer-Managed Encryption Key (CMEK) verschlüsselt"),
                                    remediation=(
                                        "Erstellen Sie einen neuen Disk mit CMEK:\n"
                                        "gcloud compute disks create <DISK_NAME> "
                                        "--kms-key=projects/<PROJECT_ID>/locations/<LOCATION>/"
                                        "keyRings/<KEYRING>/cryptoKeys/<KEY> "
                                        "--zone=<ZONE>\n"
                                        "Hinweis: Bestehende Disks können nicht nachträglich "
                                        "auf CMEK umgestellt werden."
                                    ),
                                    remediation_effort="HIGH",
                                    audit_evidence="disk.disk_encryption_key.kms_key_name is empty",
                                )
                            )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSslPolicyLoadBalancer(BaseCheck):
    """Prüft ob SSL-Policies TLS 1.2 oder höher erzwingen."""

    check_id = "GCP-NR8-003"
    title = "SSL-Policy erzwingt TLS 1.2+"
    description = (
        "Prüft ob Load Balancer SSL-Policies eine minimale TLS-Version "
        "von 1.2 erzwingen, um unsichere Verschlüsselungsprotokolle zu verhindern."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.sslPolicies.list"]
    pruefgrenzen = (
        "Prüft globale und regionale SSL-Policies (SslPolicies.aggregatedList). Load "
        "Balancer ohne zugewiesene SSL-Policy (GCP-Default) und Policies ohne "
        "auslesbare TLS-Mindestversion werden nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import SslPoliciesClient

                client = SslPoliciesClient(credentials=session.credentials)
                # aggregated_list() returns SSL policies for BOTH the global scope and
                # every region in one call (unlike a plain list(), which is global-only
                # and misses regional SSL policies attached to regional target proxies).
                ssl_policies_by_scope = client.aggregated_list(
                    request={"project": project_id},
                )

                for scope, scoped_list in ssl_policies_by_scope:
                    if not scoped_list.ssl_policies:
                        continue
                    region = scope.removeprefix("regions/") if scope != "global" else "global"

                    for policy in scoped_list.ssl_policies:
                        min_tls = policy.min_tls_version or ""
                        if not min_tls:
                            # No data at all (ADR-0016 fail-safe): neither evidence nor defect.
                            continue

                        policy_id = policy.name or ""
                        if min_tls == "TLS_1_2":
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="SSL-Policy erzwingt sicheres TLS",
                                    description=(
                                        f"SSL-Policy {policy_id} in Projekt {project_id} erzwingt mindestens {min_tls}."
                                    ),
                                    region=region,
                                    resource_id=f"sslPolicies/{policy_id}",
                                    resource_type="gcp.compute.SslPolicy",
                                    account_id=project_id,
                                    current_state={"min_tls_version": min_tls},
                                    expected_state="Minimale TLS-Version TLS_1_2",
                                    audit_evidence=f"SslPolicy.min_tls_version={min_tls}",
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        elif min_tls in ("TLS_1_0", "TLS_1_1"):
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="SSL-Policy erlaubt unsicheres TLS-Protokoll",
                                    description=(
                                        f"SSL-Policy {policy_id} in Projekt "
                                        f"{project_id} erlaubt "
                                        f"{min_tls}. TLS 1.0 und 1.1 gelten als "
                                        "unsicher und sollten deaktiviert werden."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.HIGH,
                                    provider=CloudProvider.GCP,
                                    region=region,
                                    resource_id=f"sslPolicies/{policy_id}",
                                    resource_type="gcp.compute.SslPolicy",
                                    account_id=project_id,
                                    current_state={"min_tls_version": min_tls},
                                    expected_state="Minimale TLS-Version TLS_1_2",
                                    remediation=(
                                        "Aktualisieren Sie die SSL-Policy:\n"
                                        "gcloud compute ssl-policies update <POLICY_NAME> "
                                        "--min-tls-version=1.2 --project=<PROJECT_ID>"
                                    ),
                                    remediation_effort="LOW",
                                    audit_evidence=f"SslPolicy.min_tls_version={min_tls}",
                                )
                            )
                        else:
                            errors.append(
                                CheckError(
                                    message=f"Unbekannte TLS-Mindestversion {min_tls} — nicht bewertbar",
                                    error_type="UnverifiableState",
                                )
                            )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCloudSqlSsl(BaseCheck):
    """Prüft ob Cloud SQL-Instanzen SSL/TLS-Verbindungen erzwingen."""

    check_id = "GCP-NR8-004"
    title = "Cloud SQL SSL-Verschlüsselung erzwungen"
    description = "Prüft ob Cloud SQL-Instanzen SSL/TLS-Verbindungen für alle Client-Verbindungen erzwingen."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudsql.instances.list"]
    pruefgrenzen = (
        "Prüft nur die SSL-Erzwingung der Cloud-SQL-Instanzen (requireSsl/sslMode). "
        "Client-seitige Konfiguration wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("sqladmin", "v1beta4")
                result = service.instances().list(project=project_id).execute()
                instances = result.get("items", [])

                for instance in instances:
                    settings = instance.get("settings", {})
                    ip_config = settings.get("ipConfiguration", {})
                    require_ssl = ip_config.get("requireSsl", False)
                    ssl_mode = ip_config.get("sslMode", "")

                    # SSL is enforced if requireSsl is True or sslMode is
                    # ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED
                    ssl_enforced = require_ssl or ssl_mode in (
                        "ENCRYPTED_ONLY",
                        "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
                    )

                    if ssl_enforced:
                        instance_id = instance.get("name", "")
                        findings.append(
                            compliant_finding(
                                self,
                                title="Cloud SQL mit SSL-Erzwingung",
                                description=(
                                    f"Cloud SQL-Instanz {instance_id} in Projekt {project_id} "
                                    f"erzwingt SSL/TLS-Verbindungen."
                                ),
                                region=instance.get("region", "global"),
                                resource_id=f"cloudsql/{instance_id}",
                                resource_type="gcp.sqladmin.Instance",
                                account_id=project_id,
                                current_state={
                                    "require_ssl": require_ssl,
                                    "ssl_mode": ssl_mode or "not set",
                                },
                                expected_state=(
                                    "SSL/TLS-Verbindungen erzwungen (requireSsl=true oder sslMode=ENCRYPTED_ONLY)"
                                ),
                                audit_evidence=f"requireSsl={require_ssl}, sslMode={ssl_mode or 'not set'}",
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                            )
                        )
                    else:
                        instance_id = instance.get("name", "")
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Cloud SQL ohne SSL-Erzwingung",
                                description=(
                                    f"Cloud SQL-Instanz {instance_id} in Projekt "
                                    f"{project_id} erzwingt keine "
                                    "SSL/TLS-Verbindungen. Unverschlüsselte "
                                    "Datenbankverbindungen ermöglichen das "
                                    "Abfangen von Daten im Transit."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region=instance.get("region", "global"),
                                resource_id=f"cloudsql/{instance_id}",
                                resource_type="gcp.sqladmin.Instance",
                                account_id=project_id,
                                current_state={
                                    "require_ssl": require_ssl,
                                    "ssl_mode": ssl_mode or "not set",
                                },
                                expected_state=(
                                    "SSL/TLS-Verbindungen erzwungen (requireSsl=true oder sslMode=ENCRYPTED_ONLY)"
                                ),
                                remediation=(
                                    "Erzwingen Sie SSL für die Cloud SQL-Instanz:\n"
                                    "gcloud sql instances patch <INSTANCE_NAME> "
                                    "--require-ssl --project=<PROJECT_ID>"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(f"requireSsl={require_ssl}, sslMode={ssl_mode or 'not set'}"),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckDiskEncryption(BaseCheck):
    """Prüft ob alle Persistent Disks verschlüsselt sind."""

    check_id = "GCP-NR8-005"
    title = "Persistent Disk Verschlüsselung"
    description = (
        "Prüft ob alle Persistent Disks verschlüsselt sind. GCP "
        "verschlüsselt standardmäßig alle Daten, daher wird nur geprüft, "
        "ob Disks in einem ungewöhnlichen Zustand sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.disks.list"]
    pruefgrenzen = (
        "GCP verschlüsselt Persistent Disks immer standardmäßig; dieser Check bestätigt "
        "nur den Disk-Zustand (READY) als Indiz der aktiven Plattformverschlüsselung. "
        "Er prüft keine Schlüsselstärke und keine kundenseitige Schlüsselkontrolle — "
        "dafür siehe den CMEK-Check (GCP-NR8-002)."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import DisksClient

                client = DisksClient(credentials=session.credentials)
                disks_by_zone = client.aggregated_list(
                    request={"project": project_id},
                )

                for zone, scoped_list in disks_by_zone:
                    if not scoped_list.disks:
                        continue
                    for disk in scoped_list.disks:
                        # All GCP disks are encrypted by default
                        # Flag only if disk is in an unusual state
                        if disk.status == "READY":
                            disk_id = disk.name or disk.self_link or ""
                            findings.append(
                                compliant_finding(
                                    self,
                                    title="Disk verschlüsselt (READY)",
                                    description=(
                                        f"Disk {disk_id} in Projekt {project_id} ist im Zustand "
                                        f"READY — die GCP-Standardverschlüsselung ist aktiv."
                                    ),
                                    region=zone if zone else "global",
                                    resource_id=f"disks/{disk_id}",
                                    resource_type="gcp.compute.Disk",
                                    account_id=project_id,
                                    current_state={"status": "READY", "encrypted": True},
                                    expected_state="Disk-Status READY mit aktiver Verschlüsselung",
                                    audit_evidence="disk.status=READY (GCP default encryption)",
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                )
                            )
                        elif disk.status:
                            disk_id = disk.name or disk.self_link or ""
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    title="Disk-Zustand nicht READY — Verschlüsselungsnachweis nicht verifizierbar",
                                    description=(
                                        f"Disk {disk_id} in Projekt {project_id} befindet sich im "
                                        f"ausgelesenen Zustand '{disk.status}' (nicht READY). Ob die "
                                        "GCP-Standardverschlüsselung in diesem Zustand aktiv ist, kann "
                                        "nicht bestätigt werden."
                                    ),
                                    bsig_30_nr=BSIG_30_NR,
                                    bsig_30_text=BSIG_30_TEXT,
                                    iso27001_control="A.8.24 Verwendung von Kryptographie",
                                    severity=Severity.LOW,
                                    provider=CloudProvider.GCP,
                                    region=zone if zone else "global",
                                    resource_id=f"disks/{disk_id}",
                                    resource_type="gcp.compute.Disk",
                                    account_id=project_id,
                                    current_state={"status": disk.status},
                                    expected_state="Disk-Status READY mit aktiver Verschlüsselung",
                                    remediation=(
                                        "Überprüfen Sie den Disk-Status:\n"
                                        "gcloud compute disks describe <DISK_NAME> "
                                        "--zone=<ZONE> --project=<PROJECT_ID>\n"
                                        "Stellen Sie sicher, dass der Disk im READY-Zustand ist."
                                    ),
                                    remediation_effort="MEDIUM",
                                    audit_evidence=f"disk.status={disk.status}, expected=READY",
                                )
                            )
                        else:
                            disk_id = disk.name or disk.self_link or ""
                            errors.append(
                                CheckError(
                                    message=(
                                        f"Disk-Status für {disk_id or 'unbekannt'} in Projekt "
                                        f"{project_id} nicht auslesbar"
                                    ),
                                    error_type="UnverifiableState",
                                )
                            )

                logger.info(
                    "disk.encryption.checked",
                    project=project_id,
                )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCertificateManager(BaseCheck):
    """Prüft ob verwaltete Zertifikate nicht abgelaufen sind."""

    check_id = "GCP-NR8-006"
    title = "Certificate Manager — Zertifikate nicht abgelaufen"
    description = (
        "Prüft ob über den Certificate Manager verwaltete Zertifikate noch gültig sind und nicht abgelaufen sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["certificatemanager.certs.list"]
    pruefgrenzen = (
        "Prüft nur im Certificate Manager verwaltete Zertifikate. Extern verwaltete Zertifikate werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("certificatemanager", "v1")
                result = (
                    service.projects()
                    .locations()
                    .certificates()
                    .list(parent=f"projects/{project_id}/locations/-")
                    .execute()
                )
                certificates = result.get("certificates", [])
                now = datetime.now(UTC)

                for cert in certificates:
                    expire_time_str = cert.get("expireTime", "")
                    if not expire_time_str:
                        continue

                    # Parse ISO 8601 timestamp
                    try:
                        expire_time = datetime.fromisoformat(expire_time_str.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        errors.append(
                            CheckError(
                                message=(
                                    f"expireTime '{expire_time_str}' für Zertifikat "
                                    f"{cert.get('name', '')} nicht parsebar"
                                ),
                                error_type="UnverifiableState",
                            )
                        )
                        continue

                    if expire_time >= now:
                        cert_id = cert.get("name", "")
                        findings.append(
                            compliant_finding(
                                self,
                                title="Zertifikat gültig",
                                description=(
                                    f"Zertifikat {cert_id} in Projekt {project_id} ist bis "
                                    f"{expire_time.strftime('%Y-%m-%d')} gültig."
                                ),
                                region="global",
                                resource_id=f"certificates/{cert_id}",
                                resource_type="gcp.certificatemanager.Certificate",
                                account_id=project_id,
                                current_state={
                                    "expire_time": expire_time_str,
                                    "expired": False,
                                    # Full API resource path under a deny-list suffix
                                    # (ADR-0011): the path is interpolated into the
                                    # description above, and the Certificate Manager
                                    # API may embed the numeric project NUMBER there,
                                    # which account_id (the project ID) never covers.
                                    # Singular _name — the deny-list regex requires
                                    # the suffix at the very end of the key.
                                    "certificate_name": cert_id,
                                },
                                expected_state="Zertifikat gültig und nicht abgelaufen",
                                audit_evidence=(f"certificate.expireTime={expire_time_str}, now={now.isoformat()}"),
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                            )
                        )
                    else:
                        cert_id = cert.get("name", "")
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Abgelaufenes Zertifikat im Certificate Manager",
                                description=(
                                    f"Zertifikat {cert_id} in Projekt "
                                    f"{project_id} ist am "
                                    f"{expire_time.strftime('%Y-%m-%d')} abgelaufen. "
                                    "Abgelaufene Zertifikate verhindern sichere "
                                    "TLS-Verbindungen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.24 Verwendung von Kryptographie",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region="global",
                                resource_id=f"certificates/{cert_id}",
                                resource_type="gcp.certificatemanager.Certificate",
                                account_id=project_id,
                                current_state={
                                    "expire_time": expire_time_str,
                                    "expired": True,
                                    # Same rationale as the compliant branch: full
                                    # path under a deny-list suffix (ADR-0011).
                                    "certificate_name": cert_id,
                                },
                                expected_state="Zertifikat gültig und nicht abgelaufen",
                                remediation=(
                                    "Erneuern Sie das Zertifikat:\n"
                                    "gcloud certificate-manager certificates create <CERT_NAME> "
                                    "--domains=<DOMAIN> --project=<PROJECT_ID>\n"
                                    "Oder verwenden Sie verwaltete Zertifikate für "
                                    "automatische Erneuerung."
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=f"certificate.expireTime={expire_time_str}, now={now.isoformat()}",
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
