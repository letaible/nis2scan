"""Scan result models — the JSON contract between engine and consumers."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.finding import Finding

# Contract version (ADR-0021): FROZEN 2026-07-13 for release 0.1 (ADR-0020).
# From here on SemVer evolution rules apply — minors are strictly additive,
# breaking changes require a major bump with a documented migration path.
# History: docs/schema-changelog.md.
SCHEMA_VERSION = "1.2.0"


class Erfuellungsgrad(StrEnum):
    """Ordinal assessment of the cloud-technical partial aspect of a §30 area
    (ADR-0008) — replaces percent scores, which imply a legally non-existent
    partial fulfilment."""

    ERFUELLT = "erfuellt"
    TEILWEISE_ERFUELLT = "teilweise_erfuellt"
    NICHT_ERFUELLT = "nicht_erfuellt"
    NICHT_BEWERTBAR = "nicht_bewertbar"


class CheckOutcomeEntry(BaseModel):
    """Per-check outcome in the contract (ADR-0007) — makes every executed,
    errored, or skipped check visible; nothing disappears silently (ADR-0016)."""

    check_id: str
    title: str = ""  # German check title, so reports/dashboards need no registry lookup
    provider: str = ""
    bsig_30_nr: int = Field(ge=1, le=10)
    outcome: CheckOutcome
    error_count: int = 0
    # Messages of the CheckErrors behind error_count (additive, schema 1.2.0).
    # Without them a user only sees THAT a check errored, never WHY — the
    # number-one avoidable support question. Raw exception strings; the
    # EXTERN profile drops them (they may embed identifiers no finding names).
    error_messages: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    # Known limitations of the check, printed next to the result (ADR-0016
    # rule 2: "geprüft wurde X, nicht Y"). German, None until documented.
    pruefgrenzen: str | None = None


class ComplianceScore(BaseModel):
    """Compliance score for a single §30 BSIG area."""

    bsig_30_nr: int = Field(ge=1, le=10)
    area_name: str
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    # Checks that found no Prüfobjekte (derive_outcome NOT_APPLICABLE) —
    # shown separately so "passed/applicable" never counts them silently.
    not_applicable_checks: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    # Ordinal rating of the cloud-technical partial aspect (ADR-0008/0009).
    erfuellungsgrad: Erfuellungsgrad = Erfuellungsgrad.NICHT_BEWERTBAR
    # DEPRECATED (ADR-0008): retained in schema 1.0 for SaaS compatibility
    # (founder decision 2026-07-13) — removal scheduled for schema 2.0.
    # Value is derived; erfuellungsgrad is authoritative.
    score_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    # Findings-Exceptions (ADR-0026): additive, second-track disclosure only —
    # failed_checks/critical_count/etc. above are NOT redefined by exceptions,
    # they still count every non-compliant finding. This is purely "of which
    # N are accepted via a documented exception" (no silent Herausrechnung).
    exceptions_accepted_count: int = 0


class ComplianceSummary(BaseModel):
    """Aggregated compliance summary across all §30 areas."""

    # Ordinal overall rating of the cloud-technical partial aspect (ADR-0008/0009),
    # aggregated conservatively over the per-area ratings (ADR-0016).
    erfuellungsgrad_gesamt: Erfuellungsgrad = Erfuellungsgrad.NICHT_BEWERTBAR

    # Check execution counts (ADR-0007) — ERROR is visible at the top level,
    # not buried in per-check data (ADR-0016, the 'Lacework problem').
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    not_applicable_checks: int = 0

    # total_findings and the severity counts cover NON_COMPLIANT findings
    # (Mängel) only; compliant positive evidence is counted separately
    # (ADR-0006) so defect statistics stay meaningful.
    total_findings: int = 0
    compliant_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    areas_scanned: int = 0
    scores_by_area: list[ComplianceScore] = Field(default_factory=list)

    # Findings-Exceptions (ADR-0026): total across all areas, same additive
    # second-track semantics as ComplianceScore.exceptions_accepted_count —
    # total_findings/severity counts above are unchanged by exceptions.
    exceptions_accepted_count: int = 0

    # DEPRECATED (ADR-0008): retained in schema 1.0 for SaaS compatibility
    # (founder decision 2026-07-13) — removal scheduled for schema 2.0.
    # overall_status is derived from erfuellungsgrad_gesamt (NICHT_BEWERTBAR
    # maps to NON_COMPLIANT fail-safe); erfuellungsgrad_gesamt is authoritative.
    overall_status: str = "NON_COMPLIANT"
    overall_score_percent: float = 0.0


class ScanMetadata(BaseModel):
    """Metadata about the scan execution environment."""

    tool_version: str = ""
    python_version: str = ""
    boto3_version: str | None = None
    azure_sdk_version: str | None = None
    gcp_sdk_version: str | None = None
    scan_duration_seconds: float = 0.0
    # Findings-Exceptions (ADR-0026): set only when ScanConfig.exceptions_path
    # was provided. exceptions_file is the path as configured (for
    # traceability in the JSON contract); exceptions_applied counts findings
    # annotated with an active rule; exceptions_expired counts rules that
    # matched a finding but had already expired (never applied — see
    # engine/finding_exceptions.apply_exceptions).
    exceptions_file: str | None = None
    exceptions_applied: int = 0
    exceptions_expired: int = 0


class ScanResult(BaseModel):
    """Complete scan result — the JSON contract.

    This is the single source of truth. Reports (Markdown, PDF)
    are ALWAYS generated from this, never directly from checks.
    """

    # Contract & legal versioning (ADR-0013/0021)
    schema_version: str = SCHEMA_VERSION
    mapping_version: str = ""
    rechtsstand: str = ""

    scan_id: str
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    config: ScanConfig
    # Export profile marker (ADR-0011): "intern" = raw identifiers,
    # "extern" = pseudonymized at export. Lets consumers of stored JSON
    # tell the two apart — set by reporting.pseudonymize.apply_profile.
    report_profile: str = "intern"
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    findings: list[Finding] = Field(default_factory=list)
    check_outcomes: list[CheckOutcomeEntry] = Field(default_factory=list)
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, data: str) -> "ScanResult":
        """Deserialize from JSON string."""
        return cls.model_validate_json(data)
