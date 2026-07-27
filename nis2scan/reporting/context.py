"""Shared Jinja2 render context for the Markdown and HTML report templates."""

from typing import Any

from nis2scan.engine.mapping.bsig_30 import BSIG_30_BY_NR
from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.finding import Finding, FindingStatus, Severity
from nis2scan.engine.models.result import Erfuellungsgrad, ScanResult
from nis2scan.reporting.error_hints import most_common_error_message, truncate_error_message
from nis2scan.reporting.labels import (
    ERFUELLUNGSGRAD_LABELS,
    FINDING_STATUS_LABELS,
    NIS2_CATEGORY_LABELS,
    OUTCOME_LABELS,
)
from nis2scan.reporting.pseudonymize import REPORT_PROFILE_LABELS, ReportProfile

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def _effective_erfuellt_area_nrs(result: ScanResult, maengel_by_area: dict[int, list[Finding]]) -> set[int]:
    """Areas shown in the "Zusatzsicht" as all-defects-accepted-by-exception.

    ADR-0026 Nachtrag (2026-07-24): purely DERIVED in the report layer — the
    strict engine semantics (Erfuellungsgrad, CheckOutcome, all counts in the
    JSON contract) stay untouched, and the Zusatzsicht deliberately does NOT
    reuse the reserved ordinal label "erfüllt" (ADR-0008) as a pseudo-rating.
    It only states the spelled-out condition: every defect of the area is
    accepted via an active documented exception (a risk decision of the
    organization — it does not remove the defect and does not pre-empt an
    auditor's or authority's assessment). An area appears here only when ALL:

    1. its strict rating is NICHT_ERFUELLT or TEILWEISE_ERFUELLT (ERFUELLT
       areas are counted separately as strictly fulfilled; NICHT_BEWERTBAR
       never appears — unknown state can never be excepted, ADR-0016),
    2. it has at least one Mangel finding and EVERY Mangel finding of the
       area carries an active (non-expired) exception — a single open defect
       without exception keeps the strict view alone, and
    3. no check of the area produced any CheckError (neither an ERROR outcome
       nor error_count > 0 on an otherwise FAILED check) — errors must never
       appear covered by exceptions (fail-safe, ADR-0016).
    """
    upgraded: set[int] = set()
    for score in result.summary.scores_by_area:
        if score.erfuellungsgrad not in (Erfuellungsgrad.NICHT_ERFUELLT, Erfuellungsgrad.TEILWEISE_ERFUELLT):
            continue
        area_maengel = maengel_by_area.get(score.bsig_30_nr, [])
        if not area_maengel or not all(f.exception is not None for f in area_maengel):
            continue
        area_entries = [e for e in result.check_outcomes if e.bsig_30_nr == score.bsig_30_nr]
        if any(e.outcome == CheckOutcome.ERROR or e.error_count > 0 for e in area_entries):
            continue
        upgraded.add(score.bsig_30_nr)
    return upgraded


def build_report_context(result: ScanResult, profile: ReportProfile = ReportProfile.INTERN) -> dict[str, Any]:
    """Build the template context from a ScanResult.

    Splits findings into Mängel (non-compliant) and Positivnachweise
    (compliant, ADR-0006) and groups both by §30 area.
    """
    maengel_by_area: dict[int, list[Finding]] = {}
    positive_by_area: dict[int, list[Finding]] = {}
    for finding in result.findings:
        target = maengel_by_area if finding.status == FindingStatus.NON_COMPLIANT else positive_by_area
        target.setdefault(finding.bsig_30_nr, []).append(finding)

    for area_findings in maengel_by_area.values():
        area_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))

    # Coverage model (ADR-0009): scanned areas with their automatable partial
    # aspect and the manual attestation checklist; plus per-check known
    # limitations (ADR-0016 rule 2) with an honest count of undocumented ones.
    scanned_nrs = sorted({score.bsig_30_nr for score in result.summary.scores_by_area})
    attestierung_areas = [BSIG_30_BY_NR[nr] for nr in scanned_nrs if nr in BSIG_30_BY_NR]
    pruefgrenzen_entries = [e for e in result.check_outcomes if e.pruefgrenzen]
    pruefgrenzen_missing = len(result.check_outcomes) - len(pruefgrenzen_entries)

    # Findings-Exceptions (ADR-0026): flat lists across all areas — the
    # "Ausnahmen" section is a single table, not grouped per §30 area, mirroring
    # the existing "Alle Check-Ergebnisse" coverage table.
    findings_with_exception = [f for f in result.findings if f.exception is not None]
    findings_with_expired_exception = [f for f in result.findings if f.expired_exception is not None]

    # Zusatzsicht (ADR-0026 Nachtrag): report-layer derived only, shown IN
    # ADDITION to (never instead of) the strict rating — counts areas that are
    # strictly fulfilled plus areas whose defects are all accepted via active
    # documented exceptions.
    effective_erfuellt_area_nrs = _effective_erfuellt_area_nrs(result, maengel_by_area)
    strict_erfuellt_total = sum(
        1 for s in result.summary.scores_by_area if s.erfuellungsgrad == Erfuellungsgrad.ERFUELLT
    )
    effective_erfuellt_total = strict_erfuellt_total + len(effective_erfuellt_area_nrs)

    # Fix 2 (hardening audit 27.07.2026): surface WHY checks errored, not just
    # that they did. `raw_message` stays None under the EXTERN profile — that
    # profile already strips CheckOutcomeEntry.error_messages (pseudonymize.py)
    # because raw exception text may embed identifiers no finding names.
    raw_message = most_common_error_message(result.check_outcomes)
    most_common_error = truncate_error_message(raw_message) if raw_message else None

    company = result.config.company
    return {
        "result": result,
        "summary": result.summary,
        "config": result.config,
        "company": company,
        "findings_by_area": maengel_by_area,  # legacy alias, kept for template compatibility
        "maengel_by_area": maengel_by_area,
        "positive_by_area": positive_by_area,
        "check_outcomes": result.check_outcomes,
        "attestierung_areas": attestierung_areas,
        "pruefgrenzen_entries": pruefgrenzen_entries,
        "pruefgrenzen_missing": pruefgrenzen_missing,
        "findings_with_exception": findings_with_exception,
        "findings_with_expired_exception": findings_with_expired_exception,
        "effective_erfuellt_area_nrs": effective_erfuellt_area_nrs,
        "effective_erfuellt_total": effective_erfuellt_total,
        "strict_erfuellt_total": strict_erfuellt_total,
        "bsig_areas": BSIG_30_BY_NR,
        "Severity": Severity,
        "erfuellungsgrad_labels": ERFUELLUNGSGRAD_LABELS,
        "outcome_labels": OUTCOME_LABELS,
        "finding_status_labels": FINDING_STATUS_LABELS,
        "nis2_category_label": NIS2_CATEGORY_LABELS.get(company.nis2_category, company.nis2_category),
        "report_profile_label": REPORT_PROFILE_LABELS.get(profile, str(profile)),
        "most_common_error_message": most_common_error,
    }
