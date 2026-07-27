"""Scan orchestrator — the core entry point for running NIS2 compliance scans.

This module is provider-agnostic. It resolves which checks to run
based on config, executes them, and aggregates results into a ScanResult.
"""

import hashlib
import hmac
import platform
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from nis2scan import __version__
from nis2scan.engine.events import EventBus, ScanEvent
from nis2scan.engine.finding_exceptions import ExceptionApplication, apply_exceptions, load_exceptions_file
from nis2scan.engine.mapping.bsig_30 import BSIG_30_BY_NR, MAPPING_VERSION, RECHTSSTAND
from nis2scan.engine.models.check import (
    BaseCheck,
    CheckError,
    CheckOutcome,
    CheckResult,
    derive_outcome,
)
from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.models.finding import Finding, FindingStatus, Severity
from nis2scan.engine.models.result import (
    SCHEMA_VERSION,
    CheckOutcomeEntry,
    ComplianceScore,
    ComplianceSummary,
    Erfuellungsgrad,
    ScanMetadata,
    ScanResult,
)
from nis2scan.engine.registry import CheckRegistry
from nis2scan.engine.secret import SECRET_ENV, resolve_secret

logger = structlog.get_logger()


def _compute_finding_key(finding: Finding, secret: bytes | None) -> str:
    """Stable cross-scan identity of a finding (ADR-0010).

    HMAC-SHA256 over (provider, account_id, check_id, resource_id) with the
    customer secret. Without a secret we fall back to an unkeyed SHA-256 —
    tracking still works, but the key offers no dictionary-attack protection
    for personal identifiers in externally shared reports.
    """
    payload = f"{finding.provider.value}|{finding.account_id}|{finding.check_id}|{finding.resource_id}"
    if secret is not None:
        return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def run_scan(
    config: ScanConfig,
    event_bus: EventBus | None = None,
) -> ScanResult:
    """Execute a complete NIS2 compliance scan.

    Pure functional: config in, ScanResult out.
    No print, no file write, no side effects.

    Args:
        config: Scan configuration (providers, scope, company info).
        event_bus: Optional event bus for progress reporting.

    Returns:
        Complete ScanResult ready for serialization or reporting.
    """
    scan_id = str(uuid.uuid4())
    start_time = time.monotonic()
    bus = event_bus or EventBus()

    bus.emit(ScanEvent.SCAN_STARTED, {"scan_id": scan_id, "config": config.model_dump()})

    all_findings: list[Finding] = []
    all_results: list[CheckResult] = []
    outcome_entries: list[CheckOutcomeEntry] = []

    fingerprint_secret = resolve_secret()
    if fingerprint_secret is None:
        # Fix 5b (hardening audit 27.07.2026): this hint reaches every
        # customer console, so it must be German prose without internal
        # ADR jargon — customers do not know what an ADR is.
        logger.warning(
            "scan.no_fingerprint_secret",
            hint=f"Hinweis: Für stabile Finding-Fingerprints 'nis2scan init' ausführen oder {SECRET_ENV} setzen.",
        )

    checks = resolve_checks(config)
    logger.info("scan.started", scan_id=scan_id, check_count=len(checks))

    # Findings-Exceptions (ADR-0026): LOAD the file before the first cloud
    # call, APPLY after the check loop. Loading late used to mean a file that
    # broke or vanished after the CLI preflight aborted the scan only AFTER
    # every cloud API call had already run — burning the whole scan and
    # violating the exit-64 invariant "usage errors abort before any scan
    # work" (legal delta review 27.07.2026, Auflage 2).
    loaded_exceptions = None
    if config.exceptions_path:
        # Fail-safe: a broken exceptions file raises ExceptionsFileError here,
        # which aborts the scan instead of silently proceeding without it
        # (module docstring, nis2scan.engine.finding_exceptions).
        loaded_exceptions = load_exceptions_file(Path(config.exceptions_path))

    # PERF-2: one session per enabled provider, created ONCE before the check
    # loop — not per check. A fresh session used to mean a real AssumeRole /
    # subscription- or project-discovery network call for every single check.
    provider_sessions = create_provider_sessions(checks, config)

    for check in checks:
        bus.emit(ScanEvent.CHECK_STARTED, {"check_id": check.check_id})

        try:
            session = provider_sessions.get(check.provider.value.lower())
            result = await execute_check(check, config, session)
        except Exception as exc:
            # Fail-safe (ADR-0016): a crashing check must never vanish from the
            # result — it is recorded as ERROR, not just emitted as an event.
            logger.error("check.failed", check_id=check.check_id, error=str(exc))
            bus.emit(ScanEvent.SCAN_FAILED, {"check_id": check.check_id, "error": str(exc)})
            result = CheckResult(
                check_id=check.check_id,
                errors=[CheckError(message=str(exc), error_type=type(exc).__name__)],
            )

        outcome = derive_outcome(result)  # ADR-0007: derived, never set independently
        result.outcome = outcome
        for finding in result.findings:
            finding.finding_key = _compute_finding_key(finding, fingerprint_secret)

        all_results.append(result)
        all_findings.extend(result.findings)
        outcome_entries.append(
            CheckOutcomeEntry(
                check_id=check.check_id,
                title=check.title,
                provider=check.provider.value,
                bsig_30_nr=check.bsig_30_nr,
                outcome=outcome,
                error_count=len(result.errors),
                error_messages=[e.message for e in result.errors],
                duration_ms=result.duration_ms,
                pruefgrenzen=check.pruefgrenzen,
            )
        )

        bus.emit(
            ScanEvent.CHECK_COMPLETED,
            {
                "check_id": check.check_id,
                "finding_count": len(result.findings),
                "error_count": len(result.errors),
                "outcome": outcome.value,
            },
        )

        # Emit critical finding events
        for finding in result.findings:
            if finding.severity == Severity.CRITICAL:
                bus.emit(
                    ScanEvent.FINDING_CRITICAL,
                    {
                        "check_id": finding.check_id,
                        "resource_id": finding.resource_id,
                        "title": finding.title,
                    },
                )

    scan_timestamp = datetime.now(UTC)

    # Findings-Exceptions (ADR-0026): engine-side annotation (not report-only)
    # so JSON, Markdown, PDF and SaaS all share the same exception view. Opt-in
    # only — no exceptions_path means no exceptions are ever applied.
    exceptions_result: ExceptionApplication | None = None
    if loaded_exceptions is not None:
        exceptions_result = apply_exceptions(all_findings, loaded_exceptions, scan_date=scan_timestamp.date())
        logger.info(
            "scan.exceptions_applied",
            exceptions_file=config.exceptions_path,
            applied=exceptions_result.applied_count,
            expired=len(exceptions_result.expired_matches),
        )

    duration = time.monotonic() - start_time
    summary = build_summary(all_findings, config.bsig_30_scope, outcome_entries)
    metadata = build_metadata(duration, config.exceptions_path, exceptions_result)

    scan_result = ScanResult(
        schema_version=SCHEMA_VERSION,
        mapping_version=MAPPING_VERSION,
        rechtsstand=RECHTSSTAND,
        scan_id=scan_id,
        scan_timestamp=scan_timestamp,
        config=config,
        summary=summary,
        findings=all_findings,
        check_outcomes=outcome_entries,
        metadata=metadata,
    )

    bus.emit(
        ScanEvent.SCAN_COMPLETED,
        {
            "scan_id": scan_id,
            "total_findings": len(all_findings),
            "duration_seconds": duration,
        },
    )

    logger.info("scan.completed", scan_id=scan_id, findings=len(all_findings), duration=f"{duration:.1f}s")
    return scan_result


def resolve_checks(config: ScanConfig) -> list[BaseCheck]:
    """Resolve which checks to run based on config scope."""
    checks: list[BaseCheck] = []
    registry = CheckRegistry.get_instance()

    for provider_name, provider_config in config.providers.items():
        if not provider_config.enabled:
            continue

        provider_checks = registry.get_checks_for_provider(provider_name)
        for check in provider_checks:
            if check.bsig_30_nr in config.bsig_30_scope:
                checks.append(check)

    return checks


def _create_provider_session(provider_name: str, provider_config: ProviderConfig) -> Any:
    """Create the session for a single provider (lazy SDK imports, PERF-2)."""
    if provider_name == "aws":
        from nis2scan.engine.providers.aws.session import create_aws_session

        return create_aws_session(provider_config)
    if provider_name == "azure":
        from nis2scan.engine.providers.azure.session import create_azure_session

        return create_azure_session(provider_config)
    if provider_name == "gcp":
        from nis2scan.engine.providers.gcp.session import create_gcp_session

        return create_gcp_session(provider_config)

    msg = f"Unknown provider: {provider_name}"
    raise ValueError(msg)


def create_provider_sessions(checks: list[BaseCheck], config: ScanConfig) -> dict[str, Any]:
    """Create one session per provider needed by ``checks``, before the check loop (PERF-2).

    Previously every check triggered its own session creation in
    execute_check — one real AssumeRole/subscription-/project-discovery
    network call per check instead of per scan. Hoisting it here means each
    enabled provider pays that cost exactly once, no matter how many checks
    run against it.

    A dict value is either the created session, or the exception raised while
    creating it. Storing the exception (rather than raising immediately) keeps
    this fail-safe (ADR-0016): execute_check re-raises it per check, so
    run_scan's existing per-check try/except still turns a provider-wide
    session failure into a CheckError for every affected check — exactly the
    outcome a failing per-check session creation produced before this change.
    """
    sessions: dict[str, Any] = {}
    provider_names = dict.fromkeys(check.provider.value.lower() for check in checks)
    for provider_name in provider_names:
        provider_config = config.providers.get(provider_name)
        if not provider_config or not provider_config.enabled:
            continue
        try:
            sessions[provider_name] = _create_provider_session(provider_name, provider_config)
        except Exception as exc:
            logger.error("scan.session_creation_failed", provider=provider_name, error=str(exc))
            sessions[provider_name] = exc
    return sessions


async def execute_check(check: BaseCheck, config: ScanConfig, session: Any) -> CheckResult:
    """Execute a single check with a pre-created provider session.

    ``session`` comes from ``create_provider_sessions`` (one per enabled
    provider, built once in run_scan before the check loop — PERF-2). If
    session creation failed for this check's provider, ``session`` holds the
    exception instead of a session object; re-raising it here lets run_scan's
    existing fail-safe wrapper record it as a CheckError, same as before.
    """
    provider_name = check.provider.value.lower()
    provider_config = config.providers.get(provider_name)

    if not provider_config or not provider_config.enabled:
        return CheckResult(check_id=check.check_id, skipped=True, skip_reason="Provider not enabled")

    if isinstance(session, Exception):
        raise session

    if session is None:
        return CheckResult(check_id=check.check_id, skipped=True, skip_reason=f"Unknown provider: {provider_name}")

    return await check.execute(session)


def build_summary(
    findings: list[Finding],
    scope: list[int],
    outcome_entries: list[CheckOutcomeEntry] | None = None,
) -> ComplianceSummary:
    """Build compliance summary from findings and per-check outcomes."""
    entries = outcome_entries or []
    # ADR-0006: defect statistics cover non-compliant findings only;
    # compliant findings are positive evidence and counted separately.
    maengel = [f for f in findings if f.status == FindingStatus.NON_COMPLIANT]
    compliant_count = len(findings) - len(maengel)
    severity_counts = {s: 0 for s in Severity}
    for f in maengel:
        severity_counts[f.severity] += 1

    scores: list[ComplianceScore] = []
    for nr in sorted(scope):
        area_findings = [f for f in maengel if f.bsig_30_nr == nr]
        area_severity = {s: 0 for s in Severity}
        for f in area_findings:
            area_severity[f.severity] += 1
        # Findings-Exceptions (ADR-0026): additive second-track count, does
        # NOT change area_severity/failed_checks above — see ComplianceScore.
        area_exceptions_accepted = len([f for f in area_findings if f.exception is not None])

        area_entries = [e for e in entries if e.bsig_30_nr == nr]
        passed = len([e for e in area_entries if e.outcome == CheckOutcome.PASSED])
        failed = len([e for e in area_entries if e.outcome == CheckOutcome.FAILED])
        errored = len([e for e in area_entries if e.outcome == CheckOutcome.ERROR])
        not_applicable = len([e for e in area_entries if e.outcome == CheckOutcome.NOT_APPLICABLE])
        total = len(area_entries)

        # Erfüllungsgrad of the cloud-technical partial aspect (ADR-0008),
        # conservative per ADR-0016: errors or missing evaluation never
        # count towards fulfilment.
        if failed and passed:
            grad = Erfuellungsgrad.TEILWEISE_ERFUELLT
        elif failed:
            grad = Erfuellungsgrad.NICHT_ERFUELLT
        elif passed and not errored:
            grad = Erfuellungsgrad.ERFUELLT
        else:
            grad = Erfuellungsgrad.NICHT_BEWERTBAR

        scores.append(
            ComplianceScore(
                bsig_30_nr=nr,
                area_name=BSIG_30_BY_NR[nr].title_de if nr in BSIG_30_BY_NR else f"Bereich {nr}",
                total_checks=total,
                passed_checks=passed,
                failed_checks=failed,
                error_checks=errored,
                not_applicable_checks=not_applicable,
                critical_count=area_severity[Severity.CRITICAL],
                high_count=area_severity[Severity.HIGH],
                medium_count=area_severity[Severity.MEDIUM],
                low_count=area_severity[Severity.LOW],
                info_count=area_severity[Severity.INFO],
                erfuellungsgrad=grad,
                # DEPRECATED (ADR-0008): kept for existing consumers until the
                # W2 cleanup; now at least computed from real check counts.
                score_percent=round((passed / total) * 100, 1) if total else 0.0,
                exceptions_accepted_count=area_exceptions_accepted,
            )
        )

    # Conservative ordinal aggregate over all areas (ADR-0008/0016):
    # fulfilled only when every area is fulfilled; unknown never upgrades.
    grades = {s.erfuellungsgrad for s in scores}
    if not grades or grades == {Erfuellungsgrad.NICHT_BEWERTBAR}:
        gesamt = Erfuellungsgrad.NICHT_BEWERTBAR
    elif grades == {Erfuellungsgrad.ERFUELLT}:
        gesamt = Erfuellungsgrad.ERFUELLT
    elif grades <= {Erfuellungsgrad.NICHT_ERFUELLT, Erfuellungsgrad.NICHT_BEWERTBAR}:
        gesamt = Erfuellungsgrad.NICHT_ERFUELLT
    else:
        gesamt = Erfuellungsgrad.TEILWEISE_ERFUELLT

    total_checks = len(entries)
    passed_checks = sum(1 for e in entries if e.outcome == CheckOutcome.PASSED)
    failed_checks = sum(1 for e in entries if e.outcome == CheckOutcome.FAILED)
    error_checks = sum(1 for e in entries if e.outcome == CheckOutcome.ERROR)
    not_applicable_checks = sum(1 for e in entries if e.outcome == CheckOutcome.NOT_APPLICABLE)

    # DEPRECATED (ADR-0008): legacy fields, derived from the ordinal rating so
    # old consumers cannot see COMPLIANT while checks errored (ADR-0016).
    status = {
        Erfuellungsgrad.ERFUELLT: "COMPLIANT",
        Erfuellungsgrad.TEILWEISE_ERFUELLT: "PARTIALLY_COMPLIANT",
        Erfuellungsgrad.NICHT_ERFUELLT: "NON_COMPLIANT",
        Erfuellungsgrad.NICHT_BEWERTBAR: "NON_COMPLIANT",
    }[gesamt]
    overall_score = round((passed_checks / total_checks) * 100, 1) if total_checks else 0.0

    return ComplianceSummary(
        erfuellungsgrad_gesamt=gesamt,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        error_checks=error_checks,
        not_applicable_checks=not_applicable_checks,
        total_findings=len(maengel),
        compliant_count=compliant_count,
        critical_count=severity_counts[Severity.CRITICAL],
        high_count=severity_counts[Severity.HIGH],
        medium_count=severity_counts[Severity.MEDIUM],
        low_count=severity_counts[Severity.LOW],
        info_count=severity_counts[Severity.INFO],
        areas_scanned=len(scope),
        scores_by_area=scores,
        # Findings-Exceptions (ADR-0026): sum of the per-area counts above —
        # additive second-track disclosure, total_findings is unchanged.
        exceptions_accepted_count=sum(s.exceptions_accepted_count for s in scores),
        overall_status=status,
        overall_score_percent=overall_score,
    )


def build_metadata(
    duration: float,
    exceptions_path: str | None = None,
    exceptions_result: ExceptionApplication | None = None,
) -> ScanMetadata:
    """Build scan metadata.

    exceptions_path/exceptions_result surface the Findings-Exceptions state
    (ADR-0026) in the JSON contract: which file was used, how many findings
    it annotated, and how many matched rules had already expired.

    Only the FILENAME of the exceptions file is stored (legal review
    2026-07-24, F3b): a full local path often contains the operator's user
    name and would leak it into every report — including the EXTERN profile.
    The full path stays available at scan time via ScanConfig.exceptions_path
    (reduced to the filename at EXTERN export, see reporting.pseudonymize).
    """
    metadata = ScanMetadata(
        tool_version=__version__,
        python_version=platform.python_version(),
        scan_duration_seconds=round(duration, 2),
        exceptions_file=Path(exceptions_path).name if exceptions_path else None,
        exceptions_applied=exceptions_result.applied_count if exceptions_result else 0,
        exceptions_expired=len(exceptions_result.expired_matches) if exceptions_result else 0,
    )

    try:
        import boto3

        metadata.boto3_version = boto3.__version__
    except ImportError:
        pass

    try:
        from importlib.metadata import version

        metadata.gcp_sdk_version = version("google-api-python-client")
    except Exception:  # noqa: BLE001 — metadata only, never fail the scan
        pass

    return metadata
