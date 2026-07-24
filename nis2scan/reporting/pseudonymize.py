"""Export-time pseudonymization of scan results (ADR-0011).

Checks emit raw identifiers — scan time is the internal source of truth, so
defects can be located and fixed. Pseudonymization happens only when a report
is exported, controlled by a profile:

- INTERN: raw data for the operating team.
- EXTERN: identifying values replaced by keyed pseudonyms before the report
  leaves the organization (auditors, authorities, third parties).

Identifying values per finding (formalized deny-list):
- resource_id (full value) and its trailing name segment
- account_id
- current_state values under keys ending in _name, _id, _arn, _email
  (strings or lists of strings)

Every occurrence of these values is replaced in all text fields of the
finding, so identifiers embedded in German descriptions are scrubbed too.
Pseudonyms are keyed with NIS2SCAN_SECRET (HMAC-SHA256, consistent with
finding_key per ADR-0010); without the secret an unkeyed SHA-256 fallback
offers no dictionary-attack protection.

KNOWN LIMITATION (ADR-0026, Findings-Exceptions): `Finding.exception` and
`Finding.expired_exception` are intentionally NOT scrubbed. `reason`,
`author` and `ticket` are a customer's own documented, auditable rationale —
rewriting that text would undermine the audit trail the exception mechanism
exists to provide. `expires` is a bare date, never identifying. In practice
this means: if a customer writes a raw resource name, account ID or person's
name into an exception's `reason` (or `author`/`ticket`) field, that text
will appear verbatim even in an EXTERN (pseudonymized) report — customers
who plan to share reports externally should avoid embedding raw identifiers
in exception documentation. The EXTERN report states this limitation in a
visible hint inside the "Ausnahmen" section (legal review 2026-07-24, F3).

Exceptions-file PATH (legal review 2026-07-24, F3b): a full local path often
contains the operator's OS user name. ScanMetadata.exceptions_file therefore
carries only the filename from the start (build_metadata); the full path in
ScanConfig.exceptions_path — needed at scan time to locate the file — is
additionally reduced to its filename here on EXTERN export, so no local
path ever leaves the organization via the EXTERN JSON.
"""

import hashlib
import hmac
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

from nis2scan.engine.models.finding import Finding
from nis2scan.engine.models.result import ScanResult
from nis2scan.engine.secret import resolve_secret

_IDENTIFYING_KEY_RE = re.compile(r"(_name|_id|_arn|_email)$")
_MIN_IDENTIFIER_LEN = 3


class ReportProfile(StrEnum):
    """Report export profile (ADR-0011)."""

    INTERN = "intern"
    EXTERN = "extern"


REPORT_PROFILE_LABELS: dict[ReportProfile, str] = {
    ReportProfile.INTERN: "Intern (Klardaten)",
    ReportProfile.EXTERN: "Extern (pseudonymisiert)",
}


def _pseudonym(value: str, secret: bytes | None) -> str:
    if secret is not None:
        digest = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"pseu_{digest[:12]}"


def _collect_identifiers(finding: Finding) -> set[str]:
    identifiers: set[str] = set()
    if len(finding.resource_id) >= _MIN_IDENTIFIER_LEN:
        identifiers.add(finding.resource_id)
        # Trailing segment is the resource name (e.g. ARN "…:user/alice" -> "alice"),
        # which checks interpolate into German descriptions and evidence.
        tail = re.split(r"[/:]", finding.resource_id)[-1]
        if len(tail) >= _MIN_IDENTIFIER_LEN:
            identifiers.add(tail)
    if len(finding.account_id) >= _MIN_IDENTIFIER_LEN:
        identifiers.add(finding.account_id)
    for key, value in finding.current_state.items():
        if not _IDENTIFYING_KEY_RE.search(key):
            continue
        values = value if isinstance(value, list) else [value]
        identifiers.update(v for v in values if isinstance(v, str) and len(v) >= _MIN_IDENTIFIER_LEN)
    return identifiers


def _replace(text: str, mapping: list[tuple[str, str]]) -> str:
    for raw, pseudonym in mapping:
        text = text.replace(raw, pseudonym)
    return text


def _replace_in_state(value: Any, mapping: list[tuple[str, str]]) -> Any:
    if isinstance(value, str):
        return _replace(value, mapping)
    if isinstance(value, list):
        return [_replace_in_state(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _replace_in_state(v, mapping) for k, v in value.items()}
    return value


def pseudonymize_result(result: ScanResult) -> ScanResult:
    """Return a deep copy of the ScanResult with identifying values replaced.

    The input is never mutated — the internal (raw) result stays usable.
    """
    secret = resolve_secret()

    pseudonymized = result.model_copy(deep=True)

    # F3b (legal review 2026-07-24): the configured exceptions-file path may
    # contain the operator's local user name — reduce it to the bare filename
    # before the result leaves the organization. Metadata already stores only
    # the filename (build_metadata); this covers the config copy in the JSON.
    if pseudonymized.config.exceptions_path:
        pseudonymized.config.exceptions_path = Path(pseudonymized.config.exceptions_path).name

    # CheckError messages are raw exception strings and may embed resource
    # identifiers that never appear in any finding — the finding-based
    # identifier collection below cannot scrub them. The EXTERN profile
    # therefore drops the messages entirely; error_count stays informative.
    for entry in pseudonymized.check_outcomes:
        entry.error_messages = []

    for finding in pseudonymized.findings:
        identifiers = sorted(_collect_identifiers(finding), key=len, reverse=True)
        mapping = [(raw, _pseudonym(raw, secret)) for raw in identifiers]

        finding.resource_id = _replace(finding.resource_id, mapping)
        finding.account_id = _replace(finding.account_id, mapping)
        finding.title = _replace(finding.title, mapping)
        finding.description = _replace(finding.description, mapping)
        finding.expected_state = _replace(finding.expected_state, mapping)
        finding.remediation = _replace(finding.remediation, mapping)
        finding.audit_evidence = _replace(finding.audit_evidence, mapping)
        finding.current_state = _replace_in_state(finding.current_state, mapping)
    return pseudonymized


def apply_profile(result: ScanResult, profile: ReportProfile) -> ScanResult:
    """Apply the export profile: EXTERN pseudonymizes, INTERN passes through.

    The applied profile is stamped into the result (ScanResult.report_profile)
    so stored/exported JSON is self-describing (ADR-0011).
    """
    if profile == ReportProfile.EXTERN:
        pseudonymized = pseudonymize_result(result)
        pseudonymized.report_profile = ReportProfile.EXTERN.value
        return pseudonymized
    return result
