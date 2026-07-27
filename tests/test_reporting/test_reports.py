"""Tests for Markdown report rendering — contract v2 surface (ADR-0006/0007/0008/0016)."""

import pytest

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.config import CompanyInfo, ScanConfig
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingStatus, Severity
from nis2scan.engine.models.result import CheckOutcomeEntry, ScanResult
from nis2scan.engine.scanner import build_summary
from nis2scan.reporting.markdown import render_report


def _finding(status: FindingStatus, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id="AWS-NR8-001",
        status=status,
        title="S3-Bucket ohne Verschlüsselung" if status == FindingStatus.NON_COMPLIANT else "S3-Bucket verschlüsselt",
        description="Testbeschreibung",
        bsig_30_nr=8,
        bsig_30_text="§30 Abs. 2 Nr. 8 BSIG",
        severity=severity,
        provider=CloudProvider.AWS,
        region="eu-central-1",
        resource_id="arn:aws:s3:::test-bucket",
        resource_type="AWS::S3::Bucket",
        account_id="123456789012",
        expected_state="Verschlüsselung aktiviert",
        remediation="SSE-KMS aktivieren",
        remediation_effort="LOW",
        audit_evidence="sse=aws:kms",
    )


@pytest.fixture
def scan_result() -> ScanResult:
    findings = [
        _finding(FindingStatus.NON_COMPLIANT),
        _finding(FindingStatus.COMPLIANT, Severity.INFO),
    ]
    entries = [
        CheckOutcomeEntry(
            check_id="AWS-NR8-001",
            title="S3-Verschlüsselung",
            provider="AWS",
            bsig_30_nr=8,
            outcome=CheckOutcome.FAILED,
        ),
        CheckOutcomeEntry(
            check_id="AWS-NR1-001",
            title="AWS Config aktiviert",
            provider="AWS",
            bsig_30_nr=1,
            outcome=CheckOutcome.ERROR,
            error_count=1,
            pruefgrenzen="Prüft nur den Recorder-Status, nicht die Vollständigkeit der aufgezeichneten Ressourcen.",
        ),
        CheckOutcomeEntry(
            check_id="AWS-NR2-001",
            title="GuardDuty aktiviert",
            provider="AWS",
            bsig_30_nr=2,
            outcome=CheckOutcome.PASSED,
        ),
    ]
    return ScanResult(
        mapping_version="2026.05",
        rechtsstand="BSIG i. d. F. des NIS2UmsuCG, in Kraft seit 06.12.2025",
        scan_id="test-scan-001",
        config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH", nis2_category="besonders_wichtig")),
        summary=build_summary(findings, [1, 2, 8], entries),
        findings=findings,
        check_outcomes=entries,
    )


class TestMarkdownReport:
    def test_shows_erfuellungsgrad_not_percent(self, scan_result):
        report = render_report(scan_result)

        assert "Erfüllungsgrad" in report
        assert "Teilweise erfüllt" in report
        assert "Compliance-Score" not in report

    def test_error_checks_visible(self, scan_result):
        report = render_report(scan_result)

        assert "1 Check(s) konnten nicht ausgewertet werden" in report
        assert "Nicht ausgewertete Checks (Fehler)" in report
        assert "AWS-NR1-001" in report

    def test_coverage_lists_every_check(self, scan_result):
        report = render_report(scan_result)

        assert "Prüfabdeckung" in report
        for check_id in ("AWS-NR8-001", "AWS-NR1-001", "AWS-NR2-001"):
            assert check_id in report
        assert "Bestanden" in report
        assert "Fehler — nicht ausgewertet" in report

    def test_positive_evidence_separated_from_maengel(self, scan_result):
        report = render_report(scan_result)

        assert "Positivnachweise" in report
        assert "S3-Bucket verschlüsselt" in report
        assert "Mängel nach §30-Bereich" in report

    def test_legal_versioning_in_report(self, scan_result):
        report = render_report(scan_result)

        assert "NIS2UmsuCG" in report
        assert "2026.05" in report
        assert scan_result.schema_version in report

    def test_primary_source_cited_in_report(self, scan_result):
        # ADR-0018: findings print their Fundstelle incl. primary-source URL
        report = render_report(scan_result)

        assert "gesetze-im-internet.de/bsig_2025" in report
        assert "abgerufen am 2026-07-11" in report

    def test_nis2_category_label_with_selbsteinstufung(self, scan_result):
        report = render_report(scan_result)

        assert "Besonders wichtige Einrichtung (Selbsteinstufung)" in report

    def test_no_error_banner_without_errors(self, scan_result):
        scan_result.check_outcomes = [e for e in scan_result.check_outcomes if e.outcome != CheckOutcome.ERROR]
        scan_result.summary = build_summary(scan_result.findings, [2, 8], scan_result.check_outcomes)

        report = render_report(scan_result)
        assert "konnten nicht ausgewertet werden" not in report


class TestErrorMessagesInReport:
    """Fix 2 (hardening audit 27.07.2026): the report used to render
    error_count but never the actual error MESSAGE — the number-one avoidable
    support question ("why did the check error?") had no answer in the
    report at all."""

    def test_error_message_shown_truncated_next_to_the_check(self, scan_result):
        error_entry = next(e for e in scan_result.check_outcomes if e.outcome == CheckOutcome.ERROR)
        error_entry.error_messages = ["Unable to locate credentials"]

        report = render_report(scan_result)

        assert "Unable to locate credentials" in report

    def test_long_error_message_is_truncated(self, scan_result):
        error_entry = next(e for e in scan_result.check_outcomes if e.outcome == CheckOutcome.ERROR)
        error_entry.error_messages = ["x" * 300]

        report = render_report(scan_result)

        assert "x" * 300 not in report
        assert "…" in report

    def test_pipe_in_error_message_does_not_break_table(self, scan_result):
        error_entry = next(e for e in scan_result.check_outcomes if e.outcome == CheckOutcome.ERROR)
        error_entry.error_messages = ["broken | table cell"]

        report = render_report(scan_result)

        assert "broken \\| table cell" in report

    def test_no_error_message_column_entry_without_messages(self, scan_result):
        # The existing fixture's error entry has error_count=1 but no
        # error_messages (pre-Fix-2 data shape) — must render an empty cell,
        # not crash.
        report = render_report(scan_result)

        assert "Nicht ausgewertete Checks (Fehler)" in report

    def test_most_common_error_message_sentence_when_scan_is_inconclusive(self):
        from nis2scan.engine.models.config import CompanyInfo, ScanConfig
        from nis2scan.engine.models.result import CheckOutcomeEntry, ScanResult
        from nis2scan.engine.scanner import build_summary

        entries = [
            CheckOutcomeEntry(
                check_id="AWS-NR1-001",
                bsig_30_nr=1,
                outcome=CheckOutcome.ERROR,
                error_count=1,
                error_messages=["Unable to locate credentials"],
            ),
            CheckOutcomeEntry(
                check_id="AWS-NR1-002",
                bsig_30_nr=1,
                outcome=CheckOutcome.ERROR,
                error_count=1,
                error_messages=["Unable to locate credentials"],
            ),
        ]
        result = ScanResult(
            scan_id="test-scan-inconclusive",
            config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
            summary=build_summary([], [1], entries),
            findings=[],
            check_outcomes=entries,
        )

        report = render_report(result)

        assert "Häufigste Fehlermeldung: Unable to locate credentials" in report

    def test_extern_profile_renders_no_raw_error_messages(self, scan_result):
        """ADR-0011 locking test (legal delta review 27.07.2026, Auflage 1):
        under EXTERN neither the new 'Fehlermeldung' table column nor any
        other render site may leak the raw exception text — apply_profile
        strips error_messages before build_report_context runs."""
        from nis2scan.reporting.pseudonymize import ReportProfile

        error_entry = next(e for e in scan_result.check_outcomes if e.outcome == CheckOutcome.ERROR)
        error_entry.error_messages = ["Unable to locate credentials for arn:aws:iam::123456789012:role/x"]

        report = render_report(scan_result, ReportProfile.EXTERN)

        assert "Unable to locate credentials" not in report
        # The errored check itself stays visible (ADR-0016) — only the raw
        # message is stripped; the internal result object is untouched.
        assert "Nicht ausgewertete Checks (Fehler)" in report
        assert error_entry.error_messages != []

    def test_extern_profile_renders_no_most_common_error_sentence(self):
        """ADR-0011 locking test (Auflage 1, second render site): even for an
        inconclusive scan the 'Häufigste Fehlermeldung' sentence must not
        appear under EXTERN — the raw message may embed identifiers no
        finding names."""
        from nis2scan.engine.models.config import CompanyInfo, ScanConfig
        from nis2scan.engine.models.result import CheckOutcomeEntry, ScanResult
        from nis2scan.engine.scanner import build_summary
        from nis2scan.reporting.pseudonymize import ReportProfile

        entries = [
            CheckOutcomeEntry(
                check_id="AWS-NR1-001",
                bsig_30_nr=1,
                outcome=CheckOutcome.ERROR,
                error_count=1,
                error_messages=["Unable to locate credentials"],
            ),
        ]
        result = ScanResult(
            scan_id="test-scan-inconclusive-extern",
            config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
            summary=build_summary([], [1], entries),
            findings=[],
            check_outcomes=entries,
        )

        report = render_report(result, ReportProfile.EXTERN)

        assert "Häufigste Fehlermeldung" not in report
        assert "Unable to locate credentials" not in report

    def test_most_common_error_message_sentence_absent_when_a_check_passed(self, scan_result):
        # scan_result has one PASSED, one FAILED and one ERROR entry — not
        # inconclusive, so the extra sentence must not appear (it would
        # falsely suggest the whole scan produced nothing usable) even though
        # an error message IS present.
        error_entry = next(e for e in scan_result.check_outcomes if e.outcome == CheckOutcome.ERROR)
        error_entry.error_messages = ["Unable to locate credentials"]

        report = render_report(scan_result)

        assert "Häufigste Fehlermeldung" not in report


class TestAttestierungAndPruefgrenzen:
    def test_attestation_checklist_per_scanned_area(self, scan_result):
        report = render_report(scan_result)

        assert "Attestierungs-Checkliste" in report
        # scanned areas 1, 2, 8 appear with their manual evidence items
        assert "Risikoanalyse-Verfahren ist dokumentiert" in report
        assert "Incident-Response-Plan ist dokumentiert" in report
        assert "Kryptokonzept ist dokumentiert" in report
        assert "- [ ]" in report

    def test_coverage_text_shown_per_area(self, scan_result):
        report = render_report(scan_result)

        assert "Automatisiert geprüfter Teilaspekt" in report
        assert "kein Nachweis" in report  # Nr. 1: Indiz, kein Nachweis

    def test_pruefgrenzen_printed_next_to_result(self, scan_result):
        report = render_report(scan_result)

        assert "Prüfgrenzen der Checks" in report
        assert "Prüft nur den Recorder-Status" in report

    def test_undocumented_pruefgrenzen_counted_honestly(self, scan_result):
        report = render_report(scan_result)

        # 2 of 3 entries have no declared limitations — the gap is stated, not hidden
        assert "2 Check(s) sind noch keine expliziten Prüfgrenzen dokumentiert" in report
