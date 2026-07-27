"""Engine-level integration tests for Findings-Exceptions (ADR-0026).

Verifies run_scan itself applies exceptions_path end-to-end — engine-side
annotation (not report-only), so JSON/Markdown/PDF/SaaS all share the same
exception view (ADR-0026 consequence).
"""

import asyncio
from pathlib import Path

import pytest

from nis2scan.engine.finding_exceptions import ExceptionsFileError
from nis2scan.engine.models.check import BaseCheck, CheckResult
from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingStatus, Severity
from nis2scan.engine.registry import CheckRegistry
from nis2scan.engine.scanner import run_scan

RESOURCE_ID = "arn:aws:iam::123456789012:user/alice"


class _FakeNonCompliantCheck(BaseCheck):
    """Minimal fake check emitting one hardcoded defect — no cloud SDK calls."""

    check_id = "TST-NR9-001"
    title = "Testcheck"
    description = "Testbeschreibung"
    bsig_30_nr = 9
    provider = CloudProvider.AWS
    required_permissions: list[str] = []

    async def execute(self, session: object) -> CheckResult:
        finding = Finding(
            check_id=self.check_id,
            status=FindingStatus.NON_COMPLIANT,
            title="IAM-Benutzer ohne MFA",
            description="Testbeschreibung",
            bsig_30_nr=self.bsig_30_nr,
            bsig_30_text="§30 Abs. 2 Nr. 9 BSIG",
            severity=Severity.HIGH,
            provider=self.provider,
            region="eu-central-1",
            resource_id=RESOURCE_ID,
            resource_type="AWS::IAM::User",
            account_id="123456789012",
            expected_state="MFA aktiviert",
            remediation="MFA aktivieren",
            remediation_effort="LOW",
        )
        return CheckResult(check_id=self.check_id, findings=[finding])


@pytest.fixture(autouse=True)
def _clean_registry():
    CheckRegistry.reset()
    yield
    CheckRegistry.reset()


def _scan_config(exceptions_path: str | None = None) -> ScanConfig:
    return ScanConfig(
        providers={"aws": ProviderConfig(enabled=True, regions=["eu-central-1"])},
        bsig_30_scope=[9],
        exceptions_path=exceptions_path,
    )


def _write_exceptions_file(tmp_path: Path, expires: str = "2099-01-01") -> Path:
    path = tmp_path / "exceptions.yaml"
    path.write_text(
        "exceptions:\n"
        "  - check_id: TST-NR9-001\n"
        f"    resource_id: {RESOURCE_ID}\n"
        "    reason: Akzeptiertes Risiko, Ticket SEC-42\n"
        f"    expires: {expires}\n",
        encoding="utf-8",
    )
    return path


def test_scan_without_exceptions_path_leaves_findings_unannotated():
    CheckRegistry.get_instance().register(_FakeNonCompliantCheck())

    result = asyncio.run(run_scan(_scan_config()))

    assert result.findings[0].exception is None
    assert result.summary.exceptions_accepted_count == 0
    assert result.metadata.exceptions_file is None
    assert result.metadata.exceptions_applied == 0


def test_scan_with_active_exception_annotates_finding_and_metadata(tmp_path: Path):
    CheckRegistry.get_instance().register(_FakeNonCompliantCheck())
    exceptions_file = _write_exceptions_file(tmp_path)

    result = asyncio.run(run_scan(_scan_config(str(exceptions_file))))

    finding = result.findings[0]
    assert finding.exception is not None
    assert finding.exception.reason == "Akzeptiertes Risiko, Ticket SEC-42"

    # The defect still counts fully in the primary Mängel numbers (ADR-0026
    # decision 4: no silent Herausrechnung) — plus the additive second track.
    assert result.summary.total_findings == 1
    assert result.summary.exceptions_accepted_count == 1

    # F3b (legal review): only the FILENAME is stored — a full local path
    # often contains the operator's user name and must not enter the JSON.
    assert result.metadata.exceptions_file == "exceptions.yaml"
    assert result.metadata.exceptions_applied == 1
    assert result.metadata.exceptions_expired == 0


def test_scan_with_expired_exception_counts_finding_as_fully_open(tmp_path: Path):
    CheckRegistry.get_instance().register(_FakeNonCompliantCheck())
    exceptions_file = _write_exceptions_file(tmp_path, expires="2000-01-01")

    result = asyncio.run(run_scan(_scan_config(str(exceptions_file))))

    finding = result.findings[0]
    assert finding.exception is None
    assert finding.expired_exception is not None

    assert result.summary.exceptions_accepted_count == 0
    assert result.metadata.exceptions_applied == 0
    assert result.metadata.exceptions_expired == 1


def test_broken_exceptions_file_aborts_scan(tmp_path: Path):
    CheckRegistry.get_instance().register(_FakeNonCompliantCheck())
    path = tmp_path / "exceptions.yaml"
    path.write_text("exceptions:\n  - check_id: TST-NR9-001\n", encoding="utf-8")  # missing resource_id/reason/expires

    with pytest.raises(ExceptionsFileError):
        asyncio.run(run_scan(_scan_config(str(path))))


def test_broken_exceptions_file_aborts_before_any_check_runs(tmp_path: Path):
    """Exit-64 invariant (legal delta review 27.07.2026, Auflage 2): a broken
    exceptions file must abort the scan BEFORE the first cloud call. Loading
    used to happen only after the full check loop — a file that broke between
    CLI preflight and engine load burned the entire scan before failing."""
    executed: list[str] = []

    class _RecordingCheck(_FakeNonCompliantCheck):
        async def execute(self, session: object) -> CheckResult:
            executed.append(self.check_id)
            return await super().execute(session)

    CheckRegistry.get_instance().register(_RecordingCheck())
    broken = tmp_path / "exceptions.yaml"
    broken.write_text("exceptions:\n  - check_id: TST-NR9-001\n", encoding="utf-8")  # missing required fields

    with pytest.raises(ExceptionsFileError):
        asyncio.run(run_scan(_scan_config(str(broken))))

    assert executed == []
