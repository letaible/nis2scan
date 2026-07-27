"""CLI-E2E integration tests (AWS) — installed-wheel customer journeys against real infra.

Testpyramide Stufe "CLI-E2E gegen echte Infra" (Gruender-Go 27.07.2026, CLAUDE.md
"Test-Strategie"): unlike every other file in this package, these tests never import
the engine directly — they shell out to the packaged CLI binary the same way a
customer who ran ``pip install nis2scan`` would, exercising cli.py itself (which the
rest of the integration suite and the SaaS worker never cover, see CLAUDE.md "Known
Pitfalls / CLI").

Filename note: this file is intentionally named ``test_integration_nr0_cli_e2e.py``
(NOT e.g. ``test_integration_cli_e2e.py``) so it matches the AWS workflow's existing
collection glob ``tests/integration/test_integration_nr*.py`` (see
.github/workflows/integration-tests-aws.yml, "Run Integration Tests" step). A file
named outside that pattern silently drops out of the release-gate run — this exact
pitfall previously hit test_integration_exceptions.py (CLAUDE.md "Known Pitfalls"),
which had to be listed explicitly because its name did not match.

Gate: every test skips (never errors) whenever NIS2SCAN_E2E_BIN is unset. This lets
the ordinary "Run Integration Tests" step (which does NOT set the variable) collect
and skip this file without breaking that step, while a dedicated new CI step
("CLI-E2E (Wheel)") builds a wheel, installs it into a fresh venv, points
NIS2SCAN_E2E_BIN at that venv's console script, and runs ONLY this file.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

_REGION = "eu-central-1"
# Full --scope 1-10 scans touch every AWS check across the account — generous
# budget so a slow region/API never flakes the job.
_TIMEOUT_FULL_SCAN = 900
# Scans narrowed to a single §30 area (the exceptions flow) are far cheaper.
_TIMEOUT_SCOPED_SCAN = 300


@pytest.fixture(scope="module")
def e2e_bin() -> str:
    """Path to the wheel-installed nis2scan console script.

    Set only by the CI "CLI-E2E (Wheel)" step. Missing means either a local dev
    run (no wheel built) or the ordinary integration pytest step running this
    file incidentally (it matches the nr* glob but never sets this variable) —
    either way the correct behaviour is SKIP, not ERROR or FAIL.
    """
    bin_path = os.environ.get("NIS2SCAN_E2E_BIN")
    if not bin_path:
        pytest.skip("NIS2SCAN_E2E_BIN not set — CLI-E2E test skipped (no wheel build in this run)")
    return bin_path


@pytest.fixture(scope="module")
def aws_account_id(e2e_bin: str) -> str:
    """Real AWS account id, fetched independently of the CLI (boto3 STS) — the
    needle the pseudonymization canary searches for in the EXTERN report."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        return boto3.client("sts").get_caller_identity()["Account"]
    except (BotoCoreError, ClientError) as exc:
        pytest.skip(f"No AWS credentials available for the pseudonymization canary: {exc}")


def _run_cli(
    bin_path: str,
    args: list[str],
    *,
    timeout: int,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke the installed nis2scan console script as a subprocess, UTF-8 forced
    (Windows dev pitfall, CLAUDE.md) regardless of the runner platform."""
    full_env = dict(os.environ)
    full_env["PYTHONUTF8"] = "1"
    full_env["PYTHONIOENCODING"] = "utf-8"
    if env_overrides:
        full_env.update(env_overrides)
    return subprocess.run(
        [bin_path, "scan", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=full_env,
        check=False,
    )


def _load_single_report(output_dir: Path) -> dict[str, Any]:
    reports = sorted(output_dir.glob("nis2scan_report_*.json"))
    assert len(reports) == 1, f"Expected exactly one JSON report in {output_dir}, found: {reports}"
    data: dict[str, Any] = json.loads(reports[0].read_text(encoding="utf-8"))
    return data


def _expected_exit_code(summary: dict[str, Any]) -> int:
    """Mirror the exit-code decision in nis2scan/cli/cli.py::scan from the JSON summary alone."""
    if summary["error_checks"] > 0 and summary["passed_checks"] == 0 and summary["failed_checks"] == 0:
        return 3
    if summary["critical_count"] > 0:
        return 2
    if summary["high_count"] > 0:
        return 1
    return 0


def _assert_no_traceback(proc: subprocess.CompletedProcess[str]) -> None:
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "Traceback (most recent call last)" not in combined, f"CLI traceback in output:\n{combined}"


@pytest.fixture(scope="module")
def intern_scan(e2e_bin: str, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run the primary customer journey scan once, shared by the structure and
    exceptions tests below (keeps the number of real-infra scans down)."""
    output_dir = tmp_path_factory.mktemp("nr0_intern")
    proc = _run_cli(
        e2e_bin,
        ["--provider", "aws", "--region", _REGION, "--output", str(output_dir), "--format", "json"],
        timeout=_TIMEOUT_FULL_SCAN,
    )
    report = _load_single_report(output_dir)
    return {"proc": proc, "report": report}


@pytest.mark.integration
class TestAwsCliE2EScanJourney:
    """a) + b): install wheel, scan real infra, get an audit-ready report."""

    def test_exit_code_is_valid_and_matches_severity(self, intern_scan: dict[str, Any]) -> None:
        proc: subprocess.CompletedProcess[str] = intern_scan["proc"]
        summary = intern_scan["report"]["summary"]

        assert proc.returncode in (0, 1, 2), (
            f"Unexpected exit code {proc.returncode} (0/1/2 expected; 3 = broken access, "
            f"64 = CLI usage bug). stderr:\n{proc.stderr}"
        )
        assert proc.returncode == _expected_exit_code(summary), (
            f"Exit code {proc.returncode} does not match the highest severity in the JSON "
            f"(critical={summary['critical_count']}, high={summary['high_count']})"
        )
        _assert_no_traceback(proc)

    def test_report_structure_is_audit_ready(self, intern_scan: dict[str, Any]) -> None:
        report = intern_scan["report"]

        assert report["schema_version"]
        findings = report["findings"]
        assert findings, "Expected at least one finding (deployed Terraform test gaps)"
        non_compliant = [f for f in findings if f["status"] == "non_compliant"]
        assert non_compliant, "Expected at least one non_compliant finding from the Terraform test infrastructure"

        outcomes = report["check_outcomes"]
        assert outcomes, "check_outcomes must not be empty (ADR-0007: every check must stay visible)"
        assert len(outcomes) == report["summary"]["total_checks"]

        error_outcomes = [co for co in outcomes if co["outcome"] == "error"]
        # CI test-account permissions are never 100% complete (e.g. an optional
        # read permission missing from the Terraform IAM role) — a small error
        # share is tolerated here. NOT a hard zero-assert: that needs a
        # dedicated permissions-whitelist package, not built yet (planned).
        error_ratio = len(error_outcomes) / len(outcomes)
        assert error_ratio <= 0.35, (
            f"Too many errored checks: {len(error_outcomes)}/{len(outcomes)} ({error_ratio:.0%}) "
            "— check environment permissions."
        )


@pytest.mark.integration
class TestAwsCliE2EPseudonymizationCanary:
    """c) --report-profile extern must never leak the real account id (ADR-0011)."""

    def test_extern_profile_scrubs_account_id_and_error_messages(
        self,
        e2e_bin: str,
        aws_account_id: str,
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        output_dir = tmp_path_factory.mktemp("nr0_extern")
        proc = _run_cli(
            e2e_bin,
            [
                "--provider",
                "aws",
                "--region",
                _REGION,
                "--output",
                str(output_dir),
                "--format",
                "json",
                "--report-profile",
                "extern",
            ],
            timeout=_TIMEOUT_FULL_SCAN,
            env_overrides={"NIS2SCAN_SECRET": "cli-e2e-canary-secret-not-a-real-secret"},
        )
        assert proc.returncode in (0, 1, 2), f"Unexpected exit code {proc.returncode}. stderr:\n{proc.stderr}"
        _assert_no_traceback(proc)

        report = _load_single_report(output_dir)
        assert report["report_profile"] == "extern"

        raw_json_text = json.dumps(report)
        assert aws_account_id not in raw_json_text, (
            f"Account id {aws_account_id} is visible in the EXTERN report — pseudonymization (ADR-0011) is broken."
        )
        for outcome in report["check_outcomes"]:
            assert outcome["error_messages"] == [], (
                "EXTERN profile must never carry raw error_messages (they may embed identifiers, "
                "see reporting/pseudonymize.py)."
            )


@pytest.mark.integration
class TestAwsCliE2EExceptionsJourney:
    """d) AWS-only hardening journey (ADR-0026): accept a documented defect, then
    let the exception lapse — the full customer-facing exceptions.yaml workflow."""

    def test_exceptions_flow_active_then_expired(
        self,
        e2e_bin: str,
        intern_scan: dict[str, Any],
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        non_compliant = [f for f in intern_scan["report"]["findings"] if f["status"] == "non_compliant"]
        assert non_compliant  # already asserted in test_report_structure_is_audit_ready; re-guard for -k runs
        # Deterministic pick so repeated runs target the same finding.
        target = sorted(non_compliant, key=lambda f: (f["check_id"], f["resource_id"]))[0]
        scope = str(target["bsig_30_nr"])

        # Baseline at the SAME --scope (no --exceptions) — the fair comparison
        # value for "summary.total_findings stays unchanged" below. The full
        # 1-10 scan above cannot serve as that baseline: its total_findings
        # spans all areas, not just the one area we are about to except.
        baseline_dir = tmp_path_factory.mktemp("nr0_exc_baseline")
        baseline_proc = _run_cli(
            e2e_bin,
            [
                "--provider",
                "aws",
                "--region",
                _REGION,
                "--scope",
                scope,
                "--output",
                str(baseline_dir),
                "--format",
                "json",
            ],
            timeout=_TIMEOUT_SCOPED_SCAN,
        )
        assert baseline_proc.returncode in (0, 1, 2), f"stderr:\n{baseline_proc.stderr}"
        baseline_total = _load_single_report(baseline_dir)["summary"]["total_findings"]

        exceptions_dir = tmp_path_factory.mktemp("nr0_exc_active")
        active_exceptions_file = exceptions_dir / "exceptions.yaml"
        active_exceptions_file.write_text(
            "exceptions:\n"
            f"  - check_id: {target['check_id']}\n"
            f"    resource_id: {target['resource_id']}\n"
            "    reason: CLI-E2E hardening journey — documented test exception (Gruender-Go 27.07.2026)\n"
            "    author: cli-e2e-test\n"
            "    expires: 2099-01-01\n",
            encoding="utf-8",
        )
        active_out = exceptions_dir / "out"
        active_proc = _run_cli(
            e2e_bin,
            [
                "--provider",
                "aws",
                "--region",
                _REGION,
                "--scope",
                scope,
                "--output",
                str(active_out),
                "--format",
                "json",
                "--exceptions",
                str(active_exceptions_file),
            ],
            timeout=_TIMEOUT_SCOPED_SCAN,
        )
        assert active_proc.returncode in (0, 1, 2), f"stderr:\n{active_proc.stderr}"
        _assert_no_traceback(active_proc)
        active_report = _load_single_report(active_out)

        assert active_report["metadata"]["exceptions_applied"] >= 1
        assert active_report["summary"]["exceptions_accepted_count"] >= 1
        # ADR-0026 decision 4: an accepted exception is a purely additive
        # second-track disclosure — it must NEVER shrink the primary Mängel count.
        assert active_report["summary"]["total_findings"] == baseline_total

        # Let the exception lapse: same rule, expiry in the past.
        expired_exceptions_file = exceptions_dir / "exceptions_expired.yaml"
        expired_exceptions_file.write_text(
            "exceptions:\n"
            f"  - check_id: {target['check_id']}\n"
            f"    resource_id: {target['resource_id']}\n"
            "    reason: CLI-E2E hardening journey — expired test exception (Gruender-Go 27.07.2026)\n"
            "    author: cli-e2e-test\n"
            "    expires: 2000-01-01\n",
            encoding="utf-8",
        )
        expired_out = exceptions_dir / "out_expired"
        expired_proc = _run_cli(
            e2e_bin,
            [
                "--provider",
                "aws",
                "--region",
                _REGION,
                "--scope",
                scope,
                "--output",
                str(expired_out),
                "--format",
                "json",
                "--exceptions",
                str(expired_exceptions_file),
            ],
            timeout=_TIMEOUT_SCOPED_SCAN,
        )
        assert expired_proc.returncode in (0, 1, 2), f"stderr:\n{expired_proc.stderr}"
        expired_report = _load_single_report(expired_out)

        assert expired_report["metadata"]["exceptions_expired"] >= 1
        assert expired_report["metadata"]["exceptions_applied"] == 0
