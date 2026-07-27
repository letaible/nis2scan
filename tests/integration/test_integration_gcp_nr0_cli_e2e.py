"""CLI-E2E integration tests (GCP) — installed-wheel customer journeys against real infra.

Testpyramide Stufe "CLI-E2E gegen echte Infra" (Gruender-Go 27.07.2026, CLAUDE.md
"Test-Strategie"). See test_integration_nr0_cli_e2e.py (AWS) for the full rationale —
this file mirrors it for GCP and intentionally omits the exceptions.yaml flow
(AWS-only per the founder's go-ahead).

Filename note: named ``test_integration_gcp_nr0_cli_e2e.py`` so it matches the GCP
workflow's existing collection glob ``tests/integration/test_integration_gcp_*.py``
(see .github/workflows/integration-tests-gcp.yml, "Run GCP Integration Tests" step).

Gate: every test skips (never errors) whenever NIS2SCAN_E2E_BIN is unset — see the
``e2e_bin`` fixture docstring below.
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

# Task #54 (GCP-Portierung des AWS-Musters): this file runs in ALL THREE GCP
# scenarios (see infra/gcp/variables.tf::scenario), unlike the rest of this
# package which is fixed to "gaps" (tests/integration/conftest.py::
# SKIP_UNLESS_GAPS_SCENARIO). Its assertions are already scenario-tolerant
# EXCEPT the "at least one non_compliant finding" check below, which does not
# hold in "hardened" (every supported Terraform-fixture gap is closed there).
_SCENARIO = os.environ.get("NIS2SCAN_SCENARIO", "gaps")

_TIMEOUT_FULL_SCAN = 900


@pytest.fixture(scope="module")
def e2e_bin() -> str:
    """Path to the wheel-installed nis2scan console script.

    Set only by the CI "CLI-E2E (Wheel)" step. Missing means either a local dev
    run (no wheel built) or the ordinary integration pytest step running this
    file incidentally (it matches the gcp_* glob but never sets this variable) —
    either way the correct behaviour is SKIP, not ERROR or FAIL.
    """
    bin_path = os.environ.get("NIS2SCAN_E2E_BIN")
    if not bin_path:
        pytest.skip("NIS2SCAN_E2E_BIN not set — CLI-E2E test skipped (no wheel build in this run)")
    return bin_path


@pytest.fixture(scope="module")
def gcp_project_id(e2e_bin: str) -> str:
    """Real GCP project id — prefer GCP_PROJECT_ID (set by the workflow), fall
    back to google.auth.default() (ADC) — the needle the pseudonymization
    canary searches for in the EXTERN report."""
    project_id = os.environ.get("GCP_PROJECT_ID")
    if project_id:
        return project_id

    try:
        import google.auth  # type: ignore[import-untyped]

        _, default_project_id = google.auth.default()
    except Exception as exc:  # noqa: BLE001 - environment-dependent ADC failure, not a bug to narrow
        pytest.skip(f"No GCP project id determinable (neither GCP_PROJECT_ID nor ADC available): {exc}")

    if not default_project_id:
        pytest.skip("google.auth.default() returned no project id — pseudonymization canary skipped")
    return str(default_project_id)


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
    """Run the primary customer journey scan once, shared by the structure test below."""
    output_dir = tmp_path_factory.mktemp("gcp_nr0_intern")
    proc = _run_cli(
        e2e_bin,
        ["--provider", "gcp", "--output", str(output_dir), "--format", "json"],
        timeout=_TIMEOUT_FULL_SCAN,
    )
    report = _load_single_report(output_dir)
    return {"proc": proc, "report": report}


@pytest.mark.integration
class TestGcpCliE2EScanJourney:
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

        if _SCENARIO == "hardened":
            # Every supported Terraform-fixture gap is closed in "hardened" —
            # "at least one non_compliant finding" is no longer guaranteed
            # project-wide (Task #54). Assert the mirror image instead: the
            # scan must still produce positive (COMPLIANT) evidence.
            compliant = [f for f in findings if f["status"] == "compliant"]
            assert compliant, "Expected at least one compliant finding in the 'hardened' scenario"
        else:
            non_compliant = [f for f in findings if f["status"] == "non_compliant"]
            assert non_compliant, "Expected at least one non_compliant finding from the Terraform test infrastructure"

        outcomes = report["check_outcomes"]
        assert outcomes, "check_outcomes must not be empty (ADR-0007: every check must stay visible)"
        assert len(outcomes) == report["summary"]["total_checks"]

        error_outcomes = [co for co in outcomes if co["outcome"] == "error"]
        # CI test-project permissions are never 100% complete — a small error
        # share is tolerated here. NOT a hard zero-assert: that needs a
        # dedicated permissions-whitelist package, not built yet (planned).
        error_ratio = len(error_outcomes) / len(outcomes)
        assert error_ratio <= 0.35, (
            f"Too many errored checks: {len(error_outcomes)}/{len(outcomes)} ({error_ratio:.0%}) "
            "— check environment permissions."
        )


@pytest.mark.integration
class TestGcpCliE2EPseudonymizationCanary:
    """c) --report-profile extern must never leak the real project id (ADR-0011)."""

    def test_extern_profile_scrubs_project_id_and_error_messages(
        self,
        e2e_bin: str,
        gcp_project_id: str,
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        output_dir = tmp_path_factory.mktemp("gcp_nr0_extern")
        proc = _run_cli(
            e2e_bin,
            ["--provider", "gcp", "--output", str(output_dir), "--format", "json", "--report-profile", "extern"],
            timeout=_TIMEOUT_FULL_SCAN,
            env_overrides={"NIS2SCAN_SECRET": "cli-e2e-canary-secret-not-a-real-secret"},
        )
        assert proc.returncode in (0, 1, 2), f"Unexpected exit code {proc.returncode}. stderr:\n{proc.stderr}"
        _assert_no_traceback(proc)

        report = _load_single_report(output_dir)
        assert report["report_profile"] == "extern"

        raw_json_text = json.dumps(report)
        assert gcp_project_id not in raw_json_text, (
            f"Project id {gcp_project_id} is visible in the EXTERN report — pseudonymization (ADR-0011) is broken."
        )
        for outcome in report["check_outcomes"]:
            assert outcome["error_messages"] == [], (
                "EXTERN profile must never carry raw error_messages (they may embed identifiers, "
                "see reporting/pseudonymize.py)."
            )
