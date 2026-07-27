"""CLI tests for the credential-error hint block (Fix 2, hardening audit 27.07.2026).

Before this, a scan that failed because of missing/broken cloud credentials
only ever printed an opaque "N Checks mit Fehlern" — the actual boto3/
azure-identity/google-auth exception text never reached the console, so
users could not self-serve the fix (confirmed for AWS: no explanation at
all; Azure: an English wall of 51 raw tracebacks with no summary).
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import nis2scan.cli.cli as cli_module
from nis2scan.cli.cli import app
from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.result import CheckOutcomeEntry, ComplianceSummary, ScanResult

runner = CliRunner()


def _inconclusive_result(config: ScanConfig, entries: list[CheckOutcomeEntry]) -> ScanResult:
    summary = ComplianceSummary(
        total_checks=len(entries),
        passed_checks=0,
        failed_checks=0,
        error_checks=len(entries),
    )
    return ScanResult(scan_id="test-scan", config=config, summary=summary, check_outcomes=entries)


def _error_entries(count: int, message: str) -> list[CheckOutcomeEntry]:
    return [
        CheckOutcomeEntry(
            check_id=f"AWS-NR{i}-001",
            bsig_30_nr=(i % 10) + 1,
            outcome=CheckOutcome.ERROR,
            error_count=1,
            error_messages=[message],
        )
        for i in range(count)
    ]


class TestCredentialHintAws:
    def test_missing_aws_credentials_shows_german_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        entries = _error_entries(52, "Unable to locate credentials")

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 3, result.output
        flat_output = " ".join(result.output.split())
        assert "AWS-Zugangsdaten" in flat_output
        assert "aws configure" in flat_output
        assert "nis2scan permissions --provider aws" in flat_output

    def test_no_credentials_error_type_also_triggers_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        entries = _error_entries(3, "botocore.exceptions.NoCredentialsError raised")

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        flat_output = " ".join(result.output.split())
        assert "AWS-Zugangsdaten" in flat_output


class TestCredentialHintAzure:
    def test_missing_azure_credentials_shows_german_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        entries = _error_entries(51, "DefaultAzureCredential failed to retrieve a token from the included credentials.")

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_azure_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "azure", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 3, result.output
        flat_output = " ".join(result.output.split())
        assert "Azure-Zugangsdaten" in flat_output
        assert "az login" in flat_output


class TestCredentialHintGcp:
    def test_missing_gcp_credentials_shows_german_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        entries = _error_entries(
            5,
            "Your default credentials were not found. To set up Application Default Credentials, "
            "see https://cloud.google.com/docs/authentication/external/set-up-adc for more information.",
        )

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_gcp_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "gcp", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 3, result.output
        flat_output = " ".join(result.output.split())
        assert "GCP-Zugangsdaten" in flat_output
        assert "gcloud auth application-default login" in flat_output


class TestCredentialHintFallback:
    def test_unrecognized_error_shows_generic_hint_with_most_common_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        entries = _error_entries(4, "AccessDenied: user is not authorized to perform this action") + _error_entries(
            1, "Some other error"
        )

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        flat_output = " ".join(result.output.split())
        assert "AccessDenied: user is not authorized to perform this action" in flat_output
        assert "nis2scan permissions --provider aws" in flat_output

    def test_no_hint_block_without_any_error_messages(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        # error_count > 0 but error_messages empty (e.g. an EXTERN-profile
        # scenario) — nothing to show, must not crash or print an empty hint.
        entries = [
            CheckOutcomeEntry(check_id="AWS-NR1-001", bsig_30_nr=1, outcome=CheckOutcome.ERROR, error_count=1)
        ] * 3

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return _inconclusive_result(config, entries)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 3, result.output
        assert "Hinweis:" not in result.output

    def test_no_hint_block_without_any_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return ScanResult(
                scan_id="test-scan", config=config, summary=ComplianceSummary(total_checks=1, passed_checks=1)
            )

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 0, result.output
        assert "Hinweis:" not in result.output
