"""Regression tests for the CLI fail-safe hotfix (audit 24.07.2026).

Covers four verified findings, all in nis2scan/cli/cli.py:

1. --profile shadowing: the AWS CLI profile name must reach
   ProviderConfig.profile unchanged, and independently of the report-profile
   (--report-profile) value used for JSON/Markdown export.
2. Exit code 3 when a scan is inconclusive (every applicable check errored,
   none passed, none failed) plus a warning line whenever any check errored.
3. Unknown --provider values must abort with exit 1 and a German message,
   for both `scan` and `permissions`.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import nis2scan.cli.cli as cli_module
from nis2scan.cli.cli import app
from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.models.result import ComplianceSummary, ScanResult
from nis2scan.reporting.pseudonymize import ReportProfile

runner = CliRunner()


class TestProfileShadowingFix:
    """Bug 1 (P0): `profile` (AWS CLI profile) must never be overwritten by
    the parsed --report-profile enum. The two are independent CLI inputs."""

    def test_aws_profile_reaches_provider_config_and_report_profile_is_separate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            captured["provider_config"] = config.providers["aws"]
            return ScanResult(scan_id="test-scan", config=config)

        def _fake_export_json(result: ScanResult, out_dir: Path, profile: ReportProfile) -> Path:
            captured["json_profile"] = profile
            return out_dir / "fake.json"

        def _fake_export_markdown(result: ScanResult, out_dir: Path, profile: ReportProfile) -> Path:
            captured["markdown_profile"] = profile
            return out_dir / "fake.md"

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)
        monkeypatch.setattr(cli_module, "export_json", _fake_export_json)
        monkeypatch.setattr(cli_module, "export_markdown", _fake_export_markdown)

        result = runner.invoke(
            app,
            [
                "scan",
                "--provider",
                "aws",
                "--profile",
                "my-aws-profile",
                "--report-profile",
                "extern",
                "--output",
                str(tmp_path),
                "--format",
                "json",
                "--format",
                "markdown",
            ],
        )

        assert result.exit_code == 0, result.output
        provider_config = captured["provider_config"]
        assert isinstance(provider_config, ProviderConfig)
        assert provider_config.profile == "my-aws-profile"
        assert captured["json_profile"] == ReportProfile.EXTERN
        assert captured["markdown_profile"] == ReportProfile.EXTERN

    def test_without_profile_flag_provider_config_profile_is_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            captured["provider_config"] = config.providers["aws"]
            return ScanResult(scan_id="test-scan", config=config)

        def _fake_export_json(result: ScanResult, out_dir: Path, profile: ReportProfile) -> Path:
            captured["json_profile"] = profile
            return out_dir / "fake.json"

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)
        monkeypatch.setattr(cli_module, "export_json", _fake_export_json)

        result = runner.invoke(
            app,
            ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"],
        )

        assert result.exit_code == 0, result.output
        provider_config = captured["provider_config"]
        assert isinstance(provider_config, ProviderConfig)
        assert provider_config.profile is None
        # Default --report-profile is "intern".
        assert captured["json_profile"] == ReportProfile.INTERN


class TestExitCodeInconclusiveScan:
    """Bug 2: exit 3 + German abort message when nothing could be evaluated;
    a general yellow warning whenever any check errored, regardless of the
    resulting exit code."""

    def test_all_checks_errored_exits_3_with_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        summary = ComplianceSummary(total_checks=3, passed_checks=0, failed_checks=0, error_checks=3)

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return ScanResult(scan_id="test-scan", config=config, summary=summary)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 3, result.output
        # Rich wraps long lines at the CliRunner's console width, so normalize
        # whitespace before matching the (single logical) message.
        flat_output = " ".join(result.output.split())
        assert "Scan nicht aussagekräftig: 3 Checks mit Fehlern, kein Check erfolgreich ausgewertet." in flat_output

    def test_partial_errors_keep_severity_based_exit_code_but_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 1 check passed, 2 errored, 0 failed -> not inconclusive (something
        # was actually evaluated), so the normal severity-based exit (0, no
        # findings at all here) applies, but the generic error warning fires.
        summary = ComplianceSummary(total_checks=3, passed_checks=1, failed_checks=0, error_checks=2)

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return ScanResult(scan_id="test-scan", config=config, summary=summary)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 0, result.output
        # The error count is surfaced by _print_summary; the exit-3 message
        # must not appear because a PASSED check exists.
        assert "Scan nicht aussagekräftig" not in result.output

    def test_failed_check_present_is_not_treated_as_inconclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A genuine FAILED check (a real defect was found) is meaningful even
        # if other checks errored — must NOT be masked by exit 3.
        summary = ComplianceSummary(
            total_checks=3, passed_checks=0, failed_checks=1, error_checks=2, critical_count=1, total_findings=1
        )

        async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
            return ScanResult(scan_id="test-scan", config=config, summary=summary)

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 2, result.output  # critical_count > 0
        assert "Scan nicht aussagekräftig" not in result.output


class TestProviderValidation:
    """Bug 3: unknown --provider values must abort loudly instead of
    silently registering zero checks and producing an empty 0/0 report.

    Exit code 64 (EX_USAGE) since the hardening audit 27.07.2026: an unknown
    --provider is a usage/configuration error, not a scan outcome — it must
    not be confused with the severity-based exit codes 0-3.
    """

    def test_scan_unknown_provider_exits_64(self) -> None:
        result = runner.invoke(app, ["scan", "--provider", "awss"])

        assert result.exit_code == 64
        assert "Unbekannter Provider: awss. Erlaubt: aws, azure, gcp" in result.output

    def test_permissions_unknown_provider_exits_64(self) -> None:
        result = runner.invoke(app, ["permissions", "--provider", "awss"])

        assert result.exit_code == 64
        assert "Unbekannter Provider: awss. Erlaubt: aws, azure, gcp" in result.output

    @pytest.mark.parametrize("provider", ["aws", "AWS", "azure", "AZURE", "gcp", "GCP"])
    def test_permissions_valid_providers_case_insensitive(self, provider: str) -> None:
        result = runner.invoke(app, ["permissions", "--provider", provider])

        assert result.exit_code == 0, result.output
        assert "Unbekannter Provider" not in result.output
