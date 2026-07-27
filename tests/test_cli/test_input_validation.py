"""CLI input-validation tests (Fix 3, hardening audit 27.07.2026).

Every validation covered here runs BEFORE the scan starts and aborts with
exit code 64 (EX_USAGE) plus a German message — replacing behaviour that
previously either crashed with a raw pydantic traceback (--scope), only
surfaced AFTER a full scan had already run (--output, --format), hung
silently for ~210s against a nonexistent AWS region (--region), or silently
ignored a user error altogether (missing --config file).

Each test that expects an abort also asserts run_scan was never invoked —
the whole point of moving validation earlier is that no scan work happens
for a doomed invocation.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import nis2scan.cli.cli as cli_module
from nis2scan.cli.cli import EX_USAGE, app
from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.result import ScanResult

runner = CliRunner()


def _fail_if_run_scan_called(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail(config: ScanConfig, event_bus: object = None) -> ScanResult:
        raise AssertionError("run_scan must not be called when input validation aborts the CLI")

    monkeypatch.setattr(cli_module, "run_scan", _fail)


def _succeed_run_scan(monkeypatch: pytest.MonkeyPatch, provider: str = "aws") -> None:
    async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
        return ScanResult(scan_id="test-scan", config=config)

    monkeypatch.setattr(cli_module, f"register_all_{provider}_checks", lambda: None)
    monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)


class TestScopeValidation:
    """Fix 3b: --scope outside 1-10 used to crash inside build_summary() with
    a raw pydantic ValidationError (ComplianceScore.bsig_30_nr is 1..10)."""

    def test_scope_above_range_aborts_with_exit_64(self, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--scope", "15"])

        assert result.exit_code == EX_USAGE, result.output
        assert "Ungültiger §30-Bereich: 15. Erlaubt sind 1 bis 10." in result.output

    def test_scope_zero_aborts_with_exit_64(self, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--scope", "0"])

        assert result.exit_code == EX_USAGE, result.output
        assert "Ungültiger §30-Bereich: 0. Erlaubt sind 1 bis 10." in result.output

    def test_valid_scope_passes_through(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)

        result = runner.invoke(
            app,
            ["scan", "--provider", "aws", "--scope", "1", "--scope", "10", "--output", str(tmp_path)],
        )

        assert result.exit_code == 0, result.output


class TestOutputPathValidation:
    """Fix 3c: --output pointing at an existing FILE used to crash AFTER the
    full scan had already run (out_path.mkdir raised FileExistsError),
    discarding the scan result."""

    def test_output_pointing_at_existing_file_aborts_with_exit_64(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        _fail_if_run_scan_called(monkeypatch)
        existing_file = tmp_path / "not-a-directory.txt"
        existing_file.write_text("some content", encoding="utf-8")

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(existing_file)])

        assert result.exit_code == EX_USAGE, result.output
        # Rich wraps long lines (here: a long temp-dir path) at the
        # CliRunner's console width, so normalize whitespace before matching.
        flat_output = " ".join(result.output.split())
        assert "ist eine Datei" in flat_output
        assert "Bitte ein Verzeichnis angeben" in flat_output

    def test_output_pointing_at_directory_passes_through(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)
        out_dir = tmp_path / "reports"

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(out_dir)])

        assert result.exit_code == 0, result.output


class TestFormatValidation:
    """Fix 3d: an invalid or Professional-only --format used to only be
    discovered AFTER the (potentially 80s+) scan had already completed, and
    for 'pdf' without the plugin no report was written at all despite the
    scan having succeeded."""

    def test_unknown_format_aborts_with_exit_64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "yaml"])

        assert result.exit_code == EX_USAGE, result.output
        assert "Unbekanntes Ausgabeformat: yaml" in result.output

    def test_pdf_without_premium_plugin_aborts_with_exit_64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "pdf"])

        assert result.exit_code == EX_USAGE, result.output
        assert "Professional" in result.output

    def test_valid_formats_pass_through(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--format", "json"])

        assert result.exit_code == 0, result.output


class TestConfigPathValidation:
    """Fix 3e: an explicitly given --config file that does not exist used to
    be silently ignored (_build_config's ``if config_file.exists():`` had no
    else branch) — the scan ran with defaults the user never intended,
    without any warning. The DEFAULT path staying silently missing is
    unchanged (most installs never create a config file)."""

    def test_explicit_missing_config_file_aborts_with_exit_64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)
        missing_config = tmp_path / "my-company.yaml"

        result = runner.invoke(
            app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--config", str(missing_config)]
        )

        assert result.exit_code == EX_USAGE, result.output
        # Rich may hard-wrap a long absolute temp-dir path at the CliRunner's
        # console width (no whitespace to break on, so it can split mid-word)
        # — assert the filename, not the full path, to stay robust to that.
        assert "Konfigurationsdatei nicht gefunden" in result.output
        assert missing_config.name in result.output

    def test_default_config_missing_is_silently_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)
        monkeypatch.chdir(tmp_path)  # config/default.yaml certainly doesn't exist here

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert "Konfigurationsdatei nicht gefunden" not in result.output

    def test_explicit_existing_config_file_passes_through(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)
        config_path = tmp_path / "my-company.yaml"
        config_path.write_text("company:\n  name: Testfirma GmbH\n", encoding="utf-8")

        result = runner.invoke(
            app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--config", str(config_path)]
        )

        assert result.exit_code == 0, result.output


class TestAwsRegionValidation:
    """Fix 3a: an unknown AWS region used to be silently accepted, boto3 then
    retried against it for ~210s, and a report would have claimed a
    fictitious region was scanned."""

    def test_unknown_region_aborts_with_exit_64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(
            app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--region", "mars-central-7"]
        )

        assert result.exit_code == EX_USAGE, result.output
        assert "Unbekannte AWS-Region: mars-central-7" in result.output
        assert "us-east-1" in result.output
        assert "eu-central-1" in result.output
        assert "ap-southeast-1" in result.output

    def test_valid_region_passes_through(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _succeed_run_scan(monkeypatch)

        result = runner.invoke(app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--region", "us-west-2"])

        assert result.exit_code == 0, result.output

    def test_region_validation_skipped_for_non_aws_providers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        # --region has no meaning for azure/gcp (they scan a subscription/
        # project, not a region list) — an AWS-only region name must not
        # abort a non-AWS scan.
        _succeed_run_scan(monkeypatch, provider="azure")

        result = runner.invoke(
            app,
            ["scan", "--provider", "azure", "--output", str(tmp_path), "--region", "not-an-aws-region-at-all"],
        )

        assert result.exit_code == 0, result.output


class TestReportProfileAndProviderExitCode:
    """Fix 3f: usage errors that were already German-correct only needed
    their exit code moved from 1 to 64."""

    def test_invalid_report_profile_exits_64(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _fail_if_run_scan_called(monkeypatch)

        result = runner.invoke(
            app,
            ["scan", "--provider", "aws", "--output", str(tmp_path), "--report-profile", "geheim"],
        )

        assert result.exit_code == EX_USAGE, result.output
        assert "Ungültiges Report-Profil: geheim" in result.output
