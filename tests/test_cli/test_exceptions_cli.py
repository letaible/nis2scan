"""CLI tests for --exceptions (ADR-0026): fail-safe abort on a broken file,
and the Wiedervorlage warning for long-running exceptions.

Exit code 64 (EX_USAGE) since the hardening audit 27.07.2026: a broken or
missing --exceptions file is a usage/configuration error, not a scan
outcome — it must not be confused with the severity-based exit codes 0-3.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import nis2scan.cli.cli as cli_module
from nis2scan.cli.cli import app
from nis2scan.engine.models.result import ScanResult

runner = CliRunner()


class TestExceptionsCliErrorPath:
    """A broken exceptions file must abort the scan (fail-safe) — never a
    silently-ignored file (ADR-0026). No scan/provider mocking is needed here:
    the CLI validates --exceptions eagerly, before registering checks or
    building the scan config."""

    def test_missing_required_field_aborts_with_german_message(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text(
            "exceptions:\n  - check_id: AWS-NR9-001\n",  # missing resource_id/reason/expires
            encoding="utf-8",
        )

        result = runner.invoke(app, ["scan", "--provider", "aws", "--exceptions", str(path)])

        assert result.exit_code == 64
        assert "Ausnahmen-Datei ungültig" in result.output

    def test_broken_yaml_aborts(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text("exceptions: [this is: not: valid: yaml", encoding="utf-8")

        result = runner.invoke(app, ["scan", "--provider", "aws", "--exceptions", str(path)])

        assert result.exit_code == 64
        assert "Ausnahmen-Datei ungültig" in result.output

    def test_missing_file_aborts(self, tmp_path: Path):
        result = runner.invoke(
            app, ["scan", "--provider", "aws", "--exceptions", str(tmp_path / "does-not-exist.yaml")]
        )

        assert result.exit_code == 64
        assert "nicht lesbar" in result.output


class TestExceptionsCliLongRunningWarning:
    def test_long_running_exception_warns_but_does_not_abort(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        # The scan itself is irrelevant here — only the --exceptions preflight
        # matters, so the real check registry/engine run is stubbed out to
        # keep this test fast and independent of any cloud SDK/credentials.
        async def _fake_run_scan(config: object, event_bus: object = None) -> ScanResult:
            return ScanResult(scan_id="test-scan", config=config)  # type: ignore[arg-type]

        monkeypatch.setattr(cli_module, "register_all_aws_checks", lambda: None)
        monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)
        monkeypatch.chdir(tmp_path)

        path = tmp_path / "exceptions.yaml"
        path.write_text(
            "exceptions:\n"
            "  - check_id: AWS-NR9-001\n"
            "    resource_id: arn:aws:iam::123456789012:user/alice\n"
            "    reason: Langfristig akzeptiertes Risiko\n"
            "    expires: 2099-01-01\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["scan", "--provider", "aws", "--exceptions", str(path), "--format", "json"])

        assert result.exit_code == 0, result.output
        # F4 (legal review): the warning measures REMAINING runtime from today.
        assert "läuft ab heute noch länger als 12 Monate" in result.output
