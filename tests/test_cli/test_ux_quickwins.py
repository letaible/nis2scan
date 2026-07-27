"""CLI UX quick-win regression tests (Fix 5, hardening audit 27.07.2026).

5a: the scan banner's "Regionen: ..." line is AWS-specific (Azure/GCP scan a
subscription/project, not a region list) and must not appear for them.
5c: --help texts must not reference internal ADR numbers customers cannot
look up.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import nis2scan.cli.cli as cli_module
from nis2scan.cli.cli import app
from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.result import ScanResult

runner = CliRunner()


def _stub_scan(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    async def _fake_run_scan(config: ScanConfig, event_bus: object = None) -> ScanResult:
        return ScanResult(scan_id="test-scan", config=config)

    monkeypatch.setattr(cli_module, f"register_all_{provider}_checks", lambda: None)
    monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)


class TestBannerRegionDisplay:
    def test_aws_banner_shows_regions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_scan(monkeypatch, "aws")

        result = runner.invoke(
            app, ["scan", "--provider", "aws", "--output", str(tmp_path), "--region", "eu-central-1"]
        )

        assert result.exit_code == 0, result.output
        assert "Regionen: eu-central-1" in " ".join(result.output.split())

    def test_azure_banner_omits_regions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_scan(monkeypatch, "azure")

        result = runner.invoke(app, ["scan", "--provider", "azure", "--output", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert "Regionen:" not in result.output

    def test_gcp_banner_omits_regions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _stub_scan(monkeypatch, "gcp")

        result = runner.invoke(app, ["scan", "--provider", "gcp", "--output", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert "Regionen:" not in result.output


class TestHelpTextsHaveNoAdrReferences:
    def test_scan_help_has_no_adr_reference(self):
        result = runner.invoke(app, ["scan", "--help"])

        assert result.exit_code == 0
        assert "ADR" not in result.output

    def test_report_profile_help_still_explains_intern_extern(self):
        result = runner.invoke(app, ["scan", "--help"])

        flat_output = " ".join(result.output.split())
        assert "intern" in flat_output
        assert "extern" in flat_output
        assert "pseudonymisiert" in flat_output
