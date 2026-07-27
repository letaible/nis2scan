"""Journeys (c) + (d): a brand-new customer with zero cloud credentials
configured runs `nis2scan scan`.

Uses --scope 1 to keep the run reasonably short (only §30 area 1's checks
execute) while still exercising the real, full credential-discovery chain of
each SDK (boto3 / azure-identity / google-auth) against the real installed
wheel. Exit code 3 ("Scan nicht aussagekraeftig") must hold even with this
partial scope — a customer who happens to pass --scope should get the same
fail-safe behaviour as a full scan.

Timeouts are generous (600s): a credential-less scan can take anywhere from
a few seconds (AWS: NoCredentialsError raises client-side, no retries) to
noticeably longer (Azure: DefaultAzureCredential probes several credential
providers in turn, some of which shell out to external processes; GCP:
google.auth.default() fails fast once CLOUDSDK_CONFIG is neutralized).
"""

import json
from pathlib import Path

import pytest

from .helpers import assert_no_traceback, no_credentials_env, run_cli

pytestmark = pytest.mark.package_smoke

PROVIDERS = ["aws", "azure", "gcp"]

# Substring from each provider's German "Naechster Schritt" hint in
# nis2scan/cli/cli.py's _CREDENTIAL_HINTS — the exact next command a user
# should run to fix their credentials.
_NEXT_STEP_HINTS = {
    "aws": "aws configure",
    "azure": "az login",
    "gcp": "gcloud auth application-default login",
}

_SCAN_TIMEOUT_SECONDS = 600


@pytest.mark.parametrize("provider", PROVIDERS)
def test_scan_without_credentials_is_inconclusive_with_german_cause_block(
    smoke_bin: str, tmp_path: Path, provider: str
) -> None:
    output_dir = tmp_path / f"reports-{provider}"
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", provider, "--scope", "1", "--output", str(output_dir)],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
        timeout=_SCAN_TIMEOUT_SECONDS,
    )

    assert result.returncode == 3, result.combined
    assert_no_traceback(result.combined)
    assert "Scan nicht aussagekräftig" in result.combined
    assert "Ursache:" in result.combined
    assert _NEXT_STEP_HINTS[provider] in result.combined

    report_files = sorted(output_dir.glob("nis2scan_report_*.json"))
    assert len(report_files) == 1, f"expected exactly one JSON report in {output_dir}, found {report_files}"
    data = json.loads(report_files[0].read_text(encoding="utf-8"))

    assert data["schema_version"].startswith("1."), data["schema_version"]
    assert data["report_profile"] == "intern"
    assert data["summary"]["erfuellungsgrad_gesamt"] == "nicht_bewertbar"
    assert data["check_outcomes"], "expected at least one check outcome for --scope 1"
    for entry in data["check_outcomes"]:
        assert entry["outcome"] == "error", entry
        assert entry["error_messages"], entry


@pytest.mark.parametrize("provider", PROVIDERS)
def test_scan_without_credentials_extern_profile_strips_error_messages(
    smoke_bin: str, tmp_path: Path, provider: str
) -> None:
    output_dir = tmp_path / f"reports-{provider}-extern"
    result = run_cli(
        smoke_bin,
        [
            "scan",
            "--provider",
            provider,
            "--scope",
            "1",
            "--output",
            str(output_dir),
            "--report-profile",
            "extern",
        ],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
        timeout=_SCAN_TIMEOUT_SECONDS,
    )

    # Same fail-safe outcome as the intern-profile run above — the report
    # profile only changes what is IN the report, never the exit code.
    assert result.returncode == 3, result.combined
    assert_no_traceback(result.combined)

    report_files = sorted(output_dir.glob("nis2scan_report_*.json"))
    assert len(report_files) == 1, f"expected exactly one JSON report in {output_dir}, found {report_files}"
    data = json.loads(report_files[0].read_text(encoding="utf-8"))

    assert data["report_profile"] == "extern"
    assert data["check_outcomes"], "expected at least one check outcome for --scope 1"
    for entry in data["check_outcomes"]:
        # reporting.pseudonymize.pseudonymize_result clears error_messages
        # entirely for EXTERN — raw exception text may embed identifiers no
        # finding ever surfaces, so it cannot be selectively scrubbed.
        assert entry["error_messages"] == [], entry
