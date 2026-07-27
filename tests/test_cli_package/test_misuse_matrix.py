"""Journey (e) + (f): CLI misuse matrix against the real installed wheel.

Every case here is a usage/configuration error that must abort with exit
code 64 (EX_USAGE, nis2scan/cli/cli.py) BEFORE any scan work starts — the
hardening audit 27.07.2026 convention. ``no_credentials_env`` is applied
throughout defensively even though every one of these validations runs
before credentials are ever touched, so a future reordering bug can never
make one of these tests accidentally hit real cloud APIs.

Known, documented exception: an unrecognized OPTION NAME itself (e.g. the
typo --regions instead of --region) never reaches our _validate_* functions
at all — Typer/Click's own argument parser rejects it first, which surfaces
as Click's standard usage-error exit code 2, not our EX_USAGE=64. Our 64
convention only governs validation WE perform on otherwise well-formed
arguments; see test_typo_option_is_typer_usage_error_not_ex_usage below.
"""

from pathlib import Path

import pytest

from .helpers import assert_no_traceback, no_credentials_env, run_cli

pytestmark = pytest.mark.package_smoke

EX_USAGE = 64


def test_unknown_provider_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(smoke_bin, ["scan", "--provider", "quantumcloud"], cwd=tmp_path, env=no_credentials_env(tmp_path))

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Unbekannter Provider" in result.combined


def test_unknown_aws_region_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--region", "mars-central-7"],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Unbekannte AWS-Region" in result.combined


def test_scope_out_of_range_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin, ["scan", "--provider", "aws", "--scope", "15"], cwd=tmp_path, env=no_credentials_env(tmp_path)
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Ungültiger §30-Bereich" in result.combined


def test_missing_config_file_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--config", "gibts-nicht.yaml"],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Konfigurationsdatei nicht gefunden" in result.combined


def test_output_path_pointing_at_existing_file_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    existing_file = tmp_path / "not-a-directory.txt"
    existing_file.write_text("occupied", encoding="utf-8")

    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--output", str(existing_file)],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    # Rich may hard-wrap the long absolute tmp-dir path at console width —
    # flatten whitespace before matching, same convention as
    # tests/test_cli/test_input_validation.py.
    flat = " ".join(result.combined.split())
    assert "ist eine Datei" in flat
    assert "Bitte ein Verzeichnis angeben" in flat


def test_format_pdf_without_premium_plugin_exits_64_and_mentions_professional(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--format", "pdf"],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Professional" in result.combined


def test_unknown_format_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--format", "hologramm"],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Unbekanntes Ausgabeformat" in result.combined


def test_missing_exceptions_file_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--exceptions", str(tmp_path / "gibts-nicht.yaml")],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "nicht lesbar" in result.combined


def test_broken_exceptions_yaml_exits_64(smoke_bin: str, tmp_path: Path) -> None:
    broken = tmp_path / "exceptions.yaml"
    broken.write_text("exceptions: [this is: not: valid: yaml", encoding="utf-8")

    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--exceptions", str(broken)],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == EX_USAGE, result.combined
    assert_no_traceback(result.combined)
    assert "Ausnahmen-Datei ungültig" in result.combined


def test_typo_option_is_typer_usage_error_not_ex_usage(smoke_bin: str, tmp_path: Path) -> None:
    """KNOWN, DOCUMENTED EXCEPTION: --regions (typo for --region) is rejected
    by Typer/Click's argument parser itself, before any of our _validate_*
    functions run. That is Click's own usage-error exit code 2 — distinct
    from our EX_USAGE=64 convention, which only covers validation of
    otherwise well-formed arguments. This is intentional, not a bug to fix.
    """
    result = run_cli(
        smoke_bin,
        ["scan", "--provider", "aws", "--regions", "eu-central-1"],
        cwd=tmp_path,
        env=no_credentials_env(tmp_path),
    )

    assert result.returncode == 2, result.combined
    assert_no_traceback(result.combined)
