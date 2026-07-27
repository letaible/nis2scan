"""Journey (b): `nis2scan permissions` matrix — 3 providers x 3 formats
against the real installed wheel.

The terraform/json checks specifically redirect stdout to a real FILE
(``run_cli_stdout_to_file``), not a captured pipe: that is the exact
scenario the hardening audit's Fix 1 (nis2scan/cli/cli.py) was written for —
``nis2scan permissions --format terraform > policy.tf`` — and it is
regression-tested in-process (Click's CliRunner) in
tests/test_cli/test_permissions.py already. This package additionally
proves it against a real OS file handle and a real subprocess, not a fake.
"""

import json
from pathlib import Path

import pytest

from .helpers import TERRAFORM_DESCRIPTION, assert_no_traceback, run_cli, run_cli_stdout_to_file

pytestmark = pytest.mark.package_smoke

PROVIDERS = ["aws", "azure", "gcp"]
FORMATS = ["list", "terraform", "json"]


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("format_", FORMATS)
def test_permissions_exits_zero_for_every_provider_and_format(
    smoke_bin: str, tmp_path: Path, provider: str, format_: str
) -> None:
    result = run_cli(smoke_bin, ["permissions", "--provider", provider, "--format", format_], cwd=tmp_path)

    assert result.returncode == 0, result.combined
    assert_no_traceback(result.combined)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_terraform_output_redirected_to_file_keeps_description_unbroken(
    smoke_bin: str, tmp_path: Path, provider: str
) -> None:
    out_file = tmp_path / f"policy-{provider}.tf"
    returncode, stderr = run_cli_stdout_to_file(
        smoke_bin,
        ["permissions", "--provider", provider, "--format", "terraform"],
        out_file,
        cwd=tmp_path,
    )

    assert returncode == 0, stderr
    assert_no_traceback(stderr)
    content = out_file.read_text(encoding="utf-8")
    assert TERRAFORM_DESCRIPTION in content, content


def test_azure_terraform_every_comment_line_starts_with_hash(smoke_bin: str, tmp_path: Path) -> None:
    """The Azure generator appends a Microsoft-Graph comment block (permissions
    that cannot be expressed as Terraform RBAC actions). A line-wrap bug would
    split a continuation line off its leading '#', silently turning it into
    invalid/uncommented HCL — this is the other confirmed casualty from Fix 1.
    """
    out_file = tmp_path / "policy-azure.tf"
    returncode, stderr = run_cli_stdout_to_file(
        smoke_bin,
        ["permissions", "--provider", "azure", "--format", "terraform"],
        out_file,
        cwd=tmp_path,
    )

    assert returncode == 0, stderr
    lines = out_file.read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("# Zusätzlich")), None)
    assert start is not None, "expected a '# Zusätzlich ...' Microsoft-Graph comment header in the output"

    comment_lines = [line for line in lines[start:] if line.strip()]
    assert comment_lines, "expected at least one non-empty comment line after the header"
    assert all(line.startswith("#") for line in comment_lines), comment_lines


@pytest.mark.parametrize("provider", PROVIDERS)
def test_json_output_is_nonempty_list_of_strings(smoke_bin: str, tmp_path: Path, provider: str) -> None:
    result = run_cli(smoke_bin, ["permissions", "--provider", provider, "--format", "json"], cwd=tmp_path)

    assert result.returncode == 0, result.combined
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) > 0
    assert all(isinstance(p, str) for p in parsed)
