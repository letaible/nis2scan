"""Shared helpers for tests/test_cli_package/ (subprocess-based package smoke tests).

Not a test module itself (no ``test_`` prefix) — imported by the actual test
files via relative import.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

SMOKE_BIN_ENV_VAR = "NIS2SCAN_SMOKE_BIN"

# The exact description string embedded verbatim (single line) in every
# `permissions --format terraform` generator's output (nis2scan/cli/cli.py:
# _generate_terraform_policy / _generate_azure_rbac_terraform /
# _generate_gcp_role_terraform). Length is 66 characters as derived from
# today's source — NOT the founder's recollection from the manual hardening
# test, which is why this is read off cli.py rather than hardcoded from memory.
TERRAFORM_DESCRIPTION = "Minimal read-only permissions for nis2scan NIS2 compliance scanner"

TRACEBACK_MARKER = "Traceback (most recent call last)"


@dataclass
class CliResult:
    """Captured result of one subprocess CLI invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def combined(self) -> str:
        """stdout + stderr concatenated.

        Most CLI messages go to stdout (the Rich ``Console()`` in cli.py
        defaults to stdout), but Typer/Click usage errors (e.g. an unknown
        option) and raw Python tracebacks go to stderr. Assertions that don't
        care which stream a message landed on should use this instead of
        picking one stream and guessing wrong.
        """
        return self.stdout + self.stderr


def assert_no_traceback(text: str) -> None:
    """Assert the CLI never surfaced a raw Python traceback to the user.

    Shared by every test in this package: every expected error path in
    cli.py prints a German Rich/Click message and exits cleanly (with 0-3 or
    64) — an actual Python traceback reaching the console is always a bug.
    """
    assert TRACEBACK_MARKER not in text, f"unexpected Python traceback in CLI output:\n{text}"


def run_cli(
    smoke_bin: str,
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 60,
) -> CliResult:
    """Invoke the installed nis2scan executable as a subprocess and capture output."""
    proc = subprocess.run(  # noqa: S603 — smoke_bin is our own fixture-provided path, not user input
        [smoke_bin, *args],
        cwd=cwd,
        env=env if env is not None else os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return CliResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def run_cli_stdout_to_file(
    smoke_bin: str,
    args: list[str],
    output_file: Path,
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 60,
) -> tuple[int, str]:
    """Invoke the CLI with stdout redirected to a real FILE (not a pipe).

    Machine-readable formats (``permissions --format terraform/json``) must
    never be hard-wrapped by Rich, which triggers whenever stdout is not a
    TTY — true of both a pipe and a redirected file, but a real file
    redirection is the exact scenario a user hits with
    ``nis2scan permissions ... > policy.tf`` (hardening audit 27.07.2026,
    Fix 1; regression-tested in-process in tests/test_cli/test_permissions.py,
    covered here against the real executable and real OS file I/O).

    Returns (returncode, stderr_text) — stdout was written straight to
    ``output_file``, so callers read it back from there.
    """
    with open(output_file, "w", encoding="utf-8") as f:
        proc = subprocess.run(  # noqa: S603
            [smoke_bin, *args],
            cwd=cwd,
            env=env if env is not None else os.environ.copy(),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    return proc.returncode, proc.stderr


def no_credentials_env(tmp_path: Path) -> dict[str, str]:
    """Build a subprocess environment with every cloud provider's credential
    discovery neutralized (hardening audit 27.07.2026, package-smoke gate).

    This is applied regardless of which single provider a given test
    targets: this suite runs on a developer's own machine, not just CI, and
    that machine may carry real AWS/Azure/GCP credentials (e.g. a local
    ``aws configure`` profile or a ``gcloud auth login`` session for the
    shining-medium-271123 project mentioned in CLAUDE.md). Without
    neutralizing all three, a "no credentials" test could silently succeed
    against real cloud APIs instead of exercising the credential-less code
    path it exists to test.
    """
    env = os.environ.copy()

    # AWS: point boto3 at nonexistent credentials/config files, disable the
    # EC2 instance-metadata credential provider (would otherwise spend real
    # wall-clock time probing 169.254.169.254 if this ever runs on an EC2
    # instance), and strip any inline/ambient credentials the host
    # environment might already carry.
    env["AWS_SHARED_CREDENTIALS_FILE"] = str(tmp_path / "no-such-aws-credentials")
    env["AWS_CONFIG_FILE"] = str(tmp_path / "no-such-aws-config")
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    ):
        env.pop(var, None)

    # Azure: DefaultAzureCredential's AzureCliCredential probe shells out to
    # the `az` CLI, which reads its cached login from AZURE_CONFIG_DIR
    # (default ~/.azure) — repointing it at an empty directory means `az`
    # (if even installed) reports no logged-in account. Also strip
    # service-principal env vars EnvironmentCredential would otherwise use.
    azure_config_dir = tmp_path / "azure-config-empty"
    azure_config_dir.mkdir(exist_ok=True)
    env["AZURE_CONFIG_DIR"] = str(azure_config_dir)
    for var in (
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_USERNAME",
        "AZURE_PASSWORD",
        "NIS2SCAN_AZURE_CLIENT_ID",
        "NIS2SCAN_AZURE_CLIENT_SECRET",
    ):
        env.pop(var, None)

    # GCP: google.auth.default() checks GOOGLE_APPLICATION_CREDENTIALS first,
    # then gcloud's Application Default Credentials file located under
    # CLOUDSDK_CONFIG (default ~/.config/gcloud, or %APPDATA%\gcloud on
    # Windows) — repointing it at an empty directory means no prior
    # `gcloud auth application-default login` is ever found.
    gcloud_config_dir = tmp_path / "gcloud-config-empty"
    gcloud_config_dir.mkdir(exist_ok=True)
    env["CLOUDSDK_CONFIG"] = str(gcloud_config_dir)
    for var in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"):
        env.pop(var, None)

    return env
