"""Journey (a): `nis2scan --version` and `nis2scan --help` against the real
installed wheel (subprocess, not Click's CliRunner — see package docstring).
"""

import re
from pathlib import Path

import pytest

from .helpers import assert_no_traceback, run_cli

pytestmark = pytest.mark.package_smoke

_VERSION_RE = re.compile(r"nis2scan v\d+\.\d+\.\d+")


def test_version_exits_zero_and_reports_version_and_free_edition(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(smoke_bin, ["--version"], cwd=tmp_path)

    assert result.returncode == 0, result.combined
    assert_no_traceback(result.combined)
    # The version number itself is not hardcoded here: the smoke venv is a
    # separate Python environment from the one running pytest, so asserting
    # an exact version would silently drift out of sync on a bump. A
    # well-formed "nis2scan vX.Y.Z" line is what "enthaelt Versionsnummer"
    # actually requires.
    assert _VERSION_RE.search(result.stdout), result.stdout
    # A fresh wheel-only install (no premium plugin) must always report Free.
    assert "Edition: Free (Apache 2.0)" in result.stdout


def test_help_exits_zero_and_is_german(smoke_bin: str, tmp_path: Path) -> None:
    result = run_cli(smoke_bin, ["--help"], cwd=tmp_path)

    assert result.returncode == 0, result.combined
    assert_no_traceback(result.combined)
    assert "scannt AWS/Azure/GCP" in result.stdout
