"""Package smoke tests — exercise the INSTALLED nis2scan wheel via subprocess.

Unlike tests/test_cli/ (which drives the Typer app in-process via Click's
CliRunner), everything in this package shells out to a real ``nis2scan``
executable installed from a built wheel. That is a structurally different
test: it catches packaging bugs unit tests cannot see by construction —
missing package data, broken console-script entry points, a ``pip install``
that resolves different (newer) transitive dependencies than the editable
dev checkout, and real terminal/file-redirection behaviour (Rich only
hard-wraps output when stdout is not a TTY, which CliRunner already fakes,
but a real redirected file is the exact scenario a user hits with
``nis2scan permissions ... > policy.tf``).

This directly continues the manual CLI hardening test run 25.-27.07.2026
(founder + this session) as a permanent, automated regression suite. See
CLAUDE.md's "Known Pitfalls" section for prior bugs a package-level test
would have caught immediately (the 0.1.0 ``--profile`` shadowing bug; the
azure-mgmt-security/monitor and google-cloud-logging SDK-drift breakage).

Marker: ``package_smoke`` (registered in pyproject.toml, excluded from the
default ``pytest tests/`` run the same way ``integration`` is — see
``addopts`` in ``[tool.pytest.ini_options]``). Every test in this package
additionally skips (never fails) when NIS2SCAN_SMOKE_BIN is unset, so the
default unit-test run never needs a built wheel.

Running locally
----------------

::

    pip wheel . --no-deps -w dist-smoke
    python -m venv /short/path/pkgsmoke   # short path: avoids Windows MAX_PATH
    # Windows:      /short/path/pkgsmoke/Scripts/activate
    # Linux/macOS:  source /short/path/pkgsmoke/bin/activate
    pip install dist-smoke/*.whl "pytest>=8.0.0"

    # Windows (PowerShell):
    $env:NIS2SCAN_SMOKE_BIN = "/short/path/pkgsmoke/Scripts/nis2scan.exe"
    # Linux/macOS:
    export NIS2SCAN_SMOKE_BIN=/short/path/pkgsmoke/bin/nis2scan

    pytest tests/test_cli_package/ -v -m package_smoke

Runtime note: the credential-less scan tests (test_no_credentials.py) each
run a real (failing) scan against one cloud provider's SDK. Depending on how
many credential providers that SDK's default chain probes before giving up,
a single provider can take anywhere from a few seconds to a couple of
minutes — budget several minutes for a full local run of this package, and
mind the generous per-test subprocess timeout (600s) that accounts for this.
"""
