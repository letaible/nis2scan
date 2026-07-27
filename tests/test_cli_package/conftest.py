"""Shared fixtures for tests/test_cli_package/."""

import os

import pytest

from .helpers import SMOKE_BIN_ENV_VAR


@pytest.fixture
def smoke_bin() -> str:
    """Path to the installed nis2scan executable under test.

    Set by the CI cli-smoke job / a local gate run before invoking pytest
    (see the package docstring in tests/test_cli_package/__init__.py for how
    to build and set one up). When unset, every package_smoke test using
    this fixture skips with a German reason instead of failing — this
    package only makes sense against a real built wheel, unlike the rest of
    the (in-process) unit-test suite.
    """
    path = os.environ.get(SMOKE_BIN_ENV_VAR)
    if not path:
        pytest.skip(
            f"{SMOKE_BIN_ENV_VAR} ist nicht gesetzt — Paket-Smoke-Test übersprungen. "
            "Wheel bauen und in ein frisches venv installieren, dann "
            f"{SMOKE_BIN_ENV_VAR}=<Pfad zur nis2scan-Executable> setzen "
            "(siehe Docstring in tests/test_cli_package/__init__.py)."
        )
    return path
