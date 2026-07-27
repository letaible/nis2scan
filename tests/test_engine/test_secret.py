"""Tests for customer-secret resolution and nis2scan init (ADR-0010)."""

import asyncio
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest
import structlog.testing
from typer.testing import CliRunner

from nis2scan.engine import secret as secret_module
from nis2scan.engine.secret import generate_secret, persist_secret, resolve_secret

runner = CliRunner()


@pytest.fixture
def secret_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / ".nis2scan" / "secret"
    monkeypatch.setattr(secret_module, "SECRET_FILE", path)
    monkeypatch.delenv("NIS2SCAN_SECRET", raising=False)
    return path


class TestResolveSecret:
    def test_env_wins_over_file(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        persist_secret("from-file")
        monkeypatch.setenv("NIS2SCAN_SECRET", "from-env")

        assert resolve_secret() == b"from-env"

    def test_file_fallback(self, secret_file: Path):
        persist_secret("from-file")

        assert resolve_secret() == b"from-file"

    def test_none_when_nothing_configured(self, secret_file: Path):
        assert resolve_secret() is None

    def test_empty_file_is_none(self, secret_file: Path):
        secret_file.parent.mkdir(parents=True)
        secret_file.write_text("\n", encoding="utf-8")

        assert resolve_secret() is None


class TestGeneratePersist:
    def test_generate_is_256_bit_hex(self):
        value = generate_secret()

        assert len(value) == 64
        int(value, 16)  # must be valid hex

    def test_persist_creates_parent_dir(self, secret_file: Path):
        path = persist_secret("abc123")

        assert path == secret_file
        assert path.read_text(encoding="utf-8").strip() == "abc123"


class TestWindowsAcl:
    """Windows ACL restriction on the secret file, symmetric to POSIX chmod."""

    @pytest.mark.skipif(os.name != "nt", reason="icacls ACL restriction only applies on Windows")
    def test_persist_secret_restricts_acl_to_current_user(self, secret_file: Path):
        username = os.environ.get("USERNAME", "")
        assert username, "USERNAME must be set on Windows to run this test"

        persist_secret("acl-test-value")

        result = subprocess.run(
            ["icacls", str(secret_file)],
            check=True,
            capture_output=True,
            text=True,
        )
        # icacls prints the path followed by one ACE line per grantee, then a
        # blank line, then the "Successfully processed" summary. Everything
        # before the blank line is the ACL for our file.
        acl_block = result.stdout.split("\n\n")[0]

        assert "(I)" not in acl_block, f"expected inherited ACEs to be stripped, got:\n{acl_block}"
        assert username in acl_block, f"expected current user {username!r} to be granted access, got:\n{acl_block}"
        assert acl_block.count(":(F)") == 1, f"expected exactly one Full-Control grantee, got:\n{acl_block}"

    def test_icacls_missing_logs_warning_and_does_not_crash(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        """Defensive path: icacls not on PATH must not break `nis2scan init`."""
        monkeypatch.setattr(secret_module.os, "name", "nt")
        monkeypatch.setenv("USERNAME", "testuser")

        def fake_run(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("icacls not found")

        monkeypatch.setattr(secret_module.subprocess, "run", fake_run)

        path = persist_secret("value-survives-missing-icacls")

        assert path.read_text(encoding="utf-8").strip() == "value-survives-missing-icacls"

    def test_icacls_nonzero_exit_logs_warning_and_does_not_crash(
        self, secret_file: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Defensive path: icacls failing (e.g. access denied) must not crash."""
        monkeypatch.setattr(secret_module.os, "name", "nt")
        monkeypatch.setenv("USERNAME", "testuser")

        def fake_run(*args: object, **kwargs: object) -> None:
            raise subprocess.CalledProcessError(1, ["icacls"], output=b"", stderr=b"Access is denied.")

        monkeypatch.setattr(secret_module.subprocess, "run", fake_run)

        path = persist_secret("value-survives-failing-icacls")

        assert path.read_text(encoding="utf-8").strip() == "value-survives-failing-icacls"

    def test_no_username_env_logs_warning_and_does_not_crash(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        """Defensive path: missing USERNAME env var must not crash either."""
        monkeypatch.setattr(secret_module.os, "name", "nt")
        monkeypatch.delenv("USERNAME", raising=False)

        def fail_if_called(*args: object, **kwargs: object) -> None:
            raise AssertionError("icacls should not be invoked without a USERNAME")

        monkeypatch.setattr(secret_module.subprocess, "run", fail_if_called)

        path = persist_secret("value-survives-no-username")

        assert path.read_text(encoding="utf-8").strip() == "value-survives-no-username"


class TestInitCommand:
    def test_init_creates_secret(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert secret_file.exists()
        assert len(secret_file.read_text(encoding="utf-8").strip()) == 64

    def test_init_refuses_overwrite_without_force(self, secret_file: Path):
        from nis2scan.cli.cli import app

        persist_secret("existing")
        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert secret_file.read_text(encoding="utf-8").strip() == "existing"

    def test_init_force_overwrites(self, secret_file: Path):
        from nis2scan.cli.cli import app

        persist_secret("existing")
        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == 0
        assert secret_file.read_text(encoding="utf-8").strip() != "existing"

    def test_init_help_has_no_adr_reference(self):
        """Fix 5c (hardening audit 27.07.2026): customers reading --help do
        not know what an ADR is — the reference must be gone, the meaning
        (what the secret is for) must stay."""
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["init", "--help"])

        assert result.exit_code == 0
        assert "ADR" not in result.output
        assert "NIS2SCAN_SECRET" in result.output


class TestNoFingerprintSecretHint:
    """Fix 5b (hardening audit 27.07.2026): the "no secret configured" hint
    reaches every customer console via structlog — it used to be English
    with a bare internal ADR reference customers cannot look up."""

    def test_hint_is_german_and_has_no_adr_reference(self):
        from nis2scan.engine import scanner as scanner_module
        from nis2scan.engine.models.config import ScanConfig

        with (
            mock.patch.object(scanner_module, "resolve_secret", return_value=None),
            structlog.testing.capture_logs() as logs,
        ):
            asyncio.run(scanner_module.run_scan(ScanConfig(bsig_30_scope=[1])))

        hint_events = [e for e in logs if e.get("event") == "scan.no_fingerprint_secret"]
        assert hint_events, "expected a scan.no_fingerprint_secret warning"
        hint = hint_events[0]["hint"]
        assert "ADR" not in hint
        assert "nis2scan init" in hint
        assert "NIS2SCAN_SECRET" in hint

    def test_no_hint_when_secret_is_configured(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        from nis2scan.engine import scanner as scanner_module
        from nis2scan.engine.models.config import ScanConfig

        monkeypatch.setenv("NIS2SCAN_SECRET", "configured-secret")

        with structlog.testing.capture_logs() as logs:
            asyncio.run(scanner_module.run_scan(ScanConfig(bsig_30_scope=[1])))

        assert not [e for e in logs if e.get("event") == "scan.no_fingerprint_secret"]
