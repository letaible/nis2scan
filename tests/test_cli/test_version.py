"""`nis2scan --version` shows version, installed plugins and the edition.

Founder finding 25.07.2026: users had no way to see WHICH version and
WHICH edition (Free vs. Professional plugin) is in use.
"""

from importlib import metadata as importlib_metadata

import pytest
from typer.testing import CliRunner

from nis2scan import __version__
from nis2scan.cli.cli import app

runner = CliRunner()


def test_version_shows_version_and_free_edition():
    """No plugins installed (the normal free install) → Free edition line."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"nis2scan v{__version__}" in result.output
    assert "Edition: Free (Apache 2.0)" in result.output
    assert "Professional" not in result.output


def test_version_lists_installed_plugins(monkeypatch: pytest.MonkeyPatch):
    """With a plugin entry point present, name+version and the hint that the
    license is checked at feature use must appear (ADR-0019/0023)."""

    class _FakeDist:
        version = "0.9.9"

    class _FakeEntryPoint:
        name = "premium"
        dist = _FakeDist()

    def fake_entry_points(*, group: str):
        assert group == "nis2scan.plugins"
        return [_FakeEntryPoint()]

    import nis2scan.plugins as plugins_module

    monkeypatch.setattr(plugins_module.metadata, "entry_points", fake_entry_points)

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "Plugin: premium v0.9.9" in result.output
    assert "Edition: Professional" in result.output
    assert "Lizenzstatus" in result.output


def test_version_survives_missing_dist_metadata(monkeypatch: pytest.MonkeyPatch):
    """A plugin whose entry point carries no dist metadata must not crash
    the version output."""

    class _FakeEntryPoint:
        name = "premium"
        dist = None

    import nis2scan.plugins as plugins_module

    monkeypatch.setattr(
        plugins_module.metadata,
        "entry_points",
        lambda *, group: [_FakeEntryPoint()],
    )

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "Plugin: premium vunbekannt" in result.output


def test_real_entry_points_api_matches_fake():
    """Guard: the importlib.metadata API our fakes mimic still exists."""
    eps = importlib_metadata.entry_points(group="nis2scan.plugins")
    assert hasattr(eps, "__iter__")
