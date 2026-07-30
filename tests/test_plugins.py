"""Tests for the entry-point plugin loader (ADR-0014/0019)."""

import sys
import types

import pytest
import typer

from nis2scan import __version__
from nis2scan.plugins import PLUGIN_GROUP, PluginError, load_plugins


def _current_minor_range() -> str:
    """The specifier a real plugin would pin for THIS nis2scan (ADR-0019).

    Derived from __version__ rather than hardcoded: a literal range silently
    turns the compatibility test into a failing one on the next minor bump,
    which is exactly what happened when 0.1.6 became 0.2.0.
    """
    major, minor, *_ = __version__.split(".")
    return f">={major}.{minor},<{major}.{int(minor) + 1}"


def _install_fake_plugin(monkeypatch: pytest.MonkeyPatch, module_name: str, **attrs) -> None:
    """Put a fake plugin module into sys.modules and expose it as an entry point."""
    from importlib import metadata

    module = types.ModuleType(module_name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, module_name, module)

    ep = metadata.EntryPoint(name="fake", value=f"{module_name}:register", group=PLUGIN_GROUP)
    monkeypatch.setattr(metadata, "entry_points", lambda group=None: [ep] if group == PLUGIN_GROUP else [])


def test_no_plugins_is_a_noop(monkeypatch: pytest.MonkeyPatch):
    from importlib import metadata

    monkeypatch.setattr(metadata, "entry_points", lambda group=None: [])

    ctx = load_plugins(typer.Typer())

    assert ctx.report_exporters == {}


def test_compatible_plugin_registers_exporters_and_commands(monkeypatch: pytest.MonkeyPatch):
    def register(ctx):
        ctx.report_exporters["pdf"] = lambda result, output_dir, profile: output_dir / "report.pdf"
        ctx.cli_app.command("remediate")(lambda: None)

    _install_fake_plugin(monkeypatch, "fake_plugin_ok", NIS2SCAN_REQUIRES=_current_minor_range(), register=register)

    app = typer.Typer()
    ctx = load_plugins(app)

    assert "pdf" in ctx.report_exporters
    assert any(c.name == "remediate" for c in app.registered_commands)


def test_incompatible_plugin_fails_with_german_message(monkeypatch: pytest.MonkeyPatch):
    _install_fake_plugin(monkeypatch, "fake_plugin_old", NIS2SCAN_REQUIRES=">=99.0", register=lambda ctx: None)

    with pytest.raises(PluginError, match="benötigt nis2scan >=99.0"):
        load_plugins(typer.Typer())


def test_plugin_without_requires_declaration_is_rejected(monkeypatch: pytest.MonkeyPatch):
    # Fail-safe: a plugin that does not declare compatibility is not loaded
    _install_fake_plugin(monkeypatch, "fake_plugin_undeclared", register=lambda ctx: None)

    with pytest.raises(PluginError, match="NIS2SCAN_REQUIRES fehlt"):
        load_plugins(typer.Typer())
