"""Plugin loader — the only premium-related code in the free package (ADR-0014).

Plugins are discovered via entry points in the ``nis2scan.plugins`` group
(ADR-0019). Each entry point resolves to a ``register(ctx: PluginContext)``
callable. The plugin module declares its compatible nis2scan range in a
module-level ``NIS2SCAN_REQUIRES`` (PEP 440 specifier); the loader verifies
compatibility before registering and fails with a clear German message
instead of crashing at runtime.

The free package contains no paywall logic: a plugin extends the CLI with
its own commands and report exporters; without an installed plugin only
this loader exists.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module, metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import typer

    from nis2scan.engine.models.result import ScanResult
    from nis2scan.reporting.pseudonymize import ReportProfile

PLUGIN_GROUP = "nis2scan.plugins"

# Exporter contract: (result, output_dir, profile) -> path of the written report
ReportExporter = Callable[["ScanResult", Path, "ReportProfile"], Path]


class PluginError(Exception):
    """A plugin could not be loaded — the message is user-facing German."""


@dataclass
class PluginContext:
    """Registration surface handed to each plugin's register() callable."""

    cli_app: "typer.Typer"
    report_exporters: dict[str, ReportExporter] = field(default_factory=dict)


def installed_plugins() -> list[tuple[str, str]]:
    """Name and package version of every installed nis2scan plugin.

    Purely descriptive (for `nis2scan --version`): no import, no
    compatibility check, no license validation — whether a plugin's features
    are licensed is that plugin's own concern at feature use (ADR-0019/0023).
    """
    found: list[tuple[str, str]] = []
    for ep in metadata.entry_points(group=PLUGIN_GROUP):
        version = ep.dist.version if ep.dist is not None else "unbekannt"
        found.append((ep.name, version))
    return sorted(found)


def load_plugins(cli_app: "typer.Typer") -> PluginContext:
    """Discover and register all installed nis2scan plugins (ADR-0019)."""
    ctx = PluginContext(cli_app=cli_app)
    for ep in metadata.entry_points(group=PLUGIN_GROUP):
        _check_compatibility(ep)
        register: Callable[[PluginContext], Any] = ep.load()
        register(ctx)
    return ctx


def _check_compatibility(ep: metadata.EntryPoint) -> None:
    """Verify the plugin's declared nis2scan range against the installed version."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import Version

    from nis2scan import __version__

    module = import_module(ep.module)
    requires = getattr(module, "NIS2SCAN_REQUIRES", None)
    if not requires:
        raise PluginError(
            f"Plugin '{ep.name}' deklariert keine kompatible nis2scan-Version "
            f"(NIS2SCAN_REQUIRES fehlt) und wird nicht geladen."
        )
    try:
        spec = SpecifierSet(requires)
    except InvalidSpecifier as exc:
        raise PluginError(f"Plugin '{ep.name}' hat eine ungültige Versionsangabe: '{requires}'.") from exc
    if Version(__version__) not in spec:
        raise PluginError(
            f"Plugin '{ep.name}' benötigt nis2scan {requires} — installiert ist nis2scan {__version__}. "
            f"Bitte aktualisieren Sie nis2scan oder das Plugin auf ein kompatibles Paar."
        )
