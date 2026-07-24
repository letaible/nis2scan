"""nis2scan CLI — the primary user interface for running NIS2 compliance scans."""

import asyncio
import contextlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
import typer
import yaml  # type: ignore[import-untyped]
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nis2scan import __version__
from nis2scan.engine.events import EventBus, ScanEvent
from nis2scan.engine.models.config import CompanyInfo, ProviderConfig, ScanConfig
from nis2scan.engine.models.finding import CloudProvider
from nis2scan.engine.providers.aws import register_all_aws_checks
from nis2scan.engine.providers.azure import register_all_azure_checks
from nis2scan.engine.providers.gcp import register_all_gcp_checks
from nis2scan.engine.scanner import run_scan
from nis2scan.plugins import PluginError, load_plugins
from nis2scan.reporting.json_export import export_json
from nis2scan.reporting.markdown import export_markdown

if TYPE_CHECKING:
    from nis2scan.engine.models.result import ComplianceSummary


def _reconfigure_stream_encoding(stream: Any) -> None:
    """Force UTF-8 on the given stream so German umlauts/§ render correctly on
    Windows consoles instead of mojibake (fail-safe hotfix, Bug 4).

    ``reconfigure`` only exists on real ``io.TextIOWrapper`` streams — piped,
    redirected, or otherwise replaced streams (e.g. under some CI runners or
    test harnesses) may lack it entirely. Fail silently rather than crash the
    CLI at startup; the encoding simply stays whatever it already was.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")


# Must run before any CLI output — module import time, before logger/console
# are created, so every code path (including error paths at import time) benefits.
_reconfigure_stream_encoding(sys.stdout)
_reconfigure_stream_encoding(sys.stderr)

logger = structlog.get_logger()
console = Console()

# Fix 3 (fail-safe hotfix): the only valid --provider values, derived from the
# canonical CloudProvider enum instead of duplicating a literal list.
_VALID_PROVIDERS = {p.value.lower() for p in CloudProvider}


def _validate_provider(provider: str) -> None:
    """Abort with a German error + exit 1 on an unknown --provider value.

    Without this, a typo like ``--provider awss`` silently registered zero
    checks and produced an empty 0/0 report at exit 0 (audit finding, Bug 3).
    """
    if provider.lower() not in _VALID_PROVIDERS:
        console.print(f"[red]Unbekannter Provider: {provider}. Erlaubt: aws, azure, gcp[/red]")
        raise typer.Exit(code=1)


app = typer.Typer(
    name="nis2scan",
    help="NIS2 Cloud Compliance Scanner — scannt AWS/Azure/GCP gegen §30 BSIG",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        from nis2scan.plugins import installed_plugins

        console.print(f"nis2scan v{__version__}")
        plugins = installed_plugins()
        if plugins:
            for name, plugin_version in plugins:
                console.print(f"Plugin: {name} v{plugin_version}")
            console.print(
                "Edition: Professional (Plugin installiert — der Lizenzstatus "
                "wird bei Nutzung der Professional-Funktionen geprüft)"
            )
        else:
            console.print("Edition: Free (Apache 2.0)")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=version_callback, is_eager=True, help="Version anzeigen"
    ),
) -> None:
    """NIS2 Cloud Compliance Scanner — §30 BSIG automated checks for AWS & Azure."""


@app.command()
def scan(
    config_file: Path = typer.Option(
        "config/default.yaml",
        "--config",
        "-c",
        help="Pfad zur Scan-Konfigurationsdatei (YAML)",
    ),
    provider: str = typer.Option(
        "aws",
        "--provider",
        "-p",
        help="Cloud-Provider: aws, azure oder gcp",
    ),
    output_dir: str = typer.Option(
        "./reports",
        "--output",
        "-o",
        help="Ausgabeverzeichnis für Reports",
    ),
    format: list[str] = typer.Option(
        ["json", "markdown"],
        "--format",
        "-f",
        help="Ausgabeformate: json, markdown, pdf",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="AWS CLI Profile Name",
    ),
    regions: list[str] = typer.Option(
        ["eu-central-1"],
        "--region",
        "-r",
        help="Cloud-Regionen zum Scannen",
    ),
    scope: list[int] = typer.Option(
        list(range(1, 11)),
        "--scope",
        "-s",
        help="§30 BSIG Bereiche (1-10) zum Scannen",
    ),
    report_profile: str = typer.Option(
        "intern",
        "--report-profile",
        help="Report-Profil (ADR-0011): intern = Klardaten, extern = pseudonymisiert für Weitergabe",
    ),
    assume_role_arn: str | None = typer.Option(
        None,
        "--assume-role-arn",
        help="AWS: diese Cross-Account-Rolle annehmen (STS AssumeRole) statt der lokalen Credentials",
    ),
    external_id: str | None = typer.Option(
        None,
        "--external-id",
        help="AWS: ExternalId der Vertrauensrichtlinie (Confused-Deputy-Schutz) zur angenommenen Rolle",
    ),
    exceptions: Path | None = typer.Option(
        None,
        "--exceptions",
        help="Pfad zu einer Ausnahmen-Datei (YAML) mit dokumentierten, befristeten Ausnahmen",
    ),
) -> None:
    """Führt einen NIS2-Compliance-Scan durch."""
    from nis2scan.engine.finding_exceptions import ExceptionsFileError, find_long_running_rules, load_exceptions_file
    from nis2scan.reporting.pseudonymize import ReportProfile

    _validate_provider(provider)

    try:
        # Fix 1 (fail-safe hotfix, P0): this MUST NOT be named `profile` — the
        # `profile` parameter above is the AWS CLI profile name and flows into
        # _build_config()/ProviderConfig.profile. Reusing the name here used to
        # silently shadow it, so every CLI scan got AwsSession(profile_name="intern"
        # or "extern") instead of the user's AWS profile (or None) — --profile was
        # a no-op since 0.1.0. Keep this a distinctly named variable and use it
        # ONLY for the report export calls below, never for _build_config.
        report_profile_enum = ReportProfile(report_profile.lower())
    except ValueError:
        console.print(f"[red]Ungültiges Report-Profil: {report_profile}. Erlaubt: intern, extern[/red]")
        raise typer.Exit(code=1) from None

    if exceptions is not None:
        # Fail-safe (ADR-0026): validate eagerly so a broken exceptions file
        # aborts the scan instead of being silently ignored. run_scan loads
        # it again engine-side (ADR-0026 consequence: annotation must happen
        # in the engine, not just here), so both paths always agree.
        try:
            exceptions_file = load_exceptions_file(exceptions)
        except ExceptionsFileError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(code=1) from None

        for rule in find_long_running_rules(exceptions_file, datetime.now(UTC).date()):
            console.print(
                f"[yellow]⚠ Ausnahme {rule.check_id} / {rule.resource_id} läuft ab heute noch länger als "
                f"12 Monate (bis {rule.expires.isoformat()}) — Wiedervorlage empfohlen.[/yellow]"
            )

    console.print(
        Panel.fit(
            f"[bold blue]nis2scan v{__version__}[/bold blue]\n"
            f"NIS2 Cloud Compliance Scanner — §30 BSIG\n"
            f"Provider: {provider.upper()} | Regionen: {', '.join(regions)} | §30-Scope: {scope}",
            title="NIS2 Scan",
        )
    )

    # Load config from YAML if it exists, otherwise use CLI args
    scan_config = _build_config(
        config_file, provider, profile, regions, scope, output_dir, format, assume_role_arn, external_id, exceptions
    )

    # Register check modules
    if provider.lower() == "aws":
        register_all_aws_checks()
    elif provider.lower() == "azure":
        register_all_azure_checks()
    elif provider.lower() == "gcp":
        register_all_gcp_checks()

    # Set up event bus with CLI progress
    event_bus = EventBus()
    progress_state: dict[str, int] = {"checks": 0, "findings": 0}

    def on_check_completed(data: dict[str, Any]) -> None:
        progress_state["checks"] += 1
        progress_state["findings"] += data.get("finding_count", 0)

    def on_critical(data: dict[str, Any]) -> None:
        console.print(f"  [bold red]CRITICAL[/bold red] {data.get('title', '')}")

    event_bus.subscribe(ScanEvent.CHECK_COMPLETED, on_check_completed)
    event_bus.subscribe(ScanEvent.FINDING_CRITICAL, on_critical)

    # Run scan
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            result = asyncio.run(run_scan(scan_config, event_bus))

            progress.update(task, description="Scan abgeschlossen", completed=True)
    except ExceptionsFileError as e:
        # Defense in depth: run_scan loads the exceptions file again
        # engine-side (see comment above) and could still fail here, e.g. if
        # the file changed between the pre-check and scan start.
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from None

    # Print summary
    _print_summary(result.summary)

    # Export reports
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if "json" in format:
        json_path = export_json(result, out_path, report_profile_enum)
        console.print(f"\n[green]JSON-Report:[/green] {json_path}")

    if "markdown" in format:
        md_path = export_markdown(result, out_path, report_profile_enum)
        console.print(f"[green]Markdown-Report:[/green] {md_path}")

    # Additional formats come from installed plugins (ADR-0014/0019)
    for fmt in format:
        if fmt in ("json", "markdown"):
            continue
        exporter = _PLUGINS.report_exporters.get(fmt)
        if exporter is None:
            if fmt == "pdf":
                console.print(
                    "[yellow]PDF-Reports sind Teil von nis2scan Professional.[/yellow] "
                    "Lizenzkunden installieren das Premium-Plugin (pip install nis2scan-premium). "
                    "Info: https://nis2scan.de/pricing"
                )
            else:
                console.print(f"[red]Unbekanntes Ausgabeformat:[/red] {fmt}")
            continue
        try:
            report_path = exporter(result, out_path, report_profile_enum)
            console.print(f"[green]{fmt.upper()}-Report:[/green] {report_path}")
        except Exception as e:  # plugin failures must not hide the scan results
            console.print(str(e))

    # Exit-Code-Semantik (Fix 2, fail-safe hotfix):
    #   0 = keine hohen/kritischen Mängel
    #   1 = mindestens ein High-Mangel
    #   2 = mindestens ein Critical-Mangel
    #   3 = Scan nicht aussagekräftig — alle anwendbaren Checks sind mit
    #       Fehlern geendet, kein einziger Check konnte erfolgreich (PASSED
    #       oder FAILED) ausgewertet werden. A real FAILED check still counts
    #       as meaningful (a genuine defect was found), so exit 3 fires only
    #       when there is truly nothing to report on.
    # The error count itself is already surfaced by _print_summary ("gilt
    # nicht als bestanden"), so no extra warning line is printed here.
    if result.summary.error_checks > 0 and result.summary.passed_checks == 0 and result.summary.failed_checks == 0:
        console.print(
            f"[bold red]Scan nicht aussagekräftig: {result.summary.error_checks} Checks mit Fehlern, "
            f"kein Check erfolgreich ausgewertet.[/bold red]"
        )
        raise typer.Exit(code=3)

    if result.summary.critical_count > 0:
        raise typer.Exit(code=2)
    elif result.summary.high_count > 0:
        raise typer.Exit(code=1)


@app.command()
def init(
    force: bool = typer.Option(
        False,
        "--force",
        help="Vorhandenes Secret überschreiben (Achtung: Finding-Fingerprints ändern sich)",
    ),
) -> None:
    """Initialisiert nis2scan: erzeugt und persistiert das NIS2SCAN_SECRET (ADR-0010)."""
    from nis2scan.engine.secret import SECRET_ENV, SECRET_FILE, generate_secret, persist_secret, resolve_secret

    if SECRET_FILE.exists() and not force:
        console.print(f"[yellow]Secret existiert bereits:[/yellow] {SECRET_FILE}")
        console.print("Mit [bold]--force[/bold] überschreiben — Achtung: alle Finding-Fingerprints ändern sich.")
        raise typer.Exit(code=0)

    path = persist_secret(generate_secret())
    console.print(f"[green]NIS2SCAN_SECRET erzeugt und gespeichert:[/green] {path}")
    console.print(
        "Das Secret schlüsselt Finding-Fingerprints (stabile Wiedererkennung über Scans) "
        "und Pseudonyme im externen Report-Profil."
    )
    console.print(f"[dim]Hinweis: Die Umgebungsvariable {SECRET_ENV} hat Vorrang vor der Datei (z. B. für CI).[/dim]")

    if os.environ.get(SECRET_ENV) and resolve_secret() != SECRET_FILE.read_text(encoding="utf-8").strip().encode():
        console.print(f"[yellow]Achtung: {SECRET_ENV} ist gesetzt und überstimmt die neue Datei.[/yellow]")


@app.command()
def permissions(
    provider: str = typer.Option("aws", "--provider", "-p", help="Cloud-Provider"),
    format: str = typer.Option("list", "--format", "-f", help="Ausgabeformat: list, terraform, json"),
) -> None:
    """Zeigt die benötigten Cloud-Permissions für alle Checks an."""
    _validate_provider(provider)

    if provider.lower() == "aws":
        register_all_aws_checks()
    elif provider.lower() == "azure":
        register_all_azure_checks()
    elif provider.lower() == "gcp":
        register_all_gcp_checks()

    from nis2scan.engine.registry import CheckRegistry

    registry = CheckRegistry.get_instance()
    perms = registry.get_required_permissions(provider.lower())

    if format == "json":
        console.print(json.dumps(perms, indent=2))
    elif format == "terraform":
        generators = {
            "aws": _generate_terraform_policy,
            "azure": _generate_azure_rbac_terraform,
            "gcp": _generate_gcp_role_terraform,
        }
        generator = generators.get(provider.lower())
        if generator is None:
            console.print(f"[red]Terraform-Export für Provider '{provider}' nicht verfügbar.[/red]")
            raise typer.Exit(code=1)
        console.print(generator(perms))
    else:
        console.print(f"\n[bold]Benötigte {provider.upper()} Permissions ({len(perms)}):[/bold]\n")
        for perm in perms:
            console.print(f"  - {perm}")


# --- Helpers ---


def _build_config(
    config_file: Path,
    provider: str,
    profile: str | None,
    regions: list[str],
    scope: list[int],
    output_dir: str,
    formats: list[str],
    assume_role_arn: str | None = None,
    external_id: str | None = None,
    exceptions_path: Path | None = None,
) -> ScanConfig:
    """Build ScanConfig from YAML file and CLI overrides."""
    config_data: dict[str, Any] = {}

    if config_file.exists():
        with open(config_file) as f:
            config_data = yaml.safe_load(f) or {}

    # Build provider config from CLI args (overrides YAML)
    provider_config = ProviderConfig(
        enabled=True,
        profile=profile,
        regions=regions,
        assume_role_arn=assume_role_arn,
        external_id=external_id,
    )

    company_data = config_data.get("company", {})

    return ScanConfig(
        company=CompanyInfo(**company_data) if company_data else CompanyInfo(),
        providers={provider.lower(): provider_config},
        bsig_30_scope=scope,
        output_formats=formats,
        output_dir=output_dir,
        # Findings-Exceptions (ADR-0026): opt-in via --exceptions; None means
        # no exceptions are ever applied (no implicit default file).
        exceptions_path=str(exceptions_path) if exceptions_path else None,
    )


def _print_summary(summary: "ComplianceSummary") -> None:
    """Print a formatted compliance summary to the console."""
    from nis2scan.engine.models.result import Erfuellungsgrad
    from nis2scan.reporting.labels import ERFUELLUNGSGRAD_LABELS

    grad_colors = {
        Erfuellungsgrad.ERFUELLT: "green",
        Erfuellungsgrad.TEILWEISE_ERFUELLT: "yellow",
        Erfuellungsgrad.NICHT_ERFUELLT: "red",
        Erfuellungsgrad.NICHT_BEWERTBAR: "white",
    }
    gesamt = summary.erfuellungsgrad_gesamt
    color = grad_colors.get(gesamt, "white")

    console.print(
        f"\n[bold {color}]Erfüllungsgrad (cloud-technischer Teilaspekt): "
        f"{ERFUELLUNGSGRAD_LABELS[gesamt]}[/bold {color}]"
    )
    applicable = summary.total_checks - summary.not_applicable_checks
    console.print(
        f"Checks: {summary.passed_checks}/{applicable} anwendbaren bestanden, {summary.failed_checks} nicht bestanden"
    )
    if summary.not_applicable_checks > 0:
        console.print(f"Nicht anwendbar (keine Prüfobjekte in der Umgebung): {summary.not_applicable_checks} Check(s)")
    if summary.error_checks > 0:
        console.print(
            f"[bold red]⚠ {summary.error_checks} Check(s) mit Fehler — "
            f"Ergebnis unbekannt, gilt nicht als bestanden[/bold red]"
        )
    console.print(f"Mängel gesamt: {summary.total_findings}")
    if summary.exceptions_accepted_count > 0:
        console.print(f"  davon per dokumentierter Ausnahme akzeptiert: {summary.exceptions_accepted_count}")
    if summary.compliant_count > 0:
        console.print(f"Positivnachweise: {summary.compliant_count}")

    if summary.total_findings > 0:
        console.print(
            f"  [red]Kritisch: {summary.critical_count}[/red] | "
            f"[yellow]Hoch: {summary.high_count}[/yellow] | "
            f"Mittel: {summary.medium_count} | "
            f"Niedrig: {summary.low_count} | "
            f"Info: {summary.info_count}"
        )

    if summary.scores_by_area:
        table = Table(title="\n§30 BSIG Compliance-Matrix")
        table.add_column("Nr.", style="bold")
        table.add_column("Bereich")
        table.add_column("Erfüllungsgrad")
        table.add_column("Checks", justify="right")
        table.add_column("N. a.", justify="right")
        table.add_column("Fehler", justify="right")
        table.add_column("Mängel", justify="right")
        table.add_column("Kritisch", justify="right", style="red")

        for score in summary.scores_by_area:
            area_color = grad_colors.get(score.erfuellungsgrad, "white")
            area_applicable = score.total_checks - score.not_applicable_checks
            table.add_row(
                str(score.bsig_30_nr),
                score.area_name,
                f"[{area_color}]{ERFUELLUNGSGRAD_LABELS[score.erfuellungsgrad]}[/{area_color}]",
                f"{score.passed_checks}/{area_applicable}",
                str(score.not_applicable_checks) if score.not_applicable_checks > 0 else "-",
                f"[red]{score.error_checks}[/red]" if score.error_checks > 0 else "-",
                str(score.failed_checks),
                str(score.critical_count) if score.critical_count > 0 else "-",
            )

        console.print(table)


def _generate_azure_rbac_terraform(permissions: list[str]) -> str:
    """Generate a Terraform Azure custom role for the required permissions (ADR-0020).

    ARM operations (Microsoft.*/…/read) become actions of a custom RBAC role.
    Microsoft Graph permissions (e.g. Policy.Read.All) cannot be granted via
    RBAC — they are listed as app-registration permissions with az CLI hints.
    """
    rbac_actions = sorted(p for p in permissions if "/" in p)
    graph_permissions = sorted(p for p in permissions if "/" not in p)

    actions = ",\n".join(f'      "{p}"' for p in rbac_actions)
    parts = [
        f"""data "azurerm_subscription" "current" {{}}

resource "azurerm_role_definition" "nis2scan_readonly" {{
  name        = "nis2scan-readonly"
  scope       = data.azurerm_subscription.current.id
  description = "Minimal read-only permissions for nis2scan NIS2 compliance scanner"

  permissions {{
    actions = [
{actions}
    ]
    not_actions = []
  }}

  assignable_scopes = [
    data.azurerm_subscription.current.id
  ]
}}"""
    ]

    if graph_permissions:
        graph_lines = "\n".join(f"#   - {p}" for p in graph_permissions)
        parts.append(
            f"""
# Zusätzlich benötigte Microsoft-Graph-Berechtigungen (Application permissions).
# Diese sind NICHT über Azure RBAC vergebbar — sie müssen der App-Registrierung
# des Scanners erteilt werden (Admin-Consent erforderlich):
{graph_lines}
#
# az ad app permission add --id <APP_ID> --api 00000003-0000-0000-c000-000000000000 \\
#   --api-permissions <PERMISSION_ID>=Role
# az ad app permission admin-consent --id <APP_ID>"""
        )

    return "\n".join(parts)


def _generate_gcp_role_terraform(permissions: list[str]) -> str:
    """Generate a Terraform GCP custom role + binding for the required permissions (ADR-0020)."""
    perms = ",\n".join(f'    "{p}"' for p in sorted(permissions))
    return f"""variable "project_id" {{
  description = "GCP project to scan"
  type        = string
}}

variable "nis2scan_service_account" {{
  description = "Service account email used by nis2scan"
  type        = string
}}

resource "google_project_iam_custom_role" "nis2scan_readonly" {{
  project     = var.project_id
  role_id     = "nis2scanReadonly"
  title       = "nis2scan Read-Only"
  description = "Minimal read-only permissions for nis2scan NIS2 compliance scanner"

  permissions = [
{perms}
  ]
}}

resource "google_project_iam_member" "nis2scan_readonly" {{
  project = var.project_id
  role    = google_project_iam_custom_role.nis2scan_readonly.id
  member  = "serviceAccount:${{var.nis2scan_service_account}}"
}}"""


def _generate_terraform_policy(permissions: list[str]) -> str:
    """Generate a Terraform IAM policy document for the required permissions."""
    actions = ",\n".join(f'      "{p}"' for p in permissions)
    return f"""resource "aws_iam_policy" "nis2scan_readonly" {{
  name        = "nis2scan-readonly"
  description = "Minimal read-only permissions for nis2scan NIS2 compliance scanner"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "Nis2ScanReadOnly"
        Effect = "Allow"
        Action = [
{actions}
    ]
        Resource = "*"
      }}
    ]
  }})
}}"""


# Discover installed plugins last so they can extend the fully built CLI
# (ADR-0014/0019). Without a plugin this is a no-op — the free package
# contains no premium commands and no paywall logic.
try:
    _PLUGINS = load_plugins(app)
except PluginError as e:
    console.print(f"[red]{e}[/red]")
    raise SystemExit(1) from None
