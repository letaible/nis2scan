# NIS2 Cloud Compliance Scanner (nis2scan)

## Role

You are a NIS2 expert, senior DevSecOps engineer, senior cloud security engineer, senior cloud security architect and senior software developer for this project. Apply deep knowledge of German cybersecurity law (BSIG), cloud security (AWS, Azure, GCP), and software engineering rigor to all work.

## Governance & Entscheidungen (seit W5 hier im Repo)

- **ADRs:** `docs/adr/` (0001–0023) — alle Architektur- und Produktentscheidungen
  aus den Grilling-Runden. Vor Änderungen am Modell konsultieren.
- **Domänensprache/Kontext:** `docs/CONTEXT-planning.md` (aus dem Planning-Repo).
- **Rechts-Review-Gate (ADR-0018, verbindlich):** Jede Änderung an Mapping,
  Checks oder rechtlich formulierenden Reporttexten braucht vor dem Merge
  ZWEI Reviews: Gründer + Agent `legal-reviewer` (`.claude/agents/legal-reviewer.md`,
  Checkliste: Skill `nis2-legal-review`). Kein Merge ohne beide Vermerke.
  Protokoll: `docs/rechtsgrundlagen-review.md`.

## Arbeitsweise (Kosten, verbindlich seit 12.07.2026)

- **Orchestrator-Muster** (`docs/arbeitsweise.md`): Hauptsession (Fable 5,
  ersatzweise Opus 4.8) plant, reviewt, committet. Mechanische, klar
  spezifizierte Ausführung an **Sonnet-5-Worker** delegieren
  (`Agent`, `subagent_type="general-purpose"`, `model="sonnet"`).
- NIE an Worker delegieren: Rechts-Urteile (ADR-0018), Code-Review,
  Architekturentscheidungen, Commits. Worker liefern für Rechts-Reviews nur
  mechanische Dossiers ohne Bewertung zu.

## Memory Management

- Update auto-memory (`MEMORY.md`) whenever a bug is found/fixed, a significant architectural decision is made, or a new constraint is discovered
- Update this file (`CLAUDE.md`) whenever a new pitfall, constraint, or critical pattern is discovered that ALL future sessions must know about
- Don't wait to be asked — do it proactively as part of the work, immediately after the finding
- Keep entries concise: one line per fact, grouped by topic

## What

Open-source CLI tool that scans AWS/Azure/GCP environments against the 10 mandatory measures of §30 Abs. 2 BSIG (German NIS2 implementation). Generates audit-ready compliance reports with findings mapped to §30 BSIG and ISO 27001:2022.

## Stack

- Python 3.12+, Pydantic v2, Typer (CLI), Jinja2 (Reports)
- boto3 (AWS), azure-identity + azure-mgmt-* (Azure), google-cloud-* + google-auth (GCP)
- Tests: pytest + pytest-asyncio + moto (AWS mocks) + pytest-xdist (parallel)
- Lint/Format: ruff (line-length=120, target-version=py312)
- Type check: mypy (strict mode, pydantic plugin)
- Infrastructure: Terraform (AWS, Azure, GCP test resources)
- CI/CD: GitHub Actions with OIDC (no static credentials)

## Architecture (CRITICAL)

- Engine is a library, NOT a CLI app. CLI is just one consumer.
- Every scan produces a ScanResult (Pydantic model) -> serialized as JSON -> consumed by reporters.
- Checks are stateless. No globals, no singletons. Config in, Findings out.
- The tool is READ-ONLY. Never write/modify/delete any cloud resource.
- All output text (reports, finding descriptions, remediation) is in GERMAN.
- All code (variables, comments, docstrings) is in ENGLISH.
- Each check must be tested before committing.

### Scan Flow

```
CLI (cli.py) -> register_all_{provider}_checks() -> CheckRegistry
             -> create_{provider}_session(config) -> {Provider}Session
             -> run_scan(config, event_bus) -> ScanResult
             -> export_json / export_markdown / export_pdf
```

### Key Classes

| Class | Module | Purpose |
|-------|--------|---------|
| BaseCheck | engine/models/check.py | Abstract base for all checks |
| CheckResult | engine/models/check.py | Return type of check.execute() |
| CheckError | engine/models/check.py | Error model (message + error_type) |
| Finding | engine/models/finding.py | Single compliance issue |
| ScanResult | engine/models/result.py | Complete scan output |
| ScanConfig | engine/models/config.py | Scan parameters |
| CheckRegistry | engine/registry.py | Singleton check registry |
| EventBus | engine/events.py | Scan event dispatcher |
| AwsSession | engine/providers/aws/session.py | boto3 wrapper |
| AzureSession | engine/providers/azure/session.py | Azure credential wrapper |
| GcpSession | engine/providers/gcp/session.py | Google auth wrapper |

## Key Directories

- `nis2scan/engine/` — Core scan logic, models, providers
- `nis2scan/engine/providers/aws/checks/` — 52 AWS checks (nr1-nr10, all areas)
- `nis2scan/engine/providers/azure/checks/` — 51 Azure checks (nr1-nr10, all areas)
- `nis2scan/engine/providers/gcp/checks/` — 51 GCP checks (nr1-nr10, all areas)
- `nis2scan/engine/mapping/` — §30 BSIG <-> Cloud <-> ISO 27001 mapping data
- `nis2scan/cli/` — Typer CLI (Consumer 1)
- `nis2scan/plugins.py` — Entry-point plugin loader (`nis2scan.plugins` group, ADR-0014/0019); the ONLY premium-related code in this repo
- `nis2scan/reporting/` — Markdown + JSON report generators (PDF lives in nis2scan-premium)
- `infra/aws/` — AWS Terraform test infrastructure + OIDC
- `infra/azure/` — Azure Terraform test infrastructure + OIDC
- `infra/gcp/` — GCP Terraform test infrastructure + Workload Identity Federation
- `tests/integration/` — Real-infrastructure integration tests (per provider)
- `tests/test_checks_aws/` — Unit tests with moto mocks

## Commands

```bash
# Run unit tests (excludes integration)
pytest tests/ -m "not integration" -v --tb=short -n auto

# Run integration tests (requires deployed infra)
pytest tests/integration/test_integration_nr*.py -v -m integration       # AWS
pytest tests/integration/test_integration_azure_*.py -v -m integration   # Azure
pytest tests/integration/test_integration_gcp_*.py -v -m integration     # GCP

# Lint & format
ruff check nis2scan/ tests/
ruff format nis2scan/ tests/

# Type check
mypy nis2scan/

# Run scan
python -m nis2scan scan --provider aws --region eu-central-1
python -m nis2scan scan --provider azure
python -m nis2scan scan --provider gcp

# Show required permissions
python -m nis2scan permissions --provider aws
```

### Windows Development (Git Bash)

```bash
# Python 3.13 venv
py -3.13 -m venv .venv313
source .venv313/Scripts/activate
pip install -e ".[dev]"

# Required env vars for Windows UTF-8
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python -m nis2scan scan --provider aws --region eu-central-1

# GitHub CLI path conversion fix
MSYS_NO_PATHCONV=1 gh workflow run "Integration Tests (AWS)"
```

## Check Implementation Pattern

Every check class MUST follow this pattern:

```python
class CheckExample(BaseCheck):
    check_id = "AWS-NR1-001"              # Provider-NRx-NNN
    title = "German title"                 # German
    description = "German description"     # German
    bsig_30_nr = 1                         # 1-10 (§30 area)
    provider = CloudProvider.AWS           # AWS | AZURE | GCP
    required_permissions = ["service:Action"]
    severity = Severity.HIGH               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    iso_27001_ref = "A.8.9"               # ISO 27001:2022 reference

    async def execute(self, session: AwsSession) -> CheckResult:
        findings = []
        errors = []
        try:
            # API calls, build findings. RAW identifiers — no hashing in checks
            # (ADR-0011: pseudonymization is an export step, --report-profile extern)
            if is_defect:
                findings.append(Finding(
                    check_id=self.check_id,
                    title="German finding title",
                    severity=self.severity,
                    resource_id=resource_id,  # raw ARN/ID
                    expected_state="German expected state",
                    remediation="German remediation instructions",
                    audit_evidence="Machine-readable evidence",
                    # ... all required fields
                ))
            else:
                # Positive evidence (ADR-0006): every passed Prüfobjekt is evidence.
                # Never emit evidence when the state is unknown/errored (ADR-0016).
                findings.append(compliant_finding(  # from nis2scan.engine.evidence
                    self,
                    title="German compliant title",
                    description="German description of the compliant state",
                    region=region, resource_id=resource_id, resource_type="...",
                    account_id=account_id, expected_state="...", audit_evidence="...",
                ))
        except Exception as e:
            errors.append(CheckError(message=str(e), error_type=type(e).__name__))
        return CheckResult(findings=findings, errors=errors)
```

Identifying evidence keys in `current_state` use the suffixes `_name`, `_id`, `_arn`,
`_email` — the extern report profile pseudonymizes exactly these (deny-list, ADR-0011).

### Check Registration

All checks MUST be registered in `nis2scan/engine/providers/{provider}/checks/__init__.py`:

```python
def register_all_aws_checks() -> None:
    registry = CheckRegistry.get_instance()
    from .nr1_risikoanalyse import CheckConfigRecorder, ...
    registry.register(CheckConfigRecorder())
    # ... one register() per check class
```

## Code Conventions

- Use Pydantic BaseModel for all data structures
- Use async/await for all cloud API calls
- Every check module must declare `required_permissions: list[str]`
- Every Finding must reference bsig_30_nr (1-10) and include remediation text in German
- Checks emit RAW identifiers; pseudonymization happens ONLY at report export (`--report-profile extern`, ADR-0011) — never hash inside checks
- Use structured logging (structlog)
- `datetime.UTC` (not `timezone.utc`) — ruff UP017 enforces this on Python 3.12+
- Lazy imports for cloud SDK clients (inside `execute()` methods)
- Graceful error handling: catch API errors, append to `errors`, continue scanning

## Testing Requirements

- Each commit MUST be tested before pushing
- Unit tests: moto for AWS mocking, no real API calls
- Each check needs: test with compliant state, test with non-compliant state, test with API error
- Integration tests: real infrastructure via Terraform, marked with `@pytest.mark.integration`
- Integration test pattern: deploy infra -> run checks -> assert findings -> destroy infra
- Minimum coverage target: 80%
- Run `ruff check` and `ruff format --check` before every commit

## CI/CD & OIDC Authentication

All three providers use OIDC federation — NO static credentials stored anywhere:

### AWS
- GitHub Actions assumes IAM role via OIDC provider
- Secret: `AWS_CI_ROLE_ARN`
- OIDC setup: `infra/aws/oidc/main.tf`
- `AwsSession.client()` uses `region=` keyword (NOT `region_name=`)

### Azure
- GitHub Actions authenticates via Azure AD federated credential
- Secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
- OIDC setup: `infra/azure/oidc/main.tf`

### GCP
- GitHub Actions authenticates via Workload Identity Federation
- Secrets: `GCP_PROJECT_ID`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`
- OIDC setup: `infra/gcp/oidc/main.tf`
- GCP project: `shining-medium-271123`

### Workflow Cleanup Pattern

Every integration workflow has a 4-step cleanup (always runs):
1. Pre-destroy cleanup (provider-specific resource preparation)
2. Terraform destroy
3. Nuke safety net (manual resource deletion fallback)
4. Post-destroy verification (assert zero remaining resources)

## Code Health Guidelines (Empfehlungen, Stand 24.07.2026)

- Pagination: prefer boto3 paginators / SDK-native helpers over manual token
  loops; every list/describe call must handle multi-page results.
- Outer catches: `error_type=type(e).__name__`, never a literal string; one
  try/except PER region so one failing region never silently skips the rest.
- No premature cross-provider abstractions — duplication between the three
  providers is accepted; shared helpers only within one provider.
- Module soft limit ~800 lines; split nr9 modules on the next major touch.
- New blocking SDK calls: keep the future run_blocking/to_thread convention
  in mind (parallelization rebuild is planned) — avoid patterns that make
  that migration harder (module-level clients, hidden global state).
- CONTRIBUTING.md is missing and needed before external contributors arrive
  (post-launch).
- Consider hypothesis-based property tests for pseudonymizer and exceptions
  matching (string-mangling code with security relevance).

## Test-Strategie (Gründer-Vorgabe 24.07.2026, verbindlich)

Testpyramide: Unit (moto/Fakes, jede Check-Logik) → CLI-Paket-Smoke in CI
(Wheel-Install, Exit-Codes) → Integration gegen echte Cloud (Terraform
deployt absichtliche Lücken, Checks laufen, destroy+nuke+verify) → CLI-E2E
gegen echte Infra (geplant: installiertes Paket fährt Kunden-Use-Cases:
Neuinstallation, Scan, Report, Exceptions) → SaaS-UI-e2e (Playwright,
kontinuierlich erweitern). Integrationsläufe sollen Release-Gate für
v*-Tags werden (geplant). Neue Features brauchen Abdeckung auf JEDER
passenden Ebene, nicht nur Unit.

## Known Pitfalls & Constraints

### CLI
- Integration tests and the SaaS worker call the ENGINE directly — cli.py has
  no coverage from them. The 0.1.0 `--profile` shadowing bug (ReportProfile
  enum overwrote the AWS profile name, broke every CLI AWS scan) stayed
  invisible until the 24.07.2026 audit. CLI changes need their own tests
  (tests/test_cli/), and a CI smoke test of the CLI surface is planned (P1).
- Exit codes since 0.1.5: 0 = no high/critical findings, 1 = high,
  2 = critical, 3 = scan inconclusive (only errored checks, nothing assessed).

### AWS
- `AwsSession.client()` uses `region=` NOT `region_name=` — this is a custom wrapper
- CLI flag is `--region` (singular), NOT `--regions`
- AWS rejects IAM trust policies referencing fake account IDs (e.g., 123456789012) — use positive-path testing instead
- KMS keys have 7-day mandatory pending deletion — cannot be immediately removed
- MFA virtual devices and login profiles must be deleted before IAM user deletion

### Azure
- Service principal needs Reader + specific provider registrations
- Resource groups tagged with `Project=nis2scan` for cleanup identification

### GCP
- KMS keys/keyrings are PERMANENT — cannot be deleted, only scheduled for destruction (24h minimum)
- Cloud Asset Inventory has eventual consistency — allow 30s propagation delay after resource deletion
- Post-destroy verification excludes KMS asset types (expected pending deletion)
- `gcloud storage` (not `gsutil`) for GCS operations in CI

### Terraform
- Test infrastructure uses random suffix to avoid naming conflicts between concurrent runs
- All resources tagged/labeled with `project=nis2scan` + `managed-by=terraform`
- `force_destroy = true` on all GCS buckets and S3 buckets

### Ruff
- Line length: 120 characters max
- UP017: Use `datetime.UTC` not `timezone.utc`
- Target version: py312 (use modern type hints: `list[str]` not `List[str]`)
- Per-file ignores for cli.py: B008 (typer.Option defaults), A002 (--format flag)

## §30 BSIG Areas (10 Mandatory Measures)

| Nr | German Name | English | Checks |
|----|------------|---------|--------|
| 1 | Risikoanalyse und IT-Sicherheitskonzepte | Risk analysis & IT security concepts | Config, SecurityHub, CloudTrail, GuardDuty, SCPs |
| 2 | Bewaltigung von Sicherheitsvorfallen | Incident handling | GuardDuty, CloudWatch Alarms, Detective, EventBridge |
| 3 | Aufrechterhaltung des Betriebs (BCM) | Business continuity | Backups, Multi-AZ, S3 versioning, Route53 health |
| 4 | Sicherheit der Lieferkette | Supply chain security | RAM sharing, Organizations, Cross-account roles, SCPs |
| 5 | Sicherheit bei Erwerb/Entwicklung/Wartung | Acquisition/dev security | ECR scanning, Inspector, SSM patching, AMI age |
| 6 | Bewertung der Wirksamkeit | Effectiveness assessment | Config Rules, CloudTrail integrity, audit logging |
| 7 | Grundlegende Schulungen und Sensibilisierung | Basic training & awareness | Password policy, IAM best practices, security awareness |
| 8 | Kryptographie | Cryptography | S3/EBS/RDS encryption, KMS, TLS, certificate management |
| 9 | Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung | Personnel security, access control & ICT mgmt | IAM policies, MFA, Security Groups, public access |
| 10 | MFA und gesicherte Kommunikation | MFA & secure communication | MFA enforcement, VPN, SES/SNS TLS, break-glass |

## Repo Split (ADR-0014/0019/0023)

This repo is the FREE tier (Apache 2.0) — no premium code, no paywall logic
beyond the entry-point plugin loader in `nis2scan/plugins.py`.

- `../nis2scan-premium` (private) — Professional features as plugin package
  `nis2scan_premium` with entry point `nis2scan.plugins:premium`; pins a
  compatible nis2scan minor range via `NIS2SCAN_REQUIRES` (checked by the loader,
  German error on mismatch, ADR-0019).
- `../nis2scan-saas` (private) — Enterprise: FastAPI backend (`nis2scan_saas`),
  Next.js frontend, Celery worker, docker-compose. Own deploy unit.

## Licensing Model (konsolidierte Feature-Matrix, ADR-0023)

| Tier | Features | Code-Heimat |
|------|----------|-------------|
| FREE | CLI-Scan (alle Checks, alle Provider), Rechts-Mapping, JSON/Markdown-Reports (Profile intern/extern), Attestierungs-Checkliste, Permissions-Generator | `nis2scan` (Apache 2.0) |
| PROFESSIONAL | + PDF-Report, Remediation-as-Code, Continuous Monitoring (Scheduled Scans, Drift, Trend), Multi-Account-Scan, E-Mail-Alerts | `nis2scan-premium` (Plugin) |
| ENTERPRISE | + SaaS-Dashboard, Multi-Tenant + RBAC, REST-API, SSO, Custom Mappings, Audit-Log | `nis2scan-saas` |

Grundsatz: Free ist ein vollständig nützliches Werkzeug; Premium verkauft
Komfort und Skala, nie Korrektheit.
