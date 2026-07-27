# Azure Integration Test Infrastructure

Terraform configuration that deploys compliant AND non-compliant Azure resources
for nis2scan integration testing.

## One-Time Setup

```bash
# 1. Create the OIDC service principal
cd infra/azure/oidc
terraform init
terraform apply -var="subscription_id=YOUR_SUBSCRIPTION_ID"

# 2. Grant admin consent for Graph API permissions (open the URL from output)
# 3. Set GitHub Secrets from the Terraform outputs:
#    - AZURE_CLIENT_ID
#    - AZURE_TENANT_ID
#    - AZURE_SUBSCRIPTION_ID
```

## Test Infrastructure

```bash
# Deploy (CI does this automatically)
cd infra/azure
terraform init
terraform apply -auto-approve

# Export outputs for tests
terraform output -json > ../../tests/integration/az_tf_outputs.json

# Run tests
pytest tests/integration/test_integration_az_*.py -v -m integration

# Destroy (always!)
terraform destroy -auto-approve
```

## Scenarios (Task #54, AWS als Muster — siehe infra/aws/README-Analogon)

`terraform apply -var="scenario=hardened"` (or `TF_VAR_scenario=hardened`) switches
every supported fixture from its intentional gap to the compliant configuration.
`scenario=mixed` applies a deterministic, hand-assigned split (see
`main.tf::local.fixture_compliance_mixed`). Default is `gaps` — today's
behaviour, unchanged. See `main.tf` for the full explanation of why several
Azure checks (Subscription-weite Aggregat-Checks) need cross-module
coordination that AWS's per-resource checks don't, and `outputs.tf` for the
`fixture_expectations` output that `test_integration_az_nr0_scenarios.py`
reads instead of hard-coding expectations. Legacy per-nr test files
(`test_integration_az_nr1.py` .. `nr10.py`) only run in `scenario=gaps`
(`tests/integration/conftest.py::SKIP_UNLESS_GAPS_SCENARIO`).

## Modules

| Module | Check IDs | Resources | Scenario-togglable | Cost |
|--------|-----------|-----------|---------------------|------|
| nr3_bcm | NR3-003, NR3-006 | Storage Accounts (GRS vs LRS), immutable container | both | ~$0.01 |
| nr5_schwachstellen | NR5-003 | Container Registries (Standard vs Basic) | yes | ~$0.01 |
| nr6_wirksamkeit | NR6-003, NR6-004 | Log Analytics (365d vs 30d), Key Vault | NR6-003 only (NR6-004 hardened_supported=false) | ~$0.01 |
| nr8_kryptographie | NR8-001, NR8-004, NR8-005 | Storage (CMK vs PMK), Key Vaults, App Services | NR8-004/-005 only (NR8-001 hardened_supported=false) | ~$0.02 |
| nr9_zugriffskontrolle | NR9-003, NR9-004 | NSGs (restricted vs open), Storage (private vs public) | both | ~$0.00 |

**Total per run: ~$0.05 (gaps/mixed) / ~$0.05 (hardened, +2 immutable-storage
resources) | Lifetime: ~15 min**
