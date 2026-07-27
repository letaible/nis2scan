"""Fixtures for integration tests against real AWS and Azure infrastructure."""

import json
import os
from pathlib import Path

import boto3
import pytest

TF_OUTPUTS_PATH = Path(__file__).parent / "tf_outputs.json"
AZ_TF_OUTPUTS_PATH = Path(__file__).parent / "az_tf_outputs.json"
GCP_TF_OUTPUTS_PATH = Path(__file__).parent / "gcp_tf_outputs.json"

# --- Scenario support, alle drei Provider (Task #54, Gründer-Vorgabe 27.07.2026) ---
# The AWS, Azure and GCP Terraform test infrastructures (infra/aws/,
# infra/azure/, infra/gcp/) all support three scenarios (variable "scenario"
# in infra/{aws,azure,gcp}/variables.tf): "gaps" (today's behaviour, all
# intentional gaps open), "hardened" (every supported gap closed), and
# "mixed" (a deterministic, hand-assigned split — see the respective
# main.tf::local.fixture_compliance_mixed and the scope notes in each
# outputs.tf). All three providers read the SAME NIS2SCAN_SCENARIO env var
# (set by the matching CI workflow's scenario matrix) and share this ONE
# marker below — there is no per-provider variant.
#
# Every legacy integration test file EXCEPT the per-provider
# test_integration_*nr0_scenarios.py files (which read their expectations
# from the Terraform output "fixture_expectations" instead of hard-coding
# them) and the test_integration_*nr0_cli_e2e.py files (whose assertions are
# already scenario-tolerant — see their own scenario-aware asserts) is
# hard-wired to the "gaps" state: they compare literal severities/resource
# states that only hold when every gap is open. Applying
# SKIP_UNLESS_GAPS_SCENARIO as a module-level ``pytestmark`` in those files
# skips them cleanly whenever NIS2SCAN_SCENARIO is set to anything other than
# "gaps" (or left unset — "gaps" is the default, matching local dev runs and
# today's CI behaviour).
INTEGRATION_SCENARIO = os.environ.get("NIS2SCAN_SCENARIO", "gaps")

SKIP_UNLESS_GAPS_SCENARIO = pytest.mark.skipif(
    INTEGRATION_SCENARIO != "gaps",
    reason=(
        f"NIS2SCAN_SCENARIO={INTEGRATION_SCENARIO!r} != 'gaps': diese Tests sind fest auf den "
        "urspruenglichen Luecken-Zustand verdrahtet und gelten nur fuer das Szenario 'gaps'. "
        "Szenario-bewusste Assertions fuer 'hardened'/'mixed' siehe "
        "test_integration_nr0_scenarios.py (AWS), test_integration_az_nr0_scenarios.py (Azure) "
        "bzw. test_integration_gcp_nr0_scenarios.py (GCP), die ihre Erwartungen aus dem "
        "jeweiligen Terraform-Output 'fixture_expectations' lesen."
    ),
)


@pytest.fixture(scope="session")
def tf_outputs():
    """Load Terraform outputs. Skip all integration tests if not available."""
    if not TF_OUTPUTS_PATH.exists():
        pytest.skip("No tf_outputs.json — integration infrastructure not deployed")
    with open(TF_OUTPUTS_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def aws_session(tf_outputs):
    """Create a real AwsSession for integration testing."""
    from nis2scan.engine.providers.aws.session import AwsSession

    region = tf_outputs["region"]["value"]
    session = boto3.Session(region_name=region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    return AwsSession(session=session, regions=[region], accounts=[account_id])


@pytest.fixture(scope="session")
def az_tf_outputs():
    """Load Azure Terraform outputs. Skip Azure integration tests if not available."""
    if not AZ_TF_OUTPUTS_PATH.exists():
        pytest.skip("No az_tf_outputs.json — Azure integration infrastructure not deployed")
    with open(AZ_TF_OUTPUTS_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def azure_session():
    """Create a real AzureSession for integration testing."""
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        pytest.skip("AZURE_SUBSCRIPTION_ID not set — skipping Azure integration tests")

    from azure.identity import DefaultAzureCredential

    from nis2scan.engine.providers.azure.session import AzureSession

    credential = DefaultAzureCredential()
    return AzureSession(credential=credential, subscription_ids=[sub_id])


@pytest.fixture(scope="session")
def gcp_tf_outputs():
    """Load GCP Terraform outputs. Skip GCP integration tests if not available."""
    if not GCP_TF_OUTPUTS_PATH.exists():
        pytest.skip("No gcp_tf_outputs.json — GCP integration infrastructure not deployed")
    with open(GCP_TF_OUTPUTS_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def gcp_session():
    """Create a real GcpSession for integration testing."""
    project_id = os.environ.get("GCP_PROJECT_ID")
    if not project_id:
        pytest.skip("GCP_PROJECT_ID not set — skipping GCP integration tests")

    import google.auth  # type: ignore[import-untyped]

    from nis2scan.engine.providers.gcp.session import GcpSession

    credentials, _ = google.auth.default()
    return GcpSession(credentials=credentials, project_ids=[project_id])
