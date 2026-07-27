"""Tests for the permissions generators — AWS IAM, Azure RBAC, GCP custom role (ADR-0020)."""

import json

import pytest
from typer.testing import CliRunner

from nis2scan.cli.cli import (
    _generate_azure_rbac_terraform,
    _generate_gcp_role_terraform,
    _generate_terraform_policy,
)

runner = CliRunner()


class TestAzureRbacGenerator:
    def test_arm_actions_in_role_definition(self):
        tf = _generate_azure_rbac_terraform(
            ["Microsoft.Security/securityContacts/read", "Microsoft.Insights/actionGroups/read"]
        )

        assert 'resource "azurerm_role_definition" "nis2scan_readonly"' in tf
        assert '"Microsoft.Security/securityContacts/read"' in tf
        assert '"Microsoft.Insights/actionGroups/read"' in tf
        assert "not_actions = []" in tf

    def test_graph_permissions_separated_from_rbac(self):
        tf = _generate_azure_rbac_terraform(["Microsoft.Storage/storageAccounts/read", "Policy.Read.All"])

        assert '"Microsoft.Storage/storageAccounts/read"' in tf
        # Graph permissions must not land in the RBAC actions list.
        assert '"Policy.Read.All"' not in tf
        assert "#   - Policy.Read.All" in tf
        assert "admin-consent" in tf

    def test_no_graph_section_without_graph_permissions(self):
        tf = _generate_azure_rbac_terraform(["Microsoft.Storage/storageAccounts/read"])

        assert "Microsoft-Graph" not in tf


class TestGcpRoleGenerator:
    def test_custom_role_and_binding(self):
        tf = _generate_gcp_role_terraform(["compute.instances.list", "resourcemanager.projects.getIamPolicy"])

        assert 'resource "google_project_iam_custom_role" "nis2scan_readonly"' in tf
        assert '"compute.instances.list"' in tf
        assert '"resourcemanager.projects.getIamPolicy"' in tf
        assert 'resource "google_project_iam_member" "nis2scan_readonly"' in tf
        assert "serviceAccount:${var.nis2scan_service_account}" in tf


class TestAwsGeneratorUnchanged:
    def test_iam_policy(self):
        tf = _generate_terraform_policy(["s3:GetBucketLocation", "iam:ListUsers"])

        assert 'resource "aws_iam_policy" "nis2scan_readonly"' in tf
        assert '"s3:GetBucketLocation"' in tf


class TestPermissionsCommand:
    def test_azure_terraform_via_cli(self):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "azure", "--format", "terraform"])

        assert result.exit_code == 0
        assert "azurerm_role_definition" in result.output

    def test_gcp_terraform_via_cli(self):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "gcp", "--format", "terraform"])

        assert result.exit_code == 0
        assert "google_project_iam_custom_role" in result.output


class TestPermissionsMachineFormatsNotWrapped:
    """Fix 1 (hardening audit 27.07.2026): --format terraform/json is consumed by
    tools (``nis2scan permissions --format terraform > policy.tf``), not read on
    a terminal. Rich wraps output at 80 columns whenever stdout is not a TTY —
    which CliRunner's captured stdout never is — and that used to split
    single-line HCL string/comment literals mid-token, producing invalid HCL.
    Machine formats must therefore go through plain print(), never console.print().
    """

    # The description string embedded verbatim (single line) in every
    # generator's Terraform output — a Rich line-wrap would break this exact
    # substring match by inserting a newline somewhere inside it.
    _DESCRIPTION = "Minimal read-only permissions for nis2scan NIS2 compliance scanner"

    @pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
    def test_terraform_description_string_is_not_line_wrapped(self, provider: str):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", provider, "--format", "terraform"])

        assert result.exit_code == 0, result.output
        assert self._DESCRIPTION in result.output

    def test_azure_terraform_graph_comment_is_not_line_wrapped(self):
        """The Azure generator's Microsoft-Graph comment block is the other
        confirmed casualty of Rich's line wrap: a wrapped continuation line
        loses its leading '#' and stops being a comment at all."""
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "azure", "--format", "terraform"])

        assert result.exit_code == 0, result.output
        assert "# Zusätzlich benötigte Microsoft-Graph-Berechtigungen (Application permissions)." in result.output
        assert "# az ad app permission add --id <APP_ID> --api 00000003-0000-0000-c000-000000000000 \\" in result.output

    @pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
    def test_json_output_is_parseable(self, provider: str):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", provider, "--format", "json"])

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0
        assert all(isinstance(p, str) for p in parsed)

    def test_list_format_still_uses_rich(self):
        """The human-facing 'list' format is unaffected — it may still wrap."""
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "aws", "--format", "list"])

        assert result.exit_code == 0, result.output
        assert "Benötigte AWS Permissions" in result.output
