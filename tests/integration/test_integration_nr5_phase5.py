"""Integration tests for §30 Abs. 2 Nr. 5 — Phase 5 checks (SSM Patch Manager Compliance)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckSsmPatchManagerCompliance,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR5003SsmPatchManagerCompliance:
    """Test SSM Patch Manager Compliance check against real infrastructure.

    Positive-path only — like TestNR5002SsmPatchCompliance, the CI account
    deliberately has no EC2 instances (let alone SSM-managed ones). Since the
    W4 §30 Nr.5 Batch-Review (B-Nr.5-4), the "no custom baseline" Mangel only
    fires when SSM-managed instances exist in the region — without a
    Prüfobjekt to apply a baseline to, there is nothing to flag. That branch
    (Mangel with managed instances, positive evidence with a custom baseline)
    is covered by moto-mocked unit tests in
    tests/test_checks_aws/test_nr5_schwachstellen.py::TestCheckSsmPatchManagerCompliance.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckSsmPatchManagerCompliance()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_managed_instances_no_finding(self, aws_session):
        check = CheckSsmPatchManagerCompliance()
        result = await check.execute(aws_session)
        # No SSM-managed instances in the CI account → no Prüfobjekt → no Mangel
        assert result.findings == []
