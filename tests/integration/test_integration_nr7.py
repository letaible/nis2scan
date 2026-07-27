"""Integration tests for §30 Abs. 2 Nr. 7 — Cyberhygiene checks."""

import pytest

from nis2scan.engine.models.finding import Severity
from nis2scan.engine.providers.aws.checks.nr7_cyberhygiene import (
    CheckIamPasswordPolicy,
    CheckRootAccessKeys,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR7001PasswordPolicy:
    """Test IAM password policy check against real infrastructure.

    The Terraform module sets a weak password policy (min length 8, missing
    uppercase and symbols requirements).
    """

    @pytest.mark.asyncio
    async def test_weak_policy_detected(self, aws_session, tf_outputs):
        check = CheckIamPasswordPolicy()
        result = await check.execute(aws_session)

        assert result.errors == []
        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.HIGH
        # Verify the finding identifies specific issues
        assert result.findings[0].current_state["minimum_password_length"] < 14


@pytest.mark.integration
class TestNR7002RootAccessKeys:
    """Test root account access keys check.

    Positive-path only — we cannot create/delete root access keys in CI.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckRootAccessKeys()
        result = await check.execute(aws_session)
        assert result.errors == []
