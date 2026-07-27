"""Integration tests for §30 Abs. 2 Nr. 10 — MFA & gesicherte Kommunikation checks."""

import pytest

from nis2scan.engine.models.finding import Severity
from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import (
    CheckIamUserMfaEnforcement,
    CheckRootMfa,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR10001RootMfa:
    """Test root MFA check. Do NOT assert finding count (root MFA state unknown in CI)."""

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckRootMfa()
        result = await check.execute(aws_session)
        assert result.errors == []


@pytest.mark.integration
class TestNR10002ConsoleUserMfa:
    """Test console user MFA enforcement check against real infrastructure."""

    @pytest.mark.asyncio
    async def test_console_user_without_mfa_detected(self, aws_session, tf_outputs):
        username = tf_outputs["iam_console_user_no_mfa"]["value"]
        check = CheckIamUserMfaEnforcement()
        result = await check.execute(aws_session)

        matched = [f for f in result.findings if username in f.resource_id]
        assert len(matched) == 1
        assert matched[0].severity == Severity.CRITICAL
