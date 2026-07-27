"""Integration tests for §30 Abs. 2 Nr. 3 — Phase 5 checks (RDS Multi-AZ, Backup Plans)."""

import pytest

from nis2scan.engine.providers.aws.checks.nr3_bcm import (
    CheckBackupPlans,
    CheckRdsMultiAz,
)
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


@pytest.mark.integration
class TestNR3004RdsMultiAz:
    """Test RDS Multi-AZ check against real infrastructure.

    CI account has single-AZ RDS instances from nr8_kryptographie module → findings expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckRdsMultiAz()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_single_az_rds_produces_finding(self, aws_session, tf_outputs):
        non_compliant_rds_id = tf_outputs["non_compliant_rds_id"]["value"]
        check = CheckRdsMultiAz()
        result = await check.execute(aws_session)

        # Our non-compliant RDS is single-AZ → should produce finding
        matched = [f for f in result.findings if non_compliant_rds_id in f.resource_id]
        assert len(matched) >= 1
        assert matched[0].check_id == "AWS-NR3-004"


@pytest.mark.integration
class TestNR3005BackupPlans:
    """Test AWS Backup Plans check against real infrastructure.

    Positive-path: CI account has no AWS Backup plans → finding expected.
    """

    @pytest.mark.asyncio
    async def test_check_runs_without_error(self, aws_session):
        check = CheckBackupPlans()
        result = await check.execute(aws_session)
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_no_backup_plans_produces_finding(self, aws_session):
        check = CheckBackupPlans()
        result = await check.execute(aws_session)
        # CI account has no Backup Plans → expect finding
        assert len(result.findings) >= 1
        assert result.findings[0].check_id == "AWS-NR3-005"
