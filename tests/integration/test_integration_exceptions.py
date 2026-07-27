"""Integration test for Findings-Exceptions (ADR-0026) against real AWS infrastructure.

Unlike the other files in this package, this test drives a full ``run_scan()``
(not a bare ``check.execute()``) because exception annotation and the
``exceptions_applied``/``exceptions_expired`` metadata counters are only
populated inside the scan orchestrator (nis2scan.engine.scanner), not on the
check result itself. See tests/test_engine/test_scanner_exceptions.py for the
equivalent engine-level unit test this mirrors (fake check, no real infra).

Resource choice: this test targets AWS-NR8-002 (CheckEbsEncryption) against
the unencrypted EBS volume from the NR8 Kryptographie Terraform module
(tf_outputs "non_compliant_ebs_volume_id", see
test_integration_nr8.py::TestNR8002EbsEncryption). The originally suggested
"unencrypted S3 bucket" (AWS-NR8-001) is not usable for this purpose anymore:
since AWS enabled default SSE-S3 encryption for every bucket in Jan 2023, that
Terraform bucket is encrypted regardless of intent and never produces a
Mangel-Finding to except (see test_integration_nr8.py::TestNR8001S3Encryption
docstring) — the EBS volume is the nearest stable, deterministic non-compliant
resource under the same §30 Nr. 8 Kryptographie area.
"""

from pathlib import Path

import pytest

from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.providers.aws.checks.nr8_kryptographie import CheckEbsEncryption
from nis2scan.engine.registry import CheckRegistry
from nis2scan.engine.scanner import run_scan
from tests.integration.conftest import SKIP_UNLESS_GAPS_SCENARIO

pytestmark = SKIP_UNLESS_GAPS_SCENARIO


CHECK_ID = "AWS-NR8-002"
EXCEPTION_REASON = "Bekannte Testinfrastruktur-Abweichung, Ticket INT-TEST-1"


@pytest.fixture(autouse=True)
def _clean_registry():
    """Register only CheckEbsEncryption for a fast, deterministic scan —
    same isolation pattern as tests/test_engine/test_scanner_exceptions.py.
    """
    CheckRegistry.reset()
    CheckRegistry.get_instance().register(CheckEbsEncryption())
    yield
    CheckRegistry.reset()


def _scan_config(tf_outputs: dict, exceptions_path: str | None) -> ScanConfig:
    return ScanConfig(
        providers={
            "aws": ProviderConfig(
                enabled=True,
                regions=[tf_outputs["region"]["value"]],
                accounts=[tf_outputs["account_id"]["value"]],
            )
        },
        bsig_30_scope=[8],
        exceptions_path=exceptions_path,
    )


def _write_exceptions_file(tmp_path: Path, resource_id: str, expires: str) -> Path:
    path = tmp_path / "exceptions.yaml"
    path.write_text(
        "exceptions:\n"
        f"  - check_id: {CHECK_ID}\n"
        f"    resource_id: {resource_id}\n"
        f"    reason: {EXCEPTION_REASON}\n"
        f"    expires: {expires}\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.integration
class TestExceptionsIntegration:
    """End-to-end run_scan() against real infrastructure with an exceptions file."""

    @pytest.mark.asyncio
    async def test_active_exception_annotates_finding_and_metadata(self, tf_outputs: dict, tmp_path: Path) -> None:
        volume_id = tf_outputs["non_compliant_ebs_volume_id"]["value"]
        exceptions_file = _write_exceptions_file(tmp_path, volume_id, expires="2099-01-01")

        result = await run_scan(_scan_config(tf_outputs, str(exceptions_file)))

        matched = [f for f in result.findings if f.resource_id == volume_id]
        assert len(matched) == 1
        finding = matched[0]
        assert finding.exception is not None
        assert finding.exception.reason == EXCEPTION_REASON
        assert finding.expired_exception is None

        # ADR-0026 decision 4: the defect still counts in full in the primary
        # Mängel numbers — the exception is an additive second track only.
        assert result.summary.total_findings >= 1
        assert result.summary.exceptions_accepted_count == 1

        assert result.metadata.exceptions_file == "exceptions.yaml"
        assert result.metadata.exceptions_applied == 1
        assert result.metadata.exceptions_expired == 0

    @pytest.mark.asyncio
    async def test_expired_exception_leaves_finding_fully_open(self, tf_outputs: dict, tmp_path: Path) -> None:
        volume_id = tf_outputs["non_compliant_ebs_volume_id"]["value"]
        exceptions_file = _write_exceptions_file(tmp_path, volume_id, expires="2000-01-01")

        result = await run_scan(_scan_config(tf_outputs, str(exceptions_file)))

        matched = [f for f in result.findings if f.resource_id == volume_id]
        assert len(matched) == 1
        finding = matched[0]
        assert finding.exception is None
        assert finding.expired_exception is not None

        assert result.summary.exceptions_accepted_count == 0
        assert result.metadata.exceptions_applied == 0
        assert result.metadata.exceptions_expired == 1
