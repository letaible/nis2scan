"""CheckOutcomeEntry.error_messages (schema 1.2.0, additive).

Users previously only saw THAT a check errored (error_count), never WHY —
the number-one avoidable support question. The messages now travel with the
contract; the EXTERN profile drops them because raw exception strings may
embed identifiers that no finding names (ADR-0011).
"""

import asyncio

from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.models.finding import CloudProvider
from nis2scan.engine.registry import CheckRegistry
from nis2scan.reporting.pseudonymize import pseudonymize_result


class _FakeErroringCheck(BaseCheck):
    """Minimal fake check producing only errors — no cloud SDK calls."""

    check_id = "TST-NR1-001"
    title = "Testcheck"
    description = "Testbeschreibung"
    bsig_30_nr = 1
    provider = CloudProvider.AWS
    required_permissions: list[str] = []

    async def execute(self, session: object) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            findings=[],
            errors=[
                CheckError(
                    message="Unable to locate credentials for arn:aws:iam::123456789012:role/x",
                    error_type="NoCredentialsError",
                ),
                CheckError(message="Zweiter Fehler", error_type="RuntimeError"),
            ],
        )


def _scan_config() -> ScanConfig:
    return ScanConfig(providers={"aws": ProviderConfig(enabled=True)}, bsig_30_scope=[1])


def _run_scan_with_fake_check():
    from nis2scan.engine.scanner import run_scan

    CheckRegistry.reset()
    CheckRegistry.get_instance().register(_FakeErroringCheck())
    try:
        return asyncio.run(run_scan(_scan_config()))
    finally:
        CheckRegistry.reset()


def test_error_messages_travel_with_the_contract():
    result = _run_scan_with_fake_check()
    entry = next(e for e in result.check_outcomes if e.check_id == "TST-NR1-001")
    assert entry.error_count == 2
    assert entry.error_messages == [
        "Unable to locate credentials for arn:aws:iam::123456789012:role/x",
        "Zweiter Fehler",
    ]


def test_extern_profile_drops_error_messages_but_keeps_count():
    result = _run_scan_with_fake_check()
    extern = pseudonymize_result(result)
    entry = next(e for e in extern.check_outcomes if e.check_id == "TST-NR1-001")
    assert entry.error_messages == []
    assert entry.error_count == 2
    # The internal result stays untouched (ADR-0011: never mutate the input).
    original = next(e for e in result.check_outcomes if e.check_id == "TST-NR1-001")
    assert len(original.error_messages) == 2
