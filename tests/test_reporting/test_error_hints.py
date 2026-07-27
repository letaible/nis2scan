"""Unit tests for nis2scan.reporting.error_hints (Fix 2, hardening audit 27.07.2026).

Shared helpers used by both the CLI credential-hint block and the Markdown
report to surface WHY checks errored, instead of only THAT they did.
"""

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.result import CheckOutcomeEntry
from nis2scan.reporting.error_hints import (
    markdown_table_cell,
    most_common_error_message,
    truncate_error_message,
)


class TestTruncateErrorMessage:
    def test_short_message_is_unchanged(self):
        assert truncate_error_message("Unable to locate credentials") == "Unable to locate credentials"

    def test_long_message_is_truncated_to_max_len(self):
        message = "x" * 300
        truncated = truncate_error_message(message)

        assert len(truncated) <= 160
        assert truncated.endswith("…")

    def test_whitespace_is_collapsed(self):
        assert truncate_error_message("a\n\nb   c") == "a b c"

    def test_custom_max_len(self):
        truncated = truncate_error_message("abcdefghij", max_len=5)

        assert truncated == "abcd…"


class TestMarkdownTableCell:
    def test_pipe_is_escaped(self):
        assert markdown_table_cell("error | broken table") == "error \\| broken table"

    def test_truncation_still_applies(self):
        message = "x" * 300
        cell = markdown_table_cell(message)

        assert len(cell) <= 160


class TestMostCommonErrorMessage:
    def _entry(self, *messages: str) -> CheckOutcomeEntry:
        return CheckOutcomeEntry(
            check_id="AWS-NR1-001",
            bsig_30_nr=1,
            outcome=CheckOutcome.ERROR,
            error_count=len(messages),
            error_messages=list(messages),
        )

    def test_none_without_any_errors(self):
        assert most_common_error_message([]) is None
        assert most_common_error_message([self._entry()]) is None

    def test_returns_the_most_frequent_message(self):
        entries = [
            self._entry("Unable to locate credentials"),
            self._entry("Unable to locate credentials"),
            self._entry("Some other error"),
        ]

        assert most_common_error_message(entries) == "Unable to locate credentials"

    def test_returns_raw_untruncated_message(self):
        long_message = "x" * 300
        entries = [self._entry(long_message)]

        assert most_common_error_message(entries) == long_message
