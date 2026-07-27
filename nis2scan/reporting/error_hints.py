"""Shared helpers to surface WHY checks errored (CLI hint block + Markdown report).

Before this module existed, a scan with e.g. broken credentials only ever
told the user THAT N checks errored, never WHY — the actual boto3/Azure/GCP
exception text was logged at debug level and never reached the console or
the report. Both the CLI (nis2scan/cli/cli.py) and the Markdown report
(nis2scan/reporting/templates/report.md.j2) surface a short, truncated
version of the most common error message so users can self-serve the fix.
"""

from collections import Counter

from nis2scan.engine.models.result import CheckOutcomeEntry

MAX_ERROR_MESSAGE_LENGTH = 160


def truncate_error_message(message: str, max_len: int = MAX_ERROR_MESSAGE_LENGTH) -> str:
    """Collapse whitespace and shorten a raw exception message to a single display line."""
    flattened = " ".join(message.split())
    if len(flattened) <= max_len:
        return flattened
    return flattened[: max_len - 1].rstrip() + "…"


def markdown_table_cell(message: str, max_len: int = MAX_ERROR_MESSAGE_LENGTH) -> str:
    """Truncate AND escape a raw message for safe embedding in a Markdown table cell.

    A raw exception message could contain a literal '|', which would break
    the Markdown table's column structure — escape it like any other
    Markdown-table cell content.
    """
    return truncate_error_message(message, max_len).replace("|", "\\|")


def most_common_error_message(entries: list[CheckOutcomeEntry]) -> str | None:
    """Most frequently occurring raw error message across all check outcomes, or None.

    Returns the RAW (untruncated) message — callers apply truncate_error_message
    or markdown_table_cell themselves depending on the display context.
    """
    messages = [msg for entry in entries for msg in entry.error_messages]
    if not messages:
        return None
    return Counter(messages).most_common(1)[0][0]
