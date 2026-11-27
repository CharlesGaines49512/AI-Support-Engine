import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_COMPOUND_SEPARATOR_CANARY"

CREDENTIAL_PARTS = (
    ("api", "key"),
    ("access", "token"),
    ("refresh", "token"),
    ("client", "secret"),
    ("secret", "key"),
)

COMPOUND_SEPARATORS = (
    "  ",
    "__",
    "--",
    "_ ",
    " _",
    "- ",
    " -",
    "\u00a0\u00a0",
    "\u2003\u2009",
    "\u3000\u3000",
    "_\u00a0",
    "\u00a0_",
    "-\u202f",
    "\u202f-",
    "\uff3f\uff3f",
    "\uff0d\uff0d",
    "\uff3f\u3000",
    "\u3000\uff0d",
    " \u2003 ",
    "_-\u00a0",
)

ASSIGNMENTS = tuple(
    f"{left}{separator}{right}={CANARY}"
    for left, right in CREDENTIAL_PARTS
    for separator in COMPOUND_SEPARATORS
)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_compound_separator_redaction(
    value: str,
) -> None:
    result = sanitize_text(value)

    expected = value.removesuffix(CANARY) + "[REDACTED_SECRET]"

    assert result.text == expected
    assert result.redaction_count == 1

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_compound_separator_outbound_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_compound_separator_metadata_redaction(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    expected = value.removesuffix(CANARY) + "[REDACTED_SECRET]"

    assert sanitized == expected
    assert count == 1


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_compound_separator_idempotence(
    value: str,
) -> None:
    first = sanitize_text(value)
    second = sanitize_text(first.text)

    assert CANARY not in first.text
    assert first.redaction_count == 1

    assert second.text == first.text
    assert second.redaction_count == 0

    validate_outbound_text(second.text, 2000)


@pytest.mark.parametrize("separator", COMPOUND_SEPARATORS)
def test_compound_diagnostic_separators_preserved(
    separator: str,
) -> None:
    value = f"Database{separator}connection failed."

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize("separator", COMPOUND_SEPARATORS)
def test_compound_metadata_separators_preserved(
    separator: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    value = f"Database{separator}service"

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize(
    "separator",
    ("\n", "\r", "\r\n", "\n\n"),
)
@pytest.mark.parametrize(
    "label",
    ("api", "secret"),
)
def test_separate_log_lines_not_joined(
    separator: str,
    label: str,
) -> None:
    value = f"{label}{separator}key=diagnostic"

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0
