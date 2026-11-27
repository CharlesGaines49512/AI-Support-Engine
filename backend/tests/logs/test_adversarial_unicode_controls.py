import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    UnsafeLogContentError,
)
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_UNICODE_CONTROL_CANARY"

UNSUPPORTED_FORMAT_CONTROLS = (
    "\u00ad",
    "\u061c",
    "\u200b",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2060",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\ufeff",
)

SAFE_MESSAGES = (
    "Database connection failed.",
    "Diagnostic message: caf\u00e9",
    "Diagnostic message: cafe\u0301",
    "\u0627\u0644\u062e\u0627\u062f\u0645",
    "\u05e9\u05dc\u05d5\u05dd",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "Service restarted \U0001f680",
    "Developer \U0001f468\u200d\U0001f4bb",
    "Status \u2764\ufe0f",
    "Diagnostic\tmessage",
    "Diagnostic\nmessage",
    "Diagnostic\r\nmessage",
    "Diagnostic\rmessage",
    "Processing\u00a0completed.",
    "Processing\u3000completed.",
)


@pytest.mark.parametrize(
    "character",
    UNSUPPORTED_FORMAT_CONTROLS,
)
@pytest.mark.parametrize(
    "template",
    (
        "Diagnostic{character}message",
        "pass{character}word=" + CANARY,
        "Diagnostic message{character}",
    ),
)
def test_unsupported_format_control_rejected(
    character: str,
    template: str,
) -> None:
    value = template.format(character=character)

    with pytest.raises((InvalidLogEncodingError, UnsafeLogContentError)) as captured:
        validate_sensitive_field(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "character",
    UNSUPPORTED_FORMAT_CONTROLS,
)
@pytest.mark.parametrize(
    "template",
    (
        "Diagnostic{character}message",
        "pass{character}word=" + CANARY,
        "Diagnostic message{character}",
    ),
)
def test_unsupported_format_control_rejected_outbound(
    character: str,
    template: str,
) -> None:
    value = template.format(character=character)

    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "character",
    UNSUPPORTED_FORMAT_CONTROLS,
)
@pytest.mark.parametrize(
    "template",
    (
        "Diagnostic{character}message",
        "pass{character}word=" + CANARY,
        "Diagnostic message{character}",
    ),
)
def test_unsupported_format_control_rejected_metadata(
    character: str,
    template: str,
) -> None:
    sanitizer = LogSanitizer(Settings())
    value = template.format(character=character)

    with pytest.raises((InvalidLogEncodingError, UnsafeLogContentError)) as captured:
        sanitizer.sanitize_source_name(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", SAFE_MESSAGES)
def test_legitimate_unicode_controls_preserved(
    value: str,
) -> None:
    validate_sensitive_field(value)
    validate_outbound_text(value, 2000)

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0


@pytest.mark.parametrize("value", SAFE_MESSAGES)
def test_legitimate_unicode_metadata_preserved(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


LINGUISTIC_JOINERS = (
    "\u200c",
    "\u200d",
)

JOINER_CREDENTIAL_LABELS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret_key",
    "token",
    "secret",
)

LEGITIMATE_JOINER_MESSAGES = (
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "Developer \U0001f468\u200d\U0001f4bb",
    "Developer \U0001f469\u200d\U0001f4bb",
    "Family \U0001f468\u200d\U0001f469\u200d\U0001f467",
    "Diagnostic message: cafe\u0301",
    "Status \u2764\ufe0f",
    "Database connection failed.",
)


@pytest.mark.parametrize("joiner", LINGUISTIC_JOINERS)
@pytest.mark.parametrize("label", JOINER_CREDENTIAL_LABELS)
def test_joiner_obfuscated_credential_rejected(
    joiner: str,
    label: str,
) -> None:
    value = f"{joiner.join(label)}={CANARY}"

    with pytest.raises((InvalidLogEncodingError, UnsafeLogContentError)) as captured:
        validate_sensitive_field(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("joiner", LINGUISTIC_JOINERS)
@pytest.mark.parametrize("label", JOINER_CREDENTIAL_LABELS)
def test_joiner_obfuscated_credential_rejected_outbound(
    joiner: str,
    label: str,
) -> None:
    value = f"{joiner.join(label)}={CANARY}"

    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("joiner", LINGUISTIC_JOINERS)
@pytest.mark.parametrize("label", JOINER_CREDENTIAL_LABELS)
def test_joiner_obfuscated_metadata_rejected(
    joiner: str,
    label: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    value = f"{joiner.join(label)}={CANARY}"

    with pytest.raises((InvalidLogEncodingError, UnsafeLogContentError)) as captured:
        sanitizer.sanitize_source_name(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", LEGITIMATE_JOINER_MESSAGES)
def test_legitimate_joiner_diagnostic_preserved(
    value: str,
) -> None:
    validate_sensitive_field(value)
    validate_outbound_text(value, 2000)

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0


@pytest.mark.parametrize("value", LEGITIMATE_JOINER_MESSAGES)
def test_legitimate_joiner_metadata_preserved(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0
