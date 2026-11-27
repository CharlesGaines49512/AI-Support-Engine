from app.core.config import Settings
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
)


def decode_log_payload(
    payload: bytes,
    settings: Settings,
) -> str:
    """Validate and decode an untrusted UTF-8 log payload."""

    if not payload:
        raise InvalidLogPayloadError("Log payload must not be empty.")

    if len(payload) > settings.log_max_payload_bytes:
        raise LogPayloadTooLargeError("Log payload exceeds the configured size limit.")

    try:
        content = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InvalidLogEncodingError(
            "Log payload must contain valid UTF-8 text."
        ) from None

    if any(
        ord(character) < 32
        and character not in "\t\r\n"
        or 127 <= ord(character) <= 159
        for character in content
    ):
        raise InvalidLogEncodingError(
            "Log payload contains unsupported control characters."
        )

    if not content.strip():
        raise InvalidLogPayloadError("Log payload must contain non-whitespace text.")

    return content


def validate_entry_count(
    entry_count: int,
    settings: Settings,
) -> None:
    """Enforce the configured number of extracted events."""

    if entry_count <= 0:
        raise InvalidLogPayloadError("Log payload contains no supported entries.")

    if entry_count > settings.log_max_entries:
        raise LogResourceLimitError("Log entry count exceeds the configured limit.")


def validate_nesting_depth(
    depth: int,
    settings: Settings,
) -> None:
    """Enforce the configured structured-document depth."""

    if depth < 0:
        raise LogResourceLimitError("Log nesting depth cannot be negative.")

    if depth > settings.log_max_nesting_depth:
        raise LogResourceLimitError("Log nesting depth exceeds the configured limit.")
