import json
from typing import Never, cast

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.contracts import ParsedLog, ParsedLogEntry
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    LogResourceLimitError,
    MalformedLogError,
)
from app.parsers.validation import (
    decode_log_payload,
    validate_entry_count,
    validate_nesting_depth,
)

COLLECTION_FIELDS = frozenset({"entries", "logs", "events"})

SUPPORTED_FIELDS = frozenset(
    {
        "timestamp",
        "severity",
        "service_name",
        "message",
        "exception",
        "error_code",
        "correlation_id",
    }
)


def _validate_json_structure(
    content: str,
    settings: Settings,
) -> None:
    """Enforce structural limits before JSON deserialization."""

    stack: list[tuple[str, int]] = []
    in_string = False
    escaped = False

    closing_pairs = {
        "}": "{",
        "]": "[",
    }

    for character in content:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False

            continue

        if character == '"':
            in_string = True

        elif character in "{[":
            stack.append((character, 0))

            validate_nesting_depth(
                len(stack),
                settings,
            )

        elif character == ",":
            if stack and stack[-1][0] == "[":
                opening, separators = stack[-1]
                separators += 1

                validate_entry_count(
                    separators + 1,
                    settings,
                )

                stack[-1] = (opening, separators)

        elif character in "}]":
            if not stack or stack[-1][0] != closing_pairs[character]:
                raise MalformedLogError("JSON log document has invalid structure.")

            stack.pop()


def _reject_numeric_value(value: str) -> Never:
    raise MalformedLogError("JSON log fields must not contain numeric values.")


def _unique_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise MalformedLogError("JSON log document contains a duplicate key.")

        result[key] = value

    return result


def _validate_field(
    name: str,
    value: object,
    settings: Settings,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise MalformedLogError("JSON log fields must contain text or null.")

    if any(
        (ord(character) < 32 and character not in "\t\r\n")
        or 127 <= ord(character) <= 159
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise InvalidLogEncodingError("JSON field contains unsupported characters.")

    value = value.strip()

    limit = (
        settings.log_max_message_chars
        if name in {"message", "exception"}
        else settings.log_max_metadata_chars
    )

    if len(value) > limit:
        raise LogResourceLimitError("JSON field exceeds the configured length limit.")

    return value or None


def _extract_entry(
    value: object,
    position: int,
    settings: Settings,
) -> ParsedLogEntry:
    if not isinstance(value, dict):
        raise MalformedLogError("JSON log entries must be objects.")

    fields: dict[str, str | None] = {}

    for name, field_value in value.items():
        if name not in SUPPORTED_FIELDS:
            raise MalformedLogError("JSON log entry contains an unsupported field.")

        fields[name] = _validate_field(
            name,
            field_value,
            settings,
        )

    message = fields.get("message")

    if not message:
        raise MalformedLogError("JSON log entry requires a nonempty message.")

    return ParsedLogEntry(
        position=position,
        message=message,
        timestamp=fields.get("timestamp"),
        severity=fields.get("severity"),
        service_name=fields.get("service_name"),
        exception=fields.get("exception"),
        error_code=fields.get("error_code"),
        correlation_id=fields.get("correlation_id"),
    )


def _get_entries(document: object) -> list[object]:
    if isinstance(document, list):
        return cast(list[object], document)

    if not isinstance(document, dict):
        raise MalformedLogError("JSON log document must be an object or array.")

    wrapper_fields = COLLECTION_FIELDS.intersection(document.keys())

    if not wrapper_fields:
        return [document]

    if len(document) != 1:
        raise MalformedLogError("JSON collection contains unsupported fields.")

    wrapper = next(iter(wrapper_fields))
    entries = document[wrapper]

    if not isinstance(entries, list):
        raise MalformedLogError("JSON collection must contain an array.")

    return cast(list[object], entries)


class JSONLogParser:
    """Parse supported structured JSON application logs."""

    def parse(
        self,
        payload: bytes,
        settings: Settings,
    ) -> ParsedLog:
        content = decode_log_payload(payload, settings)

        _validate_json_structure(
            content,
            settings,
        )

        try:
            document: object = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_int=_reject_numeric_value,
                parse_float=_reject_numeric_value,
                parse_constant=_reject_numeric_value,
            )
        except json.JSONDecodeError:
            raise MalformedLogError("JSON log document is malformed.") from None

        raw_entries = _get_entries(document)

        validate_entry_count(
            len(raw_entries),
            settings,
        )

        entries = tuple(
            _extract_entry(value, position, settings)
            for position, value in enumerate(
                raw_entries,
                start=1,
            )
        )

        return ParsedLog(
            source_format=LogFormat.JSON,
            payload_bytes=len(payload),
            entries=entries,
        )
