from app.core.config import Settings
from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.logs.severity import normalize_severity
from app.logs.timestamps import normalize_timestamp
from app.models.log_enums import LogFormat
from app.parsers.contracts import (
    LogParser,
    ParsedLog,
    ParsedLogEntry,
)
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
)
from app.parsers.json_parser import JSONLogParser
from app.parsers.text_parser import TextLogParser
from app.parsers.validation import validate_entry_count
from app.parsers.xml_parser import XMLLogParser


def _normalize_field(
    value: str | None,
    limit: int,
) -> str | None:
    """Validate and normalize an untrusted textual field."""

    if value is None:
        return None

    if any(
        (ord(character) < 32 and character not in "\t\r\n")
        or 127 <= ord(character) <= 159
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise InvalidLogEncodingError("Log field contains unsupported characters.")

    value = value.strip()

    if len(value) > limit:
        raise LogResourceLimitError("Log field exceeds the configured length limit.")

    return value or None


class LogNormalizer:
    """Convert parsed application logs into normalized records."""

    def __init__(
        self,
        settings: Settings,
    ) -> None:
        self._settings = settings

        self._parsers: dict[LogFormat, LogParser] = {
            LogFormat.XML: XMLLogParser(),
            LogFormat.JSON: JSONLogParser(),
            LogFormat.TEXT: TextLogParser(),
        }

    def _normalize_entry(
        self,
        entry: ParsedLogEntry,
        expected_position: int,
    ) -> NormalizedLogEntry:
        if entry.position != expected_position:
            raise MalformedLogError("Log entry positions must be sequential.")

        message_limit = self._settings.log_max_message_chars

        metadata_limit = self._settings.log_max_metadata_chars

        message = _normalize_field(
            entry.message,
            message_limit,
        )

        if message is None:
            raise MalformedLogError("Log entry requires a nonempty message.")

        original_severity = _normalize_field(
            entry.severity,
            metadata_limit,
        )

        timestamp = _normalize_field(
            entry.timestamp,
            metadata_limit,
        )

        return NormalizedLogEntry(
            position=expected_position,
            severity=normalize_severity(original_severity),
            message=message,
            event_timestamp=normalize_timestamp(timestamp),
            original_severity=original_severity,
            service_name=_normalize_field(
                entry.service_name,
                metadata_limit,
            ),
            exception=_normalize_field(
                entry.exception,
                message_limit,
            ),
            error_code=_normalize_field(
                entry.error_code,
                metadata_limit,
            ),
            correlation_id=_normalize_field(
                entry.correlation_id,
                metadata_limit,
            ),
        )

    def normalize(
        self,
        parsed: ParsedLog,
    ) -> NormalizedLog:
        """Normalize intermediate records without sanitizing them."""

        if parsed.payload_bytes <= 0:
            raise InvalidLogPayloadError("Log payload size must be positive.")

        if parsed.payload_bytes > self._settings.log_max_payload_bytes:
            raise LogPayloadTooLargeError(
                "Log payload exceeds the configured size limit."
            )

        validate_entry_count(
            len(parsed.entries),
            self._settings,
        )

        entries = tuple(
            self._normalize_entry(entry, position)
            for position, entry in enumerate(
                parsed.entries,
                start=1,
            )
        )

        return NormalizedLog(
            source_format=parsed.source_format,
            payload_bytes=parsed.payload_bytes,
            entries=entries,
        )

    def parse_and_normalize(
        self,
        payload: bytes,
        source_format: LogFormat,
    ) -> NormalizedLog:
        """Select a parser and normalize its output."""

        parser = self._parsers[source_format]

        parsed = parser.parse(
            payload,
            self._settings,
        )

        return self.normalize(parsed)
