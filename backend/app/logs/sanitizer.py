from app.core.config import Settings
from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.logs.security import (
    PRIVATE_KEY_BOUNDARY,
    validate_sensitive_field,
)
from app.parsers.exceptions import (
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.parsers.validation import validate_entry_count
from app.security.sanitizer import sanitize_text

REDACTED_FIELD = "[REDACTED]"


def _sanitize_field(
    value: str | None,
    limit: int,
) -> tuple[str | None, int]:
    """Redact a field without exceeding its configured size."""

    if value is None:
        return None, 0

    validate_sensitive_field(value)

    result = sanitize_text(value)

    sanitized = result.text
    count = result.redaction_count

    if PRIVATE_KEY_BOUNDARY.search(sanitized) is not None:
        return REDACTED_FIELD, count + 1

    if len(sanitized) > limit:
        return REDACTED_FIELD, count + 1

    try:
        validate_outbound_text(sanitized, limit)
    except UnsafeOutboundEvidenceError:
        raise UnsafeLogContentError(
            "Sanitized log field contains unsafe content."
        ) from None

    return sanitized, count


class LogSanitizer:
    """Apply existing sensitive-data redaction to normalized logs."""

    def __init__(
        self,
        settings: Settings,
    ) -> None:
        self._settings = settings

    def _sanitize_entry(
        self,
        entry: NormalizedLogEntry,
    ) -> SanitizedLogEntry:
        message_limit = self._settings.log_max_message_chars

        metadata_limit = self._settings.log_max_metadata_chars

        message, message_count = _sanitize_field(
            entry.message,
            message_limit,
        )

        if message is None or not message.strip():
            raise MalformedLogError("Sanitized log entry requires a nonempty message.")

        original_severity, severity_count = _sanitize_field(
            entry.original_severity,
            metadata_limit,
        )

        service_name, service_count = _sanitize_field(
            entry.service_name,
            metadata_limit,
        )

        exception, exception_count = _sanitize_field(
            entry.exception,
            message_limit,
        )

        error_code, error_count = _sanitize_field(
            entry.error_code,
            metadata_limit,
        )

        correlation_id, correlation_count = _sanitize_field(
            entry.correlation_id,
            metadata_limit,
        )

        redaction_count = (
            message_count
            + severity_count
            + service_count
            + exception_count
            + error_count
            + correlation_count
        )

        return SanitizedLogEntry(
            position=entry.position,
            severity=entry.severity,
            message=message,
            event_timestamp=entry.event_timestamp,
            original_severity=original_severity,
            service_name=service_name,
            exception=exception,
            error_code=error_code,
            correlation_id=correlation_id,
            redaction_count=redaction_count,
        )

    def sanitize(
        self,
        normalized: NormalizedLog,
    ) -> SanitizedLog:
        """Sanitize normalized records without modifying the source."""

        if normalized.payload_bytes <= 0:
            raise InvalidLogPayloadError("Log payload size must be positive.")

        if normalized.payload_bytes > self._settings.log_max_payload_bytes:
            raise LogPayloadTooLargeError(
                "Log payload exceeds the configured size limit."
            )

        validate_entry_count(
            normalized.entry_count,
            self._settings,
        )

        entries: list[SanitizedLogEntry] = []

        for position, entry in enumerate(
            normalized.entries,
            start=1,
        ):
            if entry.position != position:
                raise MalformedLogError("Log entry positions must be sequential.")

            entries.append(self._sanitize_entry(entry))

        return SanitizedLog(
            source_format=normalized.source_format,
            payload_bytes=normalized.payload_bytes,
            entries=tuple(entries),
        )

    def sanitize_source_name(
        self,
        source_name: str | None,
    ) -> tuple[str | None, int]:
        """Sanitize optional submission-level source metadata."""

        sanitized, count = _sanitize_field(
            source_name,
            self._settings.log_max_metadata_chars,
        )

        if sanitized is None:
            return None, count

        return sanitized.strip() or None, count
