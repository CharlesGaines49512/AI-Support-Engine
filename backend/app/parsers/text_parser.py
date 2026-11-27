import re
from dataclasses import dataclass, field
from io import StringIO

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.contracts import ParsedLog, ParsedLogEntry
from app.parsers.exceptions import (
    LogResourceLimitError,
    MalformedLogError,
)
from app.parsers.validation import (
    decode_log_payload,
    validate_entry_count,
)

TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ]"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:[.,][0-9]+)?"
    r"(?:Z|[+-][0-9]{2}:?[0-9]{2})?"
    r")(?=\s|$)\s*"
)

SEVERITY_NAMES = (
    r"TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|"
    r"ERROR|ERR|CRITICAL|FATAL|ALERT|EMERGENCY"
)

SEVERITY_PATTERN = re.compile(
    rf"^(?:\[(?P<bracketed>{SEVERITY_NAMES})\]"
    rf"|(?P<plain>{SEVERITY_NAMES}))"
    r"(?=\s|$)\s*",
    re.IGNORECASE,
)

SERVICE_PATTERN = re.compile(
    r"^\[(?P<service>[^\[\]\r\n]+)\]"
    r"(?=\s|$)\s*"
)


@dataclass(slots=True)
class _PendingEvent:
    timestamp: str | None
    severity: str | None
    service_name: str | None
    parts: list[str] = field(default_factory=list)
    message_chars: int = 0

    def append(
        self,
        message: str,
        settings: Settings,
    ) -> None:
        separator_length = 1 if self.parts else 0

        new_length = self.message_chars + separator_length + len(message)

        if new_length > settings.log_max_message_chars:
            raise LogResourceLimitError(
                "Text log message exceeds the configured length limit."
            )

        self.parts.append(message)
        self.message_chars = new_length

    def to_entry(
        self,
        position: int,
    ) -> ParsedLogEntry:
        return ParsedLogEntry(
            position=position,
            message="\n".join(self.parts),
            timestamp=self.timestamp,
            severity=self.severity,
            service_name=self.service_name,
        )


def _validate_metadata(
    value: str,
    settings: Settings,
) -> str:
    value = value.strip()

    if len(value) > settings.log_max_metadata_chars:
        raise LogResourceLimitError(
            "Text log metadata exceeds the configured length limit."
        )

    return value


def _parse_event(
    line: str,
    settings: Settings,
) -> _PendingEvent:
    remaining = line.strip()

    timestamp: str | None = None
    severity: str | None = None
    service_name: str | None = None

    timestamp_match = TIMESTAMP_PATTERN.match(remaining)

    if timestamp_match:
        timestamp = _validate_metadata(
            timestamp_match.group("timestamp"),
            settings,
        )

        remaining = remaining[timestamp_match.end() :]

    severity_match = SEVERITY_PATTERN.match(remaining)

    if severity_match:
        severity = _validate_metadata(
            severity_match.group("bracketed") or severity_match.group("plain"),
            settings,
        )

        remaining = remaining[severity_match.end() :]

        service_match = SERVICE_PATTERN.match(remaining)

        if service_match:
            service_name = (
                _validate_metadata(
                    service_match.group("service"),
                    settings,
                )
                or None
            )

            remaining = remaining[service_match.end() :]

    message = remaining.strip()

    if not message:
        raise MalformedLogError("Text log event requires a nonempty message.")

    event = _PendingEvent(
        timestamp=timestamp,
        severity=severity,
        service_name=service_name,
    )

    event.append(message, settings)

    return event


class TextLogParser:
    """Parse supported line-oriented application logs."""

    def parse(
        self,
        payload: bytes,
        settings: Settings,
    ) -> ParsedLog:
        content = decode_log_payload(
            payload,
            settings,
        )

        entries: list[ParsedLogEntry] = []
        pending: _PendingEvent | None = None

        for line in StringIO(content, newline=None):
            if not line.strip():
                continue

            if pending is not None and line.startswith((" ", "\t")):
                pending.append(
                    line.strip(),
                    settings,
                )

                continue

            if pending is not None:
                entries.append(pending.to_entry(len(entries) + 1))

            validate_entry_count(
                len(entries) + 1,
                settings,
            )

            pending = _parse_event(
                line,
                settings,
            )

        if pending is not None:
            entries.append(pending.to_entry(len(entries) + 1))

        validate_entry_count(
            len(entries),
            settings,
        )

        return ParsedLog(
            source_format=LogFormat.TEXT,
            payload_bytes=len(payload),
            entries=tuple(entries),
        )
