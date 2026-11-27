from dataclasses import dataclass, field
from datetime import datetime

from app.models.log_enums import LogFormat, LogSeverity


@dataclass(frozen=True, slots=True)
class SanitizedLogEntry:
    """Log event after recognized sensitive data has been redacted."""

    position: int
    severity: LogSeverity
    message: str = field(repr=False)
    event_timestamp: datetime | None = None
    original_severity: str | None = field(default=None, repr=False)
    service_name: str | None = field(default=None, repr=False)
    exception: str | None = field(default=None, repr=False)
    error_code: str | None = field(default=None, repr=False)
    correlation_id: str | None = field(default=None, repr=False)
    redaction_count: int = 0


@dataclass(frozen=True, slots=True)
class SanitizedLog:
    """Sanitized submission with derived accounting information."""

    source_format: LogFormat
    payload_bytes: int
    entries: tuple[SanitizedLogEntry, ...]

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def redaction_count(self) -> int:
        return sum(entry.redaction_count for entry in self.entries)

    @property
    def was_modified(self) -> bool:
        return self.redaction_count > 0
