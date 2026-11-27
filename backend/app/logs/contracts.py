from dataclasses import dataclass, field
from datetime import datetime

from app.models.log_enums import LogFormat, LogSeverity


@dataclass(frozen=True, slots=True)
class NormalizedLogEntry:
    """Normalized event that still requires sanitization."""

    position: int
    severity: LogSeverity
    message: str = field(repr=False)
    event_timestamp: datetime | None = None
    original_severity: str | None = field(default=None, repr=False)
    service_name: str | None = field(default=None, repr=False)
    exception: str | None = field(default=None, repr=False)
    error_code: str | None = field(default=None, repr=False)
    correlation_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class NormalizedLog:
    """Normalized submission before sensitive-data sanitization."""

    source_format: LogFormat
    payload_bytes: int
    entries: tuple[NormalizedLogEntry, ...]

    @property
    def entry_count(self) -> int:
        return len(self.entries)
