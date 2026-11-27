from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.core.config import Settings
from app.models.log_enums import LogFormat


@dataclass(frozen=True, slots=True)
class ParsedLogEntry:
    """Intermediate event data that remains untrusted."""

    position: int
    message: str = field(repr=False)
    timestamp: str | None = field(default=None, repr=False)
    severity: str | None = field(default=None, repr=False)
    service_name: str | None = field(default=None, repr=False)
    exception: str | None = field(default=None, repr=False)
    error_code: str | None = field(default=None, repr=False)
    correlation_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ParsedLog:
    """Intermediate parser output before normalization."""

    source_format: LogFormat
    payload_bytes: int
    entries: tuple[ParsedLogEntry, ...]


@runtime_checkable
class LogParser(Protocol):
    """Shared interface for supported log parsers."""

    def parse(
        self,
        payload: bytes,
        settings: Settings,
    ) -> ParsedLog:
        """Parse untrusted input into intermediate log records."""
        ...
