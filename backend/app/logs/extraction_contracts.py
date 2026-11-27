import json
from dataclasses import dataclass, field

from app.models.log_enums import LogFormat, LogSeverity


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """Selected diagnostic evidence associated with one log event."""

    position: int
    severity: LogSeverity
    score: int
    rule_ids: tuple[str, ...]
    categories: tuple[str, ...]
    details_omitted: bool = False

    message: str | None = field(default=None, repr=False)
    exception: str | None = field(default=None, repr=False)
    error_code: str | None = field(default=None, repr=False)
    service_name: str | None = field(default=None, repr=False)
    event_timestamp: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "position": self.position,
            "severity": self.severity.value,
            "score": self.score,
            "rule_ids": self.rule_ids,
            "categories": self.categories,
            "details_omitted": self.details_omitted,
        }

        optional_fields = (
            ("message", self.message),
            ("exception", self.exception),
            ("error_code", self.error_code),
            ("service_name", self.service_name),
            ("event_timestamp", self.event_timestamp),
        )

        for name, value in optional_fields:
            if value is not None:
                data[name] = value

        return data


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    """Bounded diagnostic evidence prepared for downstream analysis."""

    source_format: LogFormat
    total_events: int
    diagnostic_events: int
    events: tuple[EvidenceEvent, ...]

    @property
    def selected_event_count(self) -> int:
        return len(self.events)

    @property
    def omitted_event_count(self) -> int:
        return self.diagnostic_events - self.selected_event_count

    @property
    def has_evidence(self) -> bool:
        return bool(self.events)

    def to_json(self) -> str:
        return json.dumps(
            {
                "source_format": self.source_format.value,
                "total_events": self.total_events,
                "diagnostic_events": self.diagnostic_events,
                "omitted_events": self.omitted_event_count,
                "events": [event.to_dict() for event in self.events],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )

    @property
    def character_count(self) -> int:
        return len(self.to_json())
