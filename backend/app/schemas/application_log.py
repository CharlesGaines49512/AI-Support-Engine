from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.log_enums import LogFormat, LogSeverity


class LogSubmissionResponse(BaseModel):
    """Public metadata for a sanitized log submission."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: UUID
    incident_id: UUID
    source_format: LogFormat
    source_name: str | None = Field(max_length=2000)
    payload_bytes: int = Field(gt=0, le=10485760)
    entry_count: int = Field(gt=0, le=10000)
    redaction_count: int = Field(ge=0)
    created_at: datetime


class LogEntryResponse(BaseModel):
    """Public representation of a sanitized log event."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: UUID
    submission_id: UUID
    position: int = Field(gt=0, le=10000)
    severity: LogSeverity
    message: str = Field(min_length=1, max_length=20000)
    event_timestamp: datetime | None = None

    original_severity: str | None = Field(
        default=None,
        max_length=2000,
    )

    service_name: str | None = Field(
        default=None,
        max_length=2000,
    )

    exception: str | None = Field(
        default=None,
        max_length=20000,
    )

    error_code: str | None = Field(
        default=None,
        max_length=2000,
    )

    correlation_id: str | None = Field(
        default=None,
        max_length=2000,
    )


class LogEvidenceEventResponse(BaseModel):
    """A selected diagnostic event with deterministic relevance."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    position: int = Field(gt=0, le=10000)
    severity: LogSeverity
    score: int = Field(ge=0, le=110)

    rule_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=21,
    )

    categories: tuple[str, ...] = Field(
        min_length=1,
        max_length=12,
    )

    details_omitted: bool

    message: str | None = Field(
        default=None,
        max_length=20000,
    )

    exception: str | None = Field(
        default=None,
        max_length=20000,
    )

    error_code: str | None = Field(
        default=None,
        max_length=2000,
    )

    service_name: str | None = Field(
        default=None,
        max_length=2000,
    )

    event_timestamp: str | None = Field(
        default=None,
        max_length=2000,
    )


class LogEvidencePackageResponse(BaseModel):
    """Bounded diagnostic evidence derived from sanitized logs."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    source_format: LogFormat
    total_events: int = Field(gt=0, le=10000)
    diagnostic_events: int = Field(ge=0, le=10000)
    selected_event_count: int = Field(ge=0, le=100)
    omitted_event_count: int = Field(ge=0, le=10000)

    has_evidence: bool

    events: tuple[LogEvidenceEventResponse, ...] = Field(
        max_length=100,
    )


class LogEvidenceResponse(BaseModel):
    """Incident-scoped diagnostic evidence and trust metadata."""

    model_config = ConfigDict(
        extra="forbid",
    )

    schema_version: Literal["1.0.0"] = "1.0.0"
    trust_level: Literal["untrusted"] = "untrusted"

    evidence_type: Literal["diagnostic_indicators"] = "diagnostic_indicators"

    incident_id: UUID
    submission_id: UUID
    evidence: LogEvidencePackageResponse


class LogIngestionResponse(BaseModel):
    """Result of a committed application log ingestion."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    submission_id: UUID
    incident_id: UUID
    source_format: LogFormat
    source_name: str | None = Field(max_length=2000)
    payload_bytes: int = Field(gt=0, le=10485760)
    entry_count: int = Field(gt=0, le=10000)
    redaction_count: int = Field(ge=0)
    created_at: datetime

    has_diagnostic_evidence: bool
    was_redacted: bool

    evidence: LogEvidencePackageResponse
