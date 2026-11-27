from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentCategory,
    IncidentSeverity,
)


class AIAnalysisResponse(BaseModel):
    """Public representation of a persisted AI analysis."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    status: AIAnalysisStatus

    suggested_category: IncidentCategory | None
    recommended_priority: IncidentPriority | None
    recommended_severity: IncidentSeverity | None

    summary: str | None
    justification: str | None

    confidence: float | None = Field(
        ge=0.0,
        le=1.0,
        allow_inf_nan=False,
    )

    insufficient_evidence: bool | None
    missing_information: list[str] | None

    provider: str
    model: str
    prompt_version: str
    request_id: str | None

    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    total_tokens: int | None = Field(ge=0)
    cached_input_tokens: int | None = Field(ge=0)

    estimated_cost_usd: Decimal | None = Field(
        ge=0,
        allow_inf_nan=False,
    )

    latency_ms: float | None = Field(
        ge=0,
        allow_inf_nan=False,
    )

    redaction_count: int | None = Field(ge=0)
    input_characters: int | None = Field(gt=0)

    error_code: str | None
    error_message: str | None

    log_submission_id: UUID | None = None

    log_evidence_version: str | None = Field(
        default=None,
        min_length=1,
        max_length=50,
    )

    log_evidence_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    log_evidence_event_count: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    created_at: datetime
