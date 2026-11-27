from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AIAnalysisRequest(BaseModel):
    """Optional diagnostic context for incident analysis."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    log_submission_id: UUID | None = None
