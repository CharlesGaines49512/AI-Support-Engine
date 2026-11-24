from pydantic import BaseModel, ConfigDict, Field

from app.integrations.ai.contracts import AIResponse
from app.schemas.ai_analysis import IncidentAnalysisResult


class IncidentAnalysisExecution(BaseModel):
    """Incident analysis and application-generated execution metadata."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    response: AIResponse[IncidentAnalysisResult]

    redaction_count: int = Field(ge=0)

    input_characters: int = Field(gt=0)
