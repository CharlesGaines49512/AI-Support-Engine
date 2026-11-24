from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from app.models.enums import IncidentPriority


class IncidentCategory(StrEnum):
    """Standardized AI incident classifications."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    NETWORK = "network"
    APPLICATION = "application"
    INTEGRATION = "integration"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    DATA = "data"
    OTHER = "other"
    UNKNOWN = "unknown"


class IncidentSeverity(StrEnum):
    """Estimated technical impact of an incident."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


MissingInformation = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=500,
    ),
]


class IncidentAnalysisResult(BaseModel):
    """Validated AI-generated incident analysis."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    suggested_category: IncidentCategory

    recommended_priority: IncidentPriority | None

    recommended_severity: IncidentSeverity

    summary: str = Field(
        min_length=1,
        max_length=2000,
    )

    justification: str = Field(
        min_length=1,
        max_length=3000,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        allow_inf_nan=False,
    )

    insufficient_evidence: bool

    missing_information: list[MissingInformation] = Field(
        max_length=10,
    )

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        """Ensure uncertainty is represented consistently."""
        if (
            self.suggested_category == IncidentCategory.UNKNOWN
            or self.recommended_severity == IncidentSeverity.UNKNOWN
            or self.recommended_priority is None
        ) and not self.insufficient_evidence:
            raise ValueError(
                "Unknown recommendations require an insufficient evidence indicator."
            )

        if self.insufficient_evidence and not self.missing_information:
            raise ValueError("Insufficient evidence requires missing information.")

        return self
