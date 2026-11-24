from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import (
    ApplicationError,
    IncidentNotFoundError,
)
from app.models.ai_analysis import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus
from app.repositories import (
    AIAnalysisRepository,
    IncidentRepository,
)
from app.schemas.ai_analysis_response import AIAnalysisResponse
from app.schemas.pagination import PaginatedResponse


class AIAnalysisNotFoundError(ApplicationError):
    """Indicate that a requested analysis does not exist."""


class AIAnalysisQueryService:
    """Provide incident-scoped access to historical AI analyses."""

    def __init__(self, session: Session) -> None:
        self._incidents = IncidentRepository(session)
        self._analyses = AIAnalysisRepository(session)

    def _require_incident(self, incident_id: UUID) -> None:
        if self._incidents.get_by_id(incident_id) is None:
            raise IncidentNotFoundError(incident_id)

    @staticmethod
    def _require_analysis(
        analysis: AIAnalysis | None,
        incident_id: UUID,
    ) -> AIAnalysisResponse:
        if analysis is None or analysis.incident_id != incident_id:
            raise AIAnalysisNotFoundError("The requested AI analysis was not found.")

        return AIAnalysisResponse.model_validate(analysis)

    def get_analysis(
        self,
        incident_id: UUID,
        analysis_id: UUID,
    ) -> AIAnalysisResponse:
        """Retrieve an analysis belonging to the requested incident."""
        self._require_incident(incident_id)

        analysis = self._analyses.get_by_id(analysis_id)

        return self._require_analysis(
            analysis,
            incident_id,
        )

    def list_analyses(
        self,
        incident_id: UUID,
        *,
        offset: int = 0,
        limit: int = 20,
        status: AIAnalysisStatus | None = None,
    ) -> PaginatedResponse[AIAnalysisResponse]:
        """Retrieve filtered and paginated analysis history."""
        if offset < 0:
            raise ValueError("Offset must not be negative.")

        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100.")

        self._require_incident(incident_id)

        records = self._analyses.list_by_incident(
            incident_id,
            offset=offset,
            limit=limit,
            status=status,
        )

        total = self._analyses.count_by_incident(
            incident_id,
            status=status,
        )

        return PaginatedResponse[AIAnalysisResponse](
            items=[AIAnalysisResponse.model_validate(record) for record in records],
            total=total,
            offset=offset,
            limit=limit,
            has_more=offset + len(records) < total,
        )

    def get_latest(
        self,
        incident_id: UUID,
    ) -> AIAnalysisResponse:
        """Retrieve the most recent analysis attempt."""
        self._require_incident(incident_id)

        return self._require_analysis(
            self._analyses.get_latest(incident_id),
            incident_id,
        )

    def get_latest_successful(
        self,
        incident_id: UUID,
    ) -> AIAnalysisResponse:
        """Retrieve the most recent successful analysis."""
        self._require_incident(incident_id)

        return self._require_analysis(
            self._analyses.get_latest_successful(incident_id),
            incident_id,
        )
