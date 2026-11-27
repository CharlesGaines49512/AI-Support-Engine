from uuid import UUID

from app.core.config import Settings
from app.logs.ai_evidence_contracts import AIAnalysisLogContext
from app.services.log_query import LogQueryService


class AILogContextService:
    """Build AI analysis context from persisted application logs."""

    def __init__(
        self,
        query_service: LogQueryService,
        settings: Settings,
    ) -> None:
        self._query_service = query_service
        self._settings = settings

    def build_context(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> AIAnalysisLogContext:
        evidence = self._query_service.get_evidence(
            incident_id,
            submission_id,
        )

        context = AIAnalysisLogContext(
            incident_id=incident_id,
            submission_id=submission_id,
            evidence=evidence,
        )

        context.validate(
            self._settings,
            incident_id,
        )

        return context
