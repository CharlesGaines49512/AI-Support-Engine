from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus


class AIAnalysisRepository:
    """Provide database access for AI incident analysis records."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, analysis: AIAnalysis) -> AIAnalysis:
        """Persist an analysis within the current transaction."""
        self._session.add(analysis)
        self._session.flush()
        self._session.refresh(analysis)

        return analysis

    def get_by_id(
        self,
        analysis_id: UUID,
    ) -> AIAnalysis | None:
        """Retrieve an analysis by its unique identifier."""
        return self._session.get(AIAnalysis, analysis_id)

    def list_by_incident(
        self,
        incident_id: UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        status: AIAnalysisStatus | None = None,
    ) -> list[AIAnalysis]:
        """Retrieve paginated analysis history for an incident."""
        statement = select(AIAnalysis).where(AIAnalysis.incident_id == incident_id)

        if status is not None:
            statement = statement.where(AIAnalysis.status == status)

        statement = (
            statement.order_by(
                AIAnalysis.created_at.desc(),
                AIAnalysis.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self._session.scalars(statement).all())

    def count_by_incident(
        self,
        incident_id: UUID,
        *,
        status: AIAnalysisStatus | None = None,
    ) -> int:
        """Count analyses associated with an incident."""
        statement = (
            select(func.count())
            .select_from(AIAnalysis)
            .where(AIAnalysis.incident_id == incident_id)
        )

        if status is not None:
            statement = statement.where(AIAnalysis.status == status)

        return int(self._session.execute(statement).scalar_one())

    def get_latest(
        self,
        incident_id: UUID,
    ) -> AIAnalysis | None:
        """Retrieve the most recent analysis attempt."""
        records = self.list_by_incident(
            incident_id,
            limit=1,
        )

        return records[0] if records else None

    def get_latest_successful(
        self,
        incident_id: UUID,
    ) -> AIAnalysis | None:
        """Retrieve the most recent successful analysis."""
        records = self.list_by_incident(
            incident_id,
            limit=1,
            status=AIAnalysisStatus.SUCCEEDED,
        )

        return records[0] if records else None
