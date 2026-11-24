from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import IncidentNotFoundError
from app.models import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus
from app.repositories import IncidentRepository
from app.schemas.ai_metrics import AIUsageMetrics


class AIMetricsService:
    """Aggregate persisted AI usage and execution metrics."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._incidents = IncidentRepository(session)

    def get_metrics(
        self,
        incident_id: UUID | None = None,
    ) -> AIUsageMetrics:
        """Retrieve global or incident-specific AI metrics."""
        if incident_id is not None and self._incidents.get_by_id(incident_id) is None:
            raise IncidentNotFoundError(incident_id)

        statement = select(
            func.count(AIAnalysis.id).label("total_analyses"),
            func.count(AIAnalysis.id)
            .filter(AIAnalysis.status == AIAnalysisStatus.SUCCEEDED)
            .label("successful_analyses"),
            func.count(AIAnalysis.id)
            .filter(AIAnalysis.status == AIAnalysisStatus.FAILED)
            .label("failed_analyses"),
            func.avg(AIAnalysis.latency_ms).label("average_latency_ms"),
            func.count(AIAnalysis.latency_ms).label("latency_sample_count"),
            func.sum(AIAnalysis.input_tokens).label("total_input_tokens"),
            func.sum(AIAnalysis.output_tokens).label("total_output_tokens"),
            func.sum(AIAnalysis.cached_input_tokens).label("total_cached_input_tokens"),
            func.sum(AIAnalysis.total_tokens).label("total_tokens"),
            func.count(AIAnalysis.input_tokens).label("input_usage_sample_count"),
            func.count(AIAnalysis.output_tokens).label("output_usage_sample_count"),
            func.count(AIAnalysis.cached_input_tokens).label(
                "cached_usage_sample_count"
            ),
            func.count(AIAnalysis.total_tokens).label("total_usage_sample_count"),
            func.sum(AIAnalysis.estimated_cost_usd).label("estimated_cost_usd"),
            func.count(AIAnalysis.estimated_cost_usd).label("costed_analyses"),
        ).select_from(AIAnalysis)

        if incident_id is not None:
            statement = statement.where(AIAnalysis.incident_id == incident_id)

        result = self._session.execute(statement).one()

        total = result.total_analyses
        successful = result.successful_analyses

        success_rate = round(successful / total * 100, 2) if total > 0 else None

        return AIUsageMetrics(
            total_analyses=total,
            successful_analyses=successful,
            failed_analyses=result.failed_analyses,
            success_rate_percent=success_rate,
            average_latency_ms=result.average_latency_ms,
            latency_sample_count=result.latency_sample_count,
            total_input_tokens=result.total_input_tokens,
            total_output_tokens=result.total_output_tokens,
            total_cached_input_tokens=(result.total_cached_input_tokens),
            total_tokens=result.total_tokens,
            input_usage_sample_count=(result.input_usage_sample_count),
            output_usage_sample_count=(result.output_usage_sample_count),
            cached_usage_sample_count=(result.cached_usage_sample_count),
            total_usage_sample_count=(result.total_usage_sample_count),
            estimated_cost_usd=result.estimated_cost_usd,
            costed_analyses=result.costed_analyses,
            uncosted_analyses=(total - result.costed_analyses),
        )
