import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    ApplicationError,
    IncidentNotFoundError,
)
from app.integrations.ai.exceptions import AIProviderError
from app.integrations.ai.factory import create_ai_provider
from app.integrations.ai.pricing_config import estimate_configured_ai_cost
from app.integrations.ai.provider import AIProvider
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.repositories import (
    AIAnalysisRepository,
    IncidentRepository,
)
from app.schemas.ai_execution import IncidentAnalysisExecution
from app.security import sanitize_text
from app.services.ai_analysis import IncidentAnalysisService
from app.services.ai_errors import describe_ai_failure

logger = logging.getLogger(__name__)


class IncidentChangedDuringAnalysisError(ApplicationError):
    """Indicate that the analyzed incident content is stale."""


@dataclass(frozen=True, slots=True)
class IncidentSnapshot:
    """Detached incident information for asynchronous analysis."""

    id: UUID
    title: str
    description: str


class PersistentAIAnalysisService:
    """Coordinate incident analysis and historical persistence."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        settings: Settings,
        provider_factory: Callable[[Settings], AIProvider] = create_ai_provider,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._provider_factory = provider_factory

    def _get_incident_snapshot(
        self,
        incident_id: UUID,
    ) -> IncidentSnapshot:
        """Read incident data without retaining a database session."""
        with self._session_factory() as session:
            repository = IncidentRepository(session)
            incident = repository.get_by_id(incident_id)

            if incident is None:
                raise IncidentNotFoundError(incident_id)

            return IncidentSnapshot(
                id=incident.id,
                title=incident.title,
                description=incident.description,
            )

    def _persist(
        self,
        snapshot: IncidentSnapshot,
        analysis: AIAnalysis,
    ) -> AIAnalysis:
        """Persist an analysis against unchanged incident content."""
        with self._session_factory() as session:
            try:
                incident = session.get(
                    Incident,
                    snapshot.id,
                    with_for_update=True,
                    populate_existing=True,
                )

                if incident is None:
                    raise IncidentNotFoundError(snapshot.id)

                if (
                    incident.title != snapshot.title
                    or incident.description != snapshot.description
                ):
                    raise IncidentChangedDuringAnalysisError(
                        "Incident content changed during analysis."
                    )

                repository = AIAnalysisRepository(session)
                result = repository.create(analysis)

                # The repository has already flushed and refreshed
                # the record. Detach it before committing to avoid
                # expiration and additional post-commit queries.
                session.expunge(result)
                session.commit()

                return result

            except Exception:
                session.rollback()
                raise

    @staticmethod
    async def _close_provider(
        provider: AIProvider,
    ) -> None:
        """Release resources without replacing the analysis outcome."""
        try:
            await provider.close()
        except Exception:
            logger.warning("AI provider resource cleanup failed.")

    @staticmethod
    def _successful_record(
        incident_id: UUID,
        execution: IncidentAnalysisExecution,
    ) -> AIAnalysis:
        """Convert a validated execution into a database record."""
        response = execution.response
        data = response.data
        usage = response.usage

        return AIAnalysis(
            incident_id=incident_id,
            status=AIAnalysisStatus.SUCCEEDED,
            suggested_category=data.suggested_category.value,
            recommended_priority=(
                data.recommended_priority.value
                if data.recommended_priority is not None
                else None
            ),
            recommended_severity=data.recommended_severity.value,
            summary=sanitize_text(data.summary).text,
            justification=sanitize_text(data.justification).text,
            confidence=data.confidence,
            insufficient_evidence=data.insufficient_evidence,
            missing_information=[
                sanitize_text(item).text for item in data.missing_information
            ],
            provider=response.provider,
            model=response.model,
            prompt_version=response.prompt_version,
            request_id=response.request_id,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
            cached_input_tokens=usage.cached_input_tokens,
            latency_ms=response.latency_ms,
            redaction_count=execution.redaction_count,
            input_characters=execution.input_characters,
        )

    def _failed_record(
        self,
        incident_id: UUID,
        error: AIProviderError,
        latency_ms: float,
    ) -> AIAnalysis:
        """Build a failed analysis without exposing raw errors."""
        failure = describe_ai_failure(error)

        return AIAnalysis(
            incident_id=incident_id,
            status=AIAnalysisStatus.FAILED,
            provider=self._settings.ai_provider,
            model=self._settings.ai_model,
            prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
            latency_ms=latency_ms,
            error_code=failure.code,
            error_message=failure.message,
        )

    async def analyze_incident(
        self,
        incident_id: UUID,
    ) -> AIAnalysis:
        """Analyze an incident and persist its execution history."""
        snapshot = await asyncio.to_thread(
            self._get_incident_snapshot,
            incident_id,
        )

        started_at = perf_counter()

        try:
            provider = self._provider_factory(self._settings)

            try:
                service = IncidentAnalysisService(
                    provider,
                    max_input_chars=self._settings.ai_max_input_chars,
                )

                execution = await service.analyze(
                    title=snapshot.title,
                    description=snapshot.description,
                )
            finally:
                await self._close_provider(provider)

        except AIProviderError as error:
            record = self._failed_record(
                snapshot.id,
                error,
                (perf_counter() - started_at) * 1000,
            )
        else:
            record = self._successful_record(
                snapshot.id,
                execution,
            )

            record.estimated_cost_usd = estimate_configured_ai_cost(
                self._settings,
                provider=execution.response.provider,
                model=execution.response.model,
                usage=execution.response.usage,
            )

        return await asyncio.to_thread(
            self._persist,
            snapshot,
            record,
        )
