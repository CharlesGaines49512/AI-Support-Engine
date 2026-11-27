from typing import Protocol
from uuid import UUID

from app.core.config import Settings
from app.integrations.ai.contracts import AIRequest, AIResponse
from app.logs.ai_evidence_contracts import AIAnalysisLogContext
from app.logs.security import validate_sensitive_field
from app.prompts.log_enhanced_analysis import (
    build_log_enhanced_prompt,
)
from app.schemas.ai_analysis import IncidentAnalysisResult
from app.schemas.ai_execution import IncidentAnalysisExecution


class LogAnalysisProvider(Protocol):
    """Structured provider interface required by log-enhanced analysis."""

    async def generate_structured(
        self,
        request: AIRequest,
        response_schema: type[IncidentAnalysisResult],
    ) -> AIResponse[IncidentAnalysisResult]: ...


class LogEnhancedAnalysisService:
    """Analyze incidents using bounded application log evidence."""

    def __init__(
        self,
        provider: LogAnalysisProvider,
        settings: Settings,
    ) -> None:
        self._provider = provider
        self._settings = settings

    async def analyze(
        self,
        *,
        incident_id: UUID,
        title: str,
        description: str,
        context: AIAnalysisLogContext,
    ) -> IncidentAnalysisExecution:
        """Generate a structured advisory incident analysis."""

        validate_sensitive_field(title)
        validate_sensitive_field(description)

        prepared = build_log_enhanced_prompt(
            incident_id=incident_id,
            title=title,
            description=description,
            context=context,
            settings=self._settings,
        )

        response = await self._provider.generate_structured(
            prepared.request,
            IncidentAnalysisResult,
        )

        return IncidentAnalysisExecution(
            response=response,
            redaction_count=prepared.redaction_count,
            input_characters=prepared.input_characters,
        )
