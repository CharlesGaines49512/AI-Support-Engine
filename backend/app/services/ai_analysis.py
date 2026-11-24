from app.integrations.ai.exceptions import AIProviderRequestError
from app.integrations.ai.provider import AIProvider
from app.prompts import build_incident_analysis_request
from app.schemas.ai_analysis import IncidentAnalysisResult
from app.schemas.ai_execution import IncidentAnalysisExecution
from app.security import sanitize_text


class IncidentAnalysisService:
    """Generate structured incident analysis."""

    def __init__(
        self,
        provider: AIProvider,
        *,
        max_input_chars: int | None = None,
    ) -> None:
        if max_input_chars is not None and max_input_chars <= 0:
            raise ValueError("Input budget must be positive.")

        self._provider = provider
        self._max_input_chars = max_input_chars

    async def analyze(
        self,
        *,
        title: str,
        description: str,
    ) -> IncidentAnalysisExecution:
        normalized_title = title.strip()
        normalized_description = description.strip()

        if not normalized_title:
            raise AIProviderRequestError("An incident title is required.")

        if not normalized_description:
            raise AIProviderRequestError("An incident description is required.")

        if len(normalized_title) > 255:
            raise AIProviderRequestError("Incident title exceeds the supported length.")

        if len(normalized_description) > 20000:
            raise AIProviderRequestError(
                "Incident description exceeds the supported length."
            )

        sanitized_title = sanitize_text(normalized_title)
        sanitized_description = sanitize_text(normalized_description)

        request = build_incident_analysis_request(
            title=sanitized_title.text,
            description=sanitized_description.text,
        )

        input_characters = len(request.system_prompt) + len(request.user_prompt)

        if (
            self._max_input_chars is not None
            and input_characters > self._max_input_chars
        ):
            raise AIProviderRequestError(
                "AI request exceeds the configured input limit."
            )

        response = await self._provider.generate_structured(
            request,
            IncidentAnalysisResult,
        )

        return IncidentAnalysisExecution(
            response=response,
            redaction_count=(
                sanitized_title.redaction_count + sanitized_description.redaction_count
            ),
            input_characters=input_characters,
        )
