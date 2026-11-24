import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.integrations.ai import (
    AIProviderAuthenticationError,
    AIProviderDisabledError,
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    AIRequest,
    AIResponse,
    AIUsage,
)
from app.models.enums import IncidentPriority
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.schemas.ai_execution import IncidentAnalysisExecution
from app.services.ai_analysis import IncidentAnalysisService


def create_analysis_response() -> AIResponse[IncidentAnalysisResult]:
    """Return a deterministic synthetic AI analysis."""
    return AIResponse[IncidentAnalysisResult](
        data=IncidentAnalysisResult(
            suggested_category=IncidentCategory.DATABASE,
            recommended_priority=IncidentPriority.HIGH,
            recommended_severity=IncidentSeverity.HIGH,
            summary="Database connectivity failure.",
            justification="The application cannot reach the database.",
            confidence=0.90,
            insufficient_evidence=False,
            missing_information=[],
        ),
        provider="openai",
        model="gpt-5.4-mini",
        prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
        request_id="req_synthetic_analysis",
        usage=AIUsage(
            input_tokens=1000,
            output_tokens=200,
            total_tokens=1200,
            cached_input_tokens=100,
        ),
        latency_ms=250.0,
    )


@pytest.fixture
def provider() -> AsyncMock:
    """Provide a mocked AI provider without network access."""
    mock_provider = AsyncMock()

    mock_provider.generate_structured.return_value = create_analysis_response()

    return mock_provider


@pytest.fixture
def service(
    provider: AsyncMock,
) -> IncidentAnalysisService:
    return IncidentAnalysisService(provider)


def test_successful_incident_analysis(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    execution = asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="The database connection timed out.",
        )
    )

    assert isinstance(execution, IncidentAnalysisExecution)
    assert execution.response.data.suggested_category == (IncidentCategory.DATABASE)
    assert execution.response.data.recommended_priority == (IncidentPriority.HIGH)
    assert execution.response.data.recommended_severity == (IncidentSeverity.HIGH)
    assert execution.response.data.confidence == 0.90
    assert execution.redaction_count == 0
    assert execution.input_characters > 0

    provider.generate_structured.assert_awaited_once()


def test_provider_receives_correct_schema(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="Connection timed out.",
        )
    )

    arguments = provider.generate_structured.await_args
    assert arguments is not None

    request, schema = arguments.args

    assert isinstance(request, AIRequest)
    assert schema is IncidentAnalysisResult
    assert request.prompt_version == (INCIDENT_ANALYSIS_PROMPT_VERSION)


def test_sensitive_information_sanitized(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    execution = asyncio.run(
        service.analyze(
            title="Incident reported by user@example.com",
            description=("Database connection failed. password=synthetic-password"),
        )
    )

    arguments = provider.generate_structured.await_args
    assert arguments is not None

    request = arguments.args[0]
    context = json.loads(request.user_prompt)

    assert "user@example.com" not in request.user_prompt
    assert "synthetic-password" not in request.user_prompt

    assert "[REDACTED_EMAIL]" in context["title"]
    assert "[REDACTED_SECRET]" in context["description"]

    assert execution.redaction_count == 2


def test_original_input_preserved(
    service: IncidentAnalysisService,
) -> None:
    original_title = "Incident reported by user@example.com"
    original_description = "password=synthetic-password"

    asyncio.run(
        service.analyze(
            title=original_title,
            description=original_description,
        )
    )

    assert original_title == ("Incident reported by user@example.com")
    assert original_description == ("password=synthetic-password")


def test_input_character_count(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    execution = asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="Connection timed out.",
        )
    )

    arguments = provider.generate_structured.await_args
    assert arguments is not None

    request = arguments.args[0]

    assert execution.input_characters == (
        len(request.system_prompt) + len(request.user_prompt)
    )


def test_operational_metadata_preserved(
    service: IncidentAnalysisService,
) -> None:
    execution = asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="Connection timed out.",
        )
    )

    assert execution.response.provider == "openai"
    assert execution.response.model == "gpt-5.4-mini"
    assert execution.response.request_id == ("req_synthetic_analysis")
    assert execution.response.usage.input_tokens == 1000
    assert execution.response.usage.output_tokens == 200
    assert execution.response.usage.total_tokens == 1200
    assert execution.response.latency_ms == 250.0


def test_incident_whitespace_normalized(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    asyncio.run(
        service.analyze(
            title="  Database unavailable  ",
            description="  Connection timed out.  ",
        )
    )

    arguments = provider.generate_structured.await_args
    assert arguments is not None

    request = arguments.args[0]
    context = json.loads(request.user_prompt)

    assert context["title"] == "Database unavailable"
    assert context["description"] == "Connection timed out."


@pytest.mark.parametrize(
    ("title", "description"),
    [
        ("", "Valid description"),
        ("   ", "Valid description"),
        ("Valid title", ""),
        ("Valid title", "   "),
        ("x" * 256, "Valid description"),
        ("Valid title", "x" * 20001),
    ],
)
def test_invalid_incident_input(
    service: IncidentAnalysisService,
    provider: AsyncMock,
    title: str,
    description: str,
) -> None:
    with pytest.raises(AIProviderRequestError):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_incident_input_boundaries(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    asyncio.run(
        service.analyze(
            title="x" * 255,
            description="x" * 20000,
        )
    )

    provider.generate_structured.assert_awaited_once()


@pytest.mark.parametrize(
    "exception_type",
    [
        AIProviderDisabledError,
        AIProviderAuthenticationError,
        AIProviderRateLimitError,
        AIProviderTimeoutError,
        AIProviderUnavailableError,
        AIProviderResponseError,
        AIProviderRequestError,
    ],
)
def test_provider_failure_propagation(
    service: IncidentAnalysisService,
    provider: AsyncMock,
    exception_type: type[AIProviderError],
) -> None:
    provider.generate_structured.side_effect = exception_type(
        "Synthetic provider failure."
    )

    with pytest.raises(exception_type):
        asyncio.run(
            service.analyze(
                title="Database unavailable",
                description="Connection timed out.",
            )
        )

    provider.generate_structured.assert_awaited_once()


def test_service_does_not_close_provider(
    service: IncidentAnalysisService,
    provider: AsyncMock,
) -> None:
    asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="Connection timed out.",
        )
    )

    provider.close.assert_not_awaited()


def test_execution_serialization(
    service: IncidentAnalysisService,
) -> None:
    execution = asyncio.run(
        service.analyze(
            title="Database unavailable",
            description="Connection timed out.",
        )
    )

    restored = IncidentAnalysisExecution.model_validate_json(
        execution.model_dump_json()
    )

    assert restored == execution


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("redaction_count", -1),
        ("input_characters", 0),
        ("input_characters", -1),
        ("unexpected_field", "invalid"),
    ],
)
def test_invalid_execution_metadata(
    field: str,
    value: object,
) -> None:
    payload = {
        "response": create_analysis_response().model_dump(),
        "redaction_count": 0,
        "input_characters": 100,
    }

    data: dict[str, object] = dict(payload)
    data[field] = value

    with pytest.raises(ValidationError):
        IncidentAnalysisExecution.model_validate(data)


def test_execution_is_frozen() -> None:
    execution = IncidentAnalysisExecution(
        response=create_analysis_response(),
        redaction_count=0,
        input_characters=100,
    )

    with pytest.raises(ValidationError):
        execution.redaction_count = 5  # type: ignore[misc]
