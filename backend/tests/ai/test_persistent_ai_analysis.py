import asyncio
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.integrations.ai import (
    AIProviderAuthenticationError,
    AIProviderConfigurationError,
    AIProviderDisabledError,
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    AIResponse,
    AIUsage,
)
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.services.persistent_ai_analysis import (
    PersistentAIAnalysisService,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
    )


@pytest.fixture
def incident() -> Incident:
    return Incident(
        id=uuid4(),
        title="Database unavailable",
        description="Database connection timed out.",
        priority=IncidentPriority.MEDIUM,
    )


@pytest.fixture
def read_session(incident: Incident) -> MagicMock:
    session = MagicMock(spec=Session)
    session.__enter__.return_value = session
    session.get.return_value = incident

    return session


@pytest.fixture
def write_session(incident: Incident) -> MagicMock:
    session = MagicMock(spec=Session)
    session.__enter__.return_value = session
    session.get.return_value = incident

    return session


@pytest.fixture
def session_factory(
    read_session: MagicMock,
    write_session: MagicMock,
) -> MagicMock:
    return MagicMock(
        side_effect=[
            read_session,
            write_session,
        ]
    )


def create_response(
    *,
    unknown: bool = False,
    sensitive: bool = False,
) -> AIResponse[IncidentAnalysisResult]:
    return AIResponse[IncidentAnalysisResult](
        data=IncidentAnalysisResult(
            suggested_category=(
                IncidentCategory.UNKNOWN if unknown else IncidentCategory.DATABASE
            ),
            recommended_priority=(None if unknown else IncidentPriority.HIGH),
            recommended_severity=(
                IncidentSeverity.UNKNOWN if unknown else IncidentSeverity.HIGH
            ),
            summary=(
                "Contact user@example.com."
                if sensitive
                else "Database connectivity failure."
            ),
            justification=(
                "password=synthetic-password"
                if sensitive
                else "The database connection failed."
            ),
            confidence=0.90 if not unknown else 0.10,
            insufficient_evidence=unknown or sensitive,
            missing_information=(
                ["Contact user@example.com"]
                if sensitive
                else ["Business impact"]
                if unknown
                else []
            ),
        ),
        provider="openai",
        model="synthetic-model",
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
    mock_provider = AsyncMock()
    mock_provider.generate_structured.return_value = create_response()

    return mock_provider


@pytest.fixture
def provider_factory(
    provider: AsyncMock,
) -> MagicMock:
    return MagicMock(return_value=provider)


@pytest.fixture
def service(
    session_factory: MagicMock,
    settings: Settings,
    provider_factory: MagicMock,
) -> PersistentAIAnalysisService:
    return PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=provider_factory,
    )


def test_successful_analysis(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    provider_factory: MagicMock,
    settings: Settings,
    write_session: MagicMock,
) -> None:
    result = asyncio.run(service.analyze_incident(incident.id))

    assert isinstance(result, AIAnalysis)
    assert result.incident_id == incident.id
    assert result.status == AIAnalysisStatus.SUCCEEDED
    assert result.suggested_category == "database"
    assert result.recommended_priority == "high"
    assert result.recommended_severity == "high"
    assert result.confidence == 0.90
    assert result.error_code is None
    assert result.error_message is None

    provider_factory.assert_called_once_with(settings)
    provider.generate_structured.assert_awaited_once()
    provider.close.assert_awaited_once()

    write_session.add.assert_called_once_with(result)
    write_session.commit.assert_called_once_with()
    write_session.expunge.assert_called_once_with(result)
    write_session.rollback.assert_not_called()


def test_operational_metadata(
    service: PersistentAIAnalysisService,
    incident: Incident,
) -> None:
    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.provider == "openai"
    assert result.model == "synthetic-model"
    assert result.prompt_version == (INCIDENT_ANALYSIS_PROMPT_VERSION)
    assert result.request_id == "req_synthetic_analysis"
    assert result.input_tokens == 1000
    assert result.output_tokens == 200
    assert result.total_tokens == 1200
    assert result.cached_input_tokens == 100
    assert result.latency_ms == 250.0
    assert result.redaction_count == 0
    assert result.input_characters is not None
    assert result.input_characters > 0
    assert result.estimated_cost_usd is None


def test_unknown_recommendations(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
) -> None:
    provider.generate_structured.return_value = create_response(unknown=True)

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.SUCCEEDED
    assert result.suggested_category == "unknown"
    assert result.recommended_priority is None
    assert result.recommended_severity == "unknown"
    assert result.insufficient_evidence is True
    assert result.missing_information == ["Business impact"]


def test_output_sanitization(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
) -> None:
    provider.generate_structured.return_value = create_response(sensitive=True)

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.summary == "Contact [REDACTED_EMAIL]."
    assert result.justification == ("password=[REDACTED_SECRET]")
    assert result.missing_information == ["Contact [REDACTED_EMAIL]"]


def test_input_sanitization(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
) -> None:
    incident.description = "Connection failed. password=synthetic-password"

    result = asyncio.run(service.analyze_incident(incident.id))

    arguments = provider.generate_structured.await_args
    assert arguments is not None

    request = arguments.args[0]

    assert "synthetic-password" not in request.user_prompt
    assert "[REDACTED_SECRET]" in request.user_prompt
    assert result.redaction_count == 1

    assert incident.description == ("Connection failed. password=synthetic-password")


def test_original_incident_preserved(
    service: PersistentAIAnalysisService,
    incident: Incident,
) -> None:
    original_title = incident.title
    original_description = incident.description
    original_priority = incident.priority
    original_category = incident.category

    asyncio.run(service.analyze_incident(incident.id))

    assert incident.title == original_title
    assert incident.description == original_description
    assert incident.priority == original_priority
    assert incident.category == original_category


def test_missing_incident(
    service: PersistentAIAnalysisService,
    incident: Incident,
    read_session: MagicMock,
    provider_factory: MagicMock,
    write_session: MagicMock,
) -> None:
    read_session.get.return_value = None

    with pytest.raises(IncidentNotFoundError):
        asyncio.run(service.analyze_incident(incident.id))

    provider_factory.assert_not_called()
    write_session.commit.assert_not_called()

    read_session.__exit__.assert_called_once()


def test_incident_deleted_before_persistence(
    service: PersistentAIAnalysisService,
    incident: Incident,
    write_session: MagicMock,
    provider: AsyncMock,
) -> None:
    write_session.get.return_value = None

    with pytest.raises(IncidentNotFoundError):
        asyncio.run(service.analyze_incident(incident.id))

    provider.close.assert_awaited_once()

    write_session.add.assert_not_called()
    write_session.commit.assert_not_called()
    write_session.rollback.assert_called_once_with()


@pytest.mark.parametrize(
    ("exception_type", "expected_code"),
    [
        (
            AIProviderAuthenticationError,
            "provider_authentication",
        ),
        (
            AIProviderRateLimitError,
            "provider_rate_limit",
        ),
        (
            AIProviderTimeoutError,
            "provider_timeout",
        ),
        (
            AIProviderUnavailableError,
            "provider_unavailable",
        ),
        (
            AIProviderRequestError,
            "provider_request",
        ),
        (
            AIProviderResponseError,
            "provider_response",
        ),
        (
            AIProviderError,
            "provider_error",
        ),
    ],
)
def test_provider_failure_persisted(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
    exception_type: type[AIProviderError],
    expected_code: str,
) -> None:
    provider.generate_structured.side_effect = exception_type(
        "password=synthetic-password"
    )

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.FAILED
    assert result.error_code == expected_code
    assert result.error_message is not None
    assert "synthetic-password" not in result.error_message
    assert result.summary is None
    assert result.confidence is None
    assert result.total_tokens is None
    assert result.estimated_cost_usd is None
    assert result.latency_ms is not None
    assert result.latency_ms >= 0

    provider.close.assert_awaited_once()
    write_session.commit.assert_called_once_with()


@pytest.mark.parametrize(
    ("exception_type", "expected_code"),
    [
        (
            AIProviderDisabledError,
            "provider_disabled",
        ),
        (
            AIProviderConfigurationError,
            "provider_configuration",
        ),
    ],
)
def test_provider_factory_failure(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider_factory: MagicMock,
    provider: AsyncMock,
    write_session: MagicMock,
    exception_type: type[AIProviderError],
    expected_code: str,
) -> None:
    provider_factory.side_effect = exception_type("Synthetic configuration failure.")

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.FAILED
    assert result.error_code == expected_code

    provider.generate_structured.assert_not_awaited()
    provider.close.assert_not_awaited()

    write_session.commit.assert_called_once_with()


def test_read_session_released_before_ai_request(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    read_session: MagicMock,
    session_factory: MagicMock,
) -> None:
    async def generate(
        *args: object,
        **kwargs: object,
    ) -> AIResponse[IncidentAnalysisResult]:
        read_session.__exit__.assert_called_once()
        assert session_factory.call_count == 1

        return create_response()

    provider.generate_structured.side_effect = generate

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.SUCCEEDED
    assert session_factory.call_count == 2


def test_separate_database_sessions(
    service: PersistentAIAnalysisService,
    incident: Incident,
    read_session: MagicMock,
    write_session: MagicMock,
    session_factory: MagicMock,
) -> None:
    asyncio.run(service.analyze_incident(incident.id))

    assert session_factory.call_count == 2

    read_session.commit.assert_not_called()
    read_session.__exit__.assert_called_once()
    write_session.__exit__.assert_called_once()
    write_session.commit.assert_called_once_with()


def test_database_flush_failure_rolls_back(
    service: PersistentAIAnalysisService,
    incident: Incident,
    write_session: MagicMock,
    provider: AsyncMock,
) -> None:
    write_session.flush.side_effect = RuntimeError("Synthetic database flush failure.")

    with pytest.raises(RuntimeError):
        asyncio.run(service.analyze_incident(incident.id))

    write_session.rollback.assert_called_once_with()
    write_session.commit.assert_not_called()
    provider.close.assert_awaited_once()


def test_database_commit_failure_rolls_back(
    service: PersistentAIAnalysisService,
    incident: Incident,
    write_session: MagicMock,
    provider: AsyncMock,
) -> None:
    write_session.commit.side_effect = RuntimeError("Synthetic commit failure.")

    with pytest.raises(RuntimeError):
        asyncio.run(service.analyze_incident(incident.id))

    write_session.rollback.assert_called_once_with()
    provider.close.assert_awaited_once()


def test_unexpected_provider_failure(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
) -> None:
    provider.generate_structured.side_effect = RuntimeError(
        "Synthetic unexpected failure."
    )

    with pytest.raises(RuntimeError):
        asyncio.run(service.analyze_incident(incident.id))

    provider.close.assert_awaited_once()
    write_session.commit.assert_not_called()


def test_provider_cleanup_failure(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider.close.side_effect = AIProviderUnavailableError(
        "password=synthetic-password"
    )

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.SUCCEEDED
    assert result.error_code is None

    assert "AI provider resource cleanup failed." in caplog.text
    assert "synthetic-password" not in caplog.text

    write_session.commit.assert_called_once_with()


def test_analysis_cancellation(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
) -> None:
    provider.generate_structured.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(service.analyze_incident(incident.id))

    provider.close.assert_awaited_once()
    write_session.commit.assert_not_called()


def test_cleanup_preserves_original_failure(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
) -> None:
    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    provider.close.side_effect = RuntimeError("Synthetic cleanup failure.")

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.FAILED
    assert result.error_code == "provider_timeout"


def test_no_post_commit_refresh(
    service: PersistentAIAnalysisService,
    incident: Incident,
    write_session: MagicMock,
) -> None:
    result = asyncio.run(service.analyze_incident(incident.id))

    write_session.refresh.assert_called_once_with(result)

    method_names = [call[0] for call in write_session.method_calls]

    assert method_names.index("refresh") < (method_names.index("expunge"))

    assert method_names.index("expunge") < (method_names.index("commit"))


def test_incident_locked_during_persistence(
    service: PersistentAIAnalysisService,
    incident: Incident,
    write_session: MagicMock,
) -> None:
    asyncio.run(service.analyze_incident(incident.id))

    write_session.get.assert_called_once_with(
        Incident,
        incident.id,
        with_for_update=True,
        populate_existing=True,
    )


@pytest.mark.parametrize(
    "field",
    ["title", "description"],
)
def test_changed_incident_rejects_analysis(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
    field: str,
) -> None:
    from app.services.persistent_ai_analysis import (
        IncidentChangedDuringAnalysisError,
    )

    async def generate(
        *args: object,
        **kwargs: object,
    ) -> AIResponse[IncidentAnalysisResult]:
        setattr(incident, field, "Changed incident content.")

        return create_response()

    provider.generate_structured.side_effect = generate

    with pytest.raises(IncidentChangedDuringAnalysisError):
        asyncio.run(service.analyze_incident(incident.id))

    write_session.add.assert_not_called()
    write_session.commit.assert_not_called()
    write_session.rollback.assert_called_once_with()

    provider.close.assert_awaited_once()


def test_cleanup_preserves_unexpected_error(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
) -> None:
    provider.generate_structured.side_effect = RuntimeError(
        "Original execution failure."
    )

    provider.close.side_effect = RuntimeError("Secondary cleanup failure.")

    with pytest.raises(
        RuntimeError,
        match="Original execution failure",
    ):
        asyncio.run(service.analyze_incident(incident.id))

    write_session.commit.assert_not_called()


def test_active_task_cancellation(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
) -> None:
    async def execute() -> None:
        started = asyncio.Event()
        waiting = asyncio.Event()

        async def generate(
            *args: object,
            **kwargs: object,
        ) -> AIResponse[IncidentAnalysisResult]:
            started.set()

            await waiting.wait()

            return create_response()

        provider.generate_structured.side_effect = generate

        task = asyncio.create_task(service.analyze_incident(incident.id))

        await asyncio.wait_for(started.wait(), timeout=5)

        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(execute())

    provider.close.assert_awaited_once()
    write_session.commit.assert_not_called()


def test_cleanup_failure_preserves_cancellation(
    service: PersistentAIAnalysisService,
    incident: Incident,
    provider: AsyncMock,
    write_session: MagicMock,
) -> None:
    provider.generate_structured.side_effect = asyncio.CancelledError()

    provider.close.side_effect = RuntimeError("Synthetic cleanup failure.")

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(service.analyze_incident(incident.id))

    provider.close.assert_awaited_once()
    write_session.commit.assert_not_called()


def test_configured_budget_rejection_persisted(
    session_factory: MagicMock,
    settings: Settings,
    provider_factory: MagicMock,
    provider: AsyncMock,
    incident: Incident,
    write_session: MagicMock,
) -> None:
    limited_settings = settings.model_copy(update={"ai_max_input_chars": 1000})

    incident.description = "x" * 2000

    service = PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=limited_settings,
        provider_factory=provider_factory,
    )

    result = asyncio.run(service.analyze_incident(incident.id))

    assert result.status == AIAnalysisStatus.FAILED
    assert result.error_code == "provider_request"
    assert result.input_tokens is None
    assert result.output_tokens is None
    assert result.estimated_cost_usd is None

    provider.generate_structured.assert_not_awaited()
    provider.close.assert_awaited_once()

    write_session.commit.assert_called_once_with()
