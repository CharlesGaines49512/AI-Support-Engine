import asyncio
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import delete, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.integrations.ai import (
    AIProviderDisabledError,
    AIProviderTimeoutError,
    AIResponse,
    AIUsage,
)
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.repositories import AIAnalysisRepository
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.services.persistent_ai_analysis import (
    IncidentChangedDuringAnalysisError,
    PersistentAIAnalysisService,
)


@pytest.fixture
def session_factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=False,
    )


@pytest.fixture
def incident_id(
    session_factory: sessionmaker[Session],
) -> Generator[UUID]:
    identifier = uuid4()

    with session_factory() as session:
        incident = Incident(
            id=identifier,
            title="Synthetic persistent AI incident",
            description="Database connection timed out.",
            priority=IncidentPriority.MEDIUM,
            category="ai-persistent-integration",
        )

        session.add(incident)
        session.commit()

    try:
        yield identifier

    finally:
        with session_factory() as session:
            session.execute(delete(Incident).where(Incident.id == identifier))

            session.commit()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
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
                else "The database connection timed out."
            ),
            confidence=0.10 if unknown else 0.90,
            insufficient_evidence=unknown,
            missing_information=(["Business impact"] if unknown else []),
        ),
        provider="openai",
        model="synthetic-model",
        prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
        request_id="req_persistent_integration",
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
    result = AsyncMock()

    result.generate_structured.return_value = create_response()

    return result


@pytest.fixture
def provider_factory(
    provider: AsyncMock,
) -> MagicMock:
    return MagicMock(return_value=provider)


@pytest.fixture
def service(
    session_factory: sessionmaker[Session],
    settings: Settings,
    provider_factory: MagicMock,
) -> PersistentAIAnalysisService:
    return PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=provider_factory,
    )


def test_successful_analysis_committed(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    result = asyncio.run(service.analyze_incident(incident_id))

    assert result.id is not None
    assert result.status == AIAnalysisStatus.SUCCEEDED

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.incident_id == incident_id
        assert persisted.status == AIAnalysisStatus.SUCCEEDED
        assert persisted.suggested_category == "database"
        assert persisted.recommended_priority == "high"
        assert persisted.recommended_severity == "high"
        assert persisted.confidence == 0.90


def test_returned_record_is_detached(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
) -> None:
    result = asyncio.run(service.analyze_incident(incident_id))

    assert inspect(result).detached
    assert result.id is not None
    assert result.created_at.tzinfo is not None
    assert result.summary is not None
    assert result.input_characters is not None
    assert result.input_characters > 0


def test_operational_metadata_persisted(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.provider == "openai"
        assert persisted.model == "synthetic-model"
        assert persisted.prompt_version == (INCIDENT_ANALYSIS_PROMPT_VERSION)
        assert persisted.request_id == ("req_persistent_integration")
        assert persisted.input_tokens == 1000
        assert persisted.output_tokens == 200
        assert persisted.total_tokens == 1200
        assert persisted.cached_input_tokens == 100
        assert persisted.latency_ms == 250.0
        assert persisted.estimated_cost_usd is None


def test_failed_analysis_committed(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "password=synthetic-password"
    )

    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.status == AIAnalysisStatus.FAILED
        assert persisted.error_code == "provider_timeout"
        assert persisted.error_message is not None
        assert "synthetic-password" not in persisted.error_message
        assert persisted.summary is None
        assert persisted.total_tokens is None


def test_disabled_provider_failure_committed(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider_factory: MagicMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider_factory.side_effect = AIProviderDisabledError("AI disabled.")

    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.status == AIAnalysisStatus.FAILED
        assert persisted.error_code == "provider_disabled"


def test_multiple_analysis_attempts(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    successful = asyncio.run(service.analyze_incident(incident_id))

    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    failed = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 2

        latest = repository.get_latest(incident_id)

        latest_successful = repository.get_latest_successful(incident_id)

        assert latest is not None
        assert latest.id == failed.id

        assert latest_successful is not None
        assert latest_successful.id == successful.id


def test_missing_incident_does_not_call_provider(
    service: PersistentAIAnalysisService,
    provider_factory: MagicMock,
) -> None:
    with pytest.raises(IncidentNotFoundError):
        asyncio.run(service.analyze_incident(uuid4()))

    provider_factory.assert_not_called()


def test_original_incident_remains_unchanged(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        original = session.get(Incident, incident_id)

        assert original is not None

        original_values = (
            original.title,
            original.description,
            original.priority,
            original.category,
            original.status,
            original.updated_at,
        )

    asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        current = session.get(Incident, incident_id)

        assert current is not None

        assert (
            current.title,
            current.description,
            current.priority,
            current.category,
            current.status,
            current.updated_at,
        ) == original_values


def test_unknown_recommendations_committed(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider.generate_structured.return_value = create_response(unknown=True)

    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.recommended_priority is None
        assert persisted.suggested_category == "unknown"
        assert persisted.recommended_severity == "unknown"
        assert persisted.insufficient_evidence is True
        assert persisted.missing_information == ["Business impact"]


def test_sensitive_output_not_persisted(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider.generate_structured.return_value = create_response(sensitive=True)

    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.summary == ("Contact [REDACTED_EMAIL].")
        assert persisted.justification == ("password=[REDACTED_SECRET]")


@pytest.mark.parametrize(
    "field",
    ["title", "description"],
)
def test_changed_incident_rejects_persistence(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
    field: str,
) -> None:
    async def generate(
        *args: object,
        **kwargs: object,
    ) -> AIResponse[IncidentAnalysisResult]:
        with session_factory() as session:
            incident = session.get(Incident, incident_id)

            assert incident is not None

            setattr(
                incident,
                field,
                "Changed synthetic incident content.",
            )

            session.commit()

        return create_response()

    provider.generate_structured.side_effect = generate

    with pytest.raises(IncidentChangedDuringAnalysisError):
        asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0


def test_deleted_incident_rejects_persistence(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    async def generate(
        *args: object,
        **kwargs: object,
    ) -> AIResponse[IncidentAnalysisResult]:
        with session_factory() as session:
            incident = session.get(Incident, incident_id)

            assert incident is not None

            session.delete(incident)
            session.commit()

        return create_response()

    provider.generate_structured.side_effect = generate

    with pytest.raises(IncidentNotFoundError):
        asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0


def test_cleanup_failure_preserves_committed_analysis(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider.close.side_effect = RuntimeError("Synthetic cleanup failure.")

    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        persisted = session.get(AIAnalysis, result.id)

        assert persisted is not None
        assert persisted.status == AIAnalysisStatus.SUCCEEDED


def test_cancellation_does_not_create_analysis(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
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

        task = asyncio.create_task(service.analyze_incident(incident_id))

        await asyncio.wait_for(started.wait(), timeout=5)

        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(execute())

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0

    provider.close.assert_awaited_once()


def test_database_failure_does_not_commit_analysis(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create = AIAnalysisRepository.create

    def failing_create(
        repository: AIAnalysisRepository,
        analysis: AIAnalysis,
    ) -> AIAnalysis:
        original_create(repository, analysis)

        raise RuntimeError("Synthetic failure after database flush.")

    monkeypatch.setattr(
        AIAnalysisRepository,
        "create",
        failing_create,
    )

    with pytest.raises(
        RuntimeError,
        match="Synthetic failure after database flush",
    ):
        asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0

        assert session.get(Incident, incident_id) is not None


def test_incident_deletion_removes_analysis_history(
    service: PersistentAIAnalysisService,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    result = asyncio.run(service.analyze_incident(incident_id))

    with session_factory() as session:
        incident = session.get(Incident, incident_id)

        assert incident is not None

        session.delete(incident)
        session.commit()

    with session_factory() as session:
        assert session.get(AIAnalysis, result.id) is None

        records = session.scalars(
            select(AIAnalysis).where(AIAnalysis.incident_id == incident_id)
        ).all()

        assert records == []
