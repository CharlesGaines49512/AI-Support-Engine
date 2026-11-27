from collections.abc import Generator
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.integrations.ai import (
    AIProviderTimeoutError,
    AIResponse,
    AIUsage,
)
from app.models import AIAnalysis, Incident
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.models.log_enums import LogFormat
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.prompts.log_enhanced_analysis import (
    LOG_ENHANCED_PROMPT_VERSION,
)
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.services.ai_analysis_query import AIAnalysisQueryService
from app.services.log_ingestion import LogIngestionService
from app.services.persistent_ai_analysis import (
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
        session.add(
            Incident(
                id=identifier,
                title="Synthetic cost tracking incident",
                description="Database connection timed out.",
                category="ai-cost-integration",
            )
        )
        session.commit()

    try:
        yield identifier
    finally:
        with session_factory() as session:
            session.execute(delete(Incident).where(Incident.id == identifier))
            session.commit()


@pytest.fixture
def provider() -> AsyncMock:
    result = AsyncMock()

    result.generate_structured.return_value = AIResponse[IncidentAnalysisResult](
        data=IncidentAnalysisResult(
            suggested_category=IncidentCategory.DATABASE,
            recommended_priority=IncidentPriority.HIGH,
            recommended_severity=IncidentSeverity.HIGH,
            summary="Database connectivity failure.",
            justification="Repeated connection timeouts.",
            confidence=0.9,
            insufficient_evidence=False,
            missing_information=[],
        ),
        provider="openai",
        model="synthetic-model",
        prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
        request_id="req_cost_integration",
        usage=AIUsage(
            input_tokens=1000,
            cached_input_tokens=400,
            output_tokens=500,
            total_tokens=1500,
        ),
        latency_ms=250.0,
    )

    return result


@pytest.mark.parametrize(
    ("pricing_model", "provider_fails", "expected_cost"),
    [
        (
            "synthetic-model",
            False,
            Decimal("0.0054000000"),
        ),
        (
            "unmatched-model",
            False,
            None,
        ),
        (
            "synthetic-model",
            True,
            None,
        ),
    ],
)
def test_cost_persistence(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    provider: AsyncMock,
    pricing_model: str,
    provider_fails: bool,
    expected_cost: Decimal | None,
) -> None:
    import asyncio

    settings = Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
        ai_pricing_model=pricing_model,
        ai_pricing_input_usd_per_million=Decimal("2"),
        ai_pricing_cached_input_usd_per_million=Decimal("0.5"),
        ai_pricing_output_usd_per_million=Decimal("8"),
    )

    if provider_fails:
        provider.generate_structured.side_effect = AIProviderTimeoutError(
            "Synthetic timeout."
        )

    service = PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=MagicMock(return_value=provider),
    )

    created = asyncio.run(service.analyze_incident(incident_id))

    assert created.estimated_cost_usd == expected_cost

    with session_factory() as session:
        record = session.get(AIAnalysis, created.id)

        assert record is not None
        assert record.estimated_cost_usd == expected_cost

        expected_status = (
            AIAnalysisStatus.FAILED if provider_fails else AIAnalysisStatus.SUCCEEDED
        )

        assert record.status == expected_status

        response = AIAnalysisQueryService(session).get_analysis(
            incident_id,
            created.id,
        )

        assert response.estimated_cost_usd == expected_cost

        serialized = response.model_dump(mode="json")

        assert serialized["estimated_cost_usd"] == (
            str(expected_cost) if expected_cost is not None else None
        )


def create_priced_service(
    session_factory: sessionmaker[Session],
    provider: AsyncMock,
    *,
    input_price: Decimal = Decimal("2"),
    cached_price: Decimal = Decimal("0.5"),
) -> PersistentAIAnalysisService:
    settings = Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
        ai_pricing_model="synthetic-model",
        ai_pricing_input_usd_per_million=input_price,
        ai_pricing_cached_input_usd_per_million=cached_price,
        ai_pricing_output_usd_per_million=Decimal("8"),
    )

    return PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=MagicMock(return_value=provider),
    )


@pytest.mark.parametrize(
    ("input_price", "cached_price"),
    [
        (Decimal("-1"), Decimal("0.5")),
        (Decimal("2"), Decimal("10")),
    ],
)
def test_invalid_pricing_preserves_success(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    provider: AsyncMock,
    input_price: Decimal,
    cached_price: Decimal,
) -> None:
    import asyncio

    service = create_priced_service(
        session_factory,
        provider,
        input_price=input_price,
        cached_price=cached_price,
    )

    created = asyncio.run(service.analyze_incident(incident_id))

    assert created.status == AIAnalysisStatus.SUCCEEDED
    assert created.estimated_cost_usd is None
    assert created.error_code is None
    assert created.summary is not None

    with session_factory() as session:
        record = session.get(AIAnalysis, created.id)

        assert record is not None
        assert record.status == AIAnalysisStatus.SUCCEEDED
        assert record.estimated_cost_usd is None


def test_historical_costs_preserved_after_price_change(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    provider: AsyncMock,
) -> None:
    import asyncio

    from app.services.ai_metrics import AIMetricsService

    first_service = create_priced_service(
        session_factory,
        provider,
        input_price=Decimal("2"),
    )

    first = asyncio.run(first_service.analyze_incident(incident_id))

    second_service = create_priced_service(
        session_factory,
        provider,
        input_price=Decimal("4"),
    )

    second = asyncio.run(second_service.analyze_incident(incident_id))

    assert first.id != second.id

    with session_factory() as session:
        first_record = session.get(AIAnalysis, first.id)
        second_record = session.get(AIAnalysis, second.id)

        assert first_record is not None
        assert second_record is not None

        assert first_record.estimated_cost_usd == Decimal("0.0054000000")

        assert second_record.estimated_cost_usd == Decimal("0.0066000000")

        metrics = AIMetricsService(session).get_metrics(incident_id)

        assert metrics.total_analyses == 2
        assert metrics.successful_analyses == 2
        assert metrics.failed_analyses == 0
        assert metrics.costed_analyses == 2
        assert metrics.uncosted_analyses == 0

        assert metrics.estimated_cost_usd == Decimal("0.0120000000")

        assert metrics.total_tokens == 3000


@pytest.mark.parametrize(
    "usage",
    [
        AIUsage(),
        AIUsage(
            input_tokens=1000,
            output_tokens=500,
            total_tokens=1500,
        ),
    ],
)
def test_partial_usage_preserves_analysis(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    provider: AsyncMock,
    usage: AIUsage,
) -> None:
    import asyncio

    from app.services.ai_metrics import AIMetricsService

    response: AIResponse[IncidentAnalysisResult] = (
        provider.generate_structured.return_value
    )

    provider.generate_structured.return_value = response.model_copy(
        update={"usage": usage}
    )

    service = create_priced_service(
        session_factory,
        provider,
    )

    created = asyncio.run(service.analyze_incident(incident_id))

    assert created.status == AIAnalysisStatus.SUCCEEDED
    assert created.estimated_cost_usd is None
    assert created.input_tokens == usage.input_tokens
    assert created.output_tokens == usage.output_tokens

    with session_factory() as session:
        metrics = AIMetricsService(session).get_metrics(incident_id)

        assert metrics.total_analyses == 1
        assert metrics.successful_analyses == 1
        assert metrics.costed_analyses == 0
        assert metrics.uncosted_analyses == 1
        assert metrics.estimated_cost_usd is None
        assert metrics.total_tokens == usage.total_tokens
        assert metrics.cached_usage_sample_count == 0


@pytest.mark.parametrize(
    ("pricing_model", "expected_cost"),
    [
        ("synthetic-model", Decimal("0.0054000000")),
        ("unmatched-model", None),
    ],
)
def test_enhanced_cost_persistence(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    provider: AsyncMock,
    pricing_model: str,
    expected_cost: Decimal | None,
) -> None:
    import asyncio

    settings = Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
        ai_pricing_model=pricing_model,
        ai_pricing_input_usd_per_million=Decimal("2"),
        ai_pricing_cached_input_usd_per_million=Decimal("0.5"),
        ai_pricing_output_usd_per_million=Decimal("8"),
    )

    response = provider.generate_structured.return_value

    provider.generate_structured.return_value = response.model_copy(
        update={
            "prompt_version": LOG_ENHANCED_PROMPT_VERSION,
        }
    )

    submission = LogIngestionService(
        session_factory,
        settings,
    ).ingest(
        incident_id,
        b"ERROR Database connection failed.",
        LogFormat.TEXT,
    )

    service = PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=MagicMock(return_value=provider),
    )

    created = asyncio.run(
        service.analyze_incident(
            incident_id,
            submission_id=submission.submission_id,
        )
    )

    assert created.status == AIAnalysisStatus.SUCCEEDED
    assert created.estimated_cost_usd == expected_cost

    with session_factory() as session:
        stored = session.get(AIAnalysis, created.id)

        assert stored is not None
        assert stored.estimated_cost_usd == expected_cost
        assert stored.log_submission_id == submission.submission_id
        assert stored.prompt_version == LOG_ENHANCED_PROMPT_VERSION
        assert stored.log_evidence_sha256 is not None

    provider.generate_structured.assert_awaited_once()
    provider.close.assert_awaited_once()
