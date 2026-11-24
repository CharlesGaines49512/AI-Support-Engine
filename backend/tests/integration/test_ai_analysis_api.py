from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.ai_dependencies import (
    get_persistent_ai_analysis_service,
)
from app.core.config import Settings
from app.core.database import get_db
from app.integrations.ai import (
    AIProviderTimeoutError,
    AIResponse,
    AIUsage,
)
from app.main import app
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
                title="Synthetic AI API incident",
                description="Database connection timed out.",
                priority=IncidentPriority.MEDIUM,
                category="ai-api-integration",
            )
        )

        session.commit()

    try:
        yield identifier

    finally:
        with session_factory() as session:
            session.execute(delete(Incident).where(Incident.id == identifier))

            session.commit()


def create_response() -> AIResponse[IncidentAnalysisResult]:
    return AIResponse[IncidentAnalysisResult](
        data=IncidentAnalysisResult(
            suggested_category=IncidentCategory.DATABASE,
            recommended_priority=IncidentPriority.HIGH,
            recommended_severity=IncidentSeverity.HIGH,
            summary="Database connectivity failure.",
            justification="Repeated connection timeouts.",
            confidence=0.90,
            insufficient_evidence=False,
            missing_information=[],
        ),
        provider="openai",
        model="synthetic-model",
        prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
        request_id="req_api_integration",
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
def client(
    session_factory: sessionmaker[Session],
    provider: AsyncMock,
) -> Generator[TestClient]:
    settings = Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
    )

    service = PersistentAIAnalysisService(
        session_factory=session_factory,
        settings=settings,
        provider_factory=MagicMock(return_value=provider),
    )

    def override_db() -> Generator[Session]:
        with session_factory() as session:
            try:
                yield session
            except Exception:
                session.rollback()
                raise

    previous = app.dependency_overrides.copy()

    app.dependency_overrides[get_db] = override_db

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: service

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.fixture
def url(incident_id: UUID) -> str:
    return f"/api/v1/incidents/{incident_id}/analyses"


def test_create_and_retrieve_analysis(
    client: TestClient,
    url: str,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    created = client.post(url)

    assert created.status_code == 201

    payload = created.json()
    analysis_id = UUID(payload["id"])

    assert payload["status"] == "succeeded"
    assert payload["incident_id"] == str(incident_id)

    with session_factory() as session:
        record = session.get(AIAnalysis, analysis_id)

        assert record is not None
        assert record.status == AIAnalysisStatus.SUCCEEDED
        assert record.recommended_priority == "high"

    retrieved = client.get(f"{url}/{analysis_id}")

    assert retrieved.status_code == 200
    assert retrieved.json() == payload


def test_failed_analysis_persisted(
    client: TestClient,
    url: str,
    provider: AsyncMock,
    session_factory: sessionmaker[Session],
) -> None:
    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "password=synthetic-password"
    )

    result = client.post(url)

    assert result.status_code == 201

    payload = result.json()

    assert payload["status"] == "failed"
    assert payload["error_code"] == "provider_timeout"
    assert payload["summary"] is None
    assert "synthetic-password" not in result.text

    with session_factory() as session:
        persisted = session.get(
            AIAnalysis,
            UUID(payload["id"]),
        )

        assert persisted is not None
        assert persisted.status == AIAnalysisStatus.FAILED


def test_analysis_history(
    client: TestClient,
    url: str,
) -> None:
    first = client.post(url)
    second = client.post(url)

    assert first.status_code == 201
    assert second.status_code == 201

    result = client.get(url)

    assert result.status_code == 200

    payload = result.json()

    assert payload["total"] == 2

    assert [item["id"] for item in payload["items"]] == [
        second.json()["id"],
        first.json()["id"],
    ]


def test_latest_and_latest_successful(
    client: TestClient,
    url: str,
    provider: AsyncMock,
) -> None:
    successful = client.post(url)

    assert successful.status_code == 201

    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    failed = client.post(url)

    assert failed.status_code == 201

    latest = client.get(f"{url}/latest")
    latest_successful = client.get(f"{url}/latest-successful")

    assert latest.status_code == 200
    assert latest.json()["id"] == failed.json()["id"]

    assert latest_successful.status_code == 200
    assert latest_successful.json()["id"] == (successful.json()["id"])


def test_status_filtering(
    client: TestClient,
    url: str,
    provider: AsyncMock,
) -> None:
    successful = client.post(url)

    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    failed = client.post(url)

    assert successful.status_code == 201
    assert failed.status_code == 201

    for status, expected in [
        ("succeeded", successful.json()["id"]),
        ("failed", failed.json()["id"]),
    ]:
        result = client.get(
            url,
            params={"status": status},
        )

        assert result.status_code == 200
        assert result.json()["total"] == 1
        assert result.json()["items"][0]["id"] == expected


def test_analysis_pagination(
    client: TestClient,
    url: str,
) -> None:
    for _ in range(3):
        assert client.post(url).status_code == 201

    first = client.get(
        url,
        params={"offset": 0, "limit": 2},
    )

    second = client.get(
        url,
        params={"offset": 2, "limit": 2},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    first_payload = first.json()
    second_payload = second.json()

    assert first_payload["total"] == 3
    assert len(first_payload["items"]) == 2
    assert first_payload["has_more"] is True

    assert second_payload["total"] == 3
    assert len(second_payload["items"]) == 1
    assert second_payload["has_more"] is False

    assert not (
        {item["id"] for item in first_payload["items"]}
        & {item["id"] for item in second_payload["items"]}
    )


def test_empty_analysis_history(
    client: TestClient,
    url: str,
) -> None:
    result = client.get(url)

    assert result.status_code == 200
    assert result.json()["items"] == []
    assert result.json()["total"] == 0

    assert client.get(f"{url}/latest").status_code == 404

    assert client.get(f"{url}/latest-successful").status_code == 404


def test_missing_incident(
    client: TestClient,
    provider: AsyncMock,
) -> None:
    url = f"/api/v1/incidents/{uuid4()}/analyses"

    assert client.post(url).status_code == 404
    assert client.get(url).status_code == 404
    assert client.get(f"{url}/latest").status_code == 404

    provider.generate_structured.assert_not_awaited()


def test_missing_analysis(
    client: TestClient,
    url: str,
) -> None:
    result = client.get(f"{url}/{uuid4()}")

    assert result.status_code == 404


def test_cross_incident_access_rejected(
    client: TestClient,
    url: str,
    session_factory: sessionmaker[Session],
) -> None:
    created = client.post(url)

    assert created.status_code == 201

    analysis_id = created.json()["id"]
    other_id = uuid4()

    with session_factory() as session:
        session.add(
            Incident(
                id=other_id,
                title="Unrelated synthetic incident",
                description="Network connection failed.",
                category="ai-api-integration",
            )
        )
        session.commit()

    try:
        other_url = f"/api/v1/incidents/{other_id}/analyses"

        result = client.get(f"{other_url}/{analysis_id}")

        assert result.status_code == 404

        history = client.get(other_url)

        assert history.status_code == 200
        assert history.json()["total"] == 0

    finally:
        with session_factory() as session:
            session.execute(delete(Incident).where(Incident.id == other_id))
            session.commit()


@pytest.mark.parametrize(
    "params",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": 101},
        {"status": "unsupported"},
    ],
)
def test_invalid_pagination_or_status(
    client: TestClient,
    url: str,
    params: dict[str, int | str],
) -> None:
    assert (
        client.get(
            url,
            params=params,
        ).status_code
        == 422
    )


def test_incident_unchanged_after_analysis(
    client: TestClient,
    url: str,
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
            original.status,
            original.category,
            original.updated_at,
        )

    assert client.post(url).status_code == 201

    with session_factory() as session:
        current = session.get(Incident, incident_id)

        assert current is not None

        assert (
            current.title,
            current.description,
            current.priority,
            current.status,
            current.category,
            current.updated_at,
        ) == original_values


def test_changed_incident_returns_conflict(
    client: TestClient,
    url: str,
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

            incident.description = "Updated synthetic incident description."

            session.commit()

        return create_response()

    provider.generate_structured.side_effect = generate

    result = client.post(url)

    assert result.status_code == 409

    with session_factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0


def test_retrieval_does_not_call_ai_provider(
    client: TestClient,
    url: str,
    provider: AsyncMock,
) -> None:
    created = client.post(url)

    assert created.status_code == 201

    provider.generate_structured.reset_mock()

    assert client.get(url).status_code == 200
    assert client.get(f"{url}/latest").status_code == 200

    assert client.get(f"{url}/latest-successful").status_code == 200

    analysis_id = created.json()["id"]

    assert client.get(f"{url}/{analysis_id}").status_code == 200

    provider.generate_structured.assert_not_awaited()


def test_incident_deletion_removes_analysis_history(
    client: TestClient,
    url: str,
    incident_id: UUID,
    session_factory: sessionmaker[Session],
) -> None:
    created = client.post(url)

    assert created.status_code == 201

    analysis_id = UUID(created.json()["id"])

    deleted = client.delete(f"/api/v1/incidents/{incident_id}")

    assert deleted.status_code == 204

    assert client.get(url).status_code == 404

    with session_factory() as session:
        assert session.get(AIAnalysis, analysis_id) is None
