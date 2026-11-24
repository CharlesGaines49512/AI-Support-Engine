from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.ai_dependencies import (
    get_ai_analysis_query_service,
    get_persistent_ai_analysis_service,
)
from app.core.exceptions import IncidentNotFoundError
from app.main import app
from app.models import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus
from app.schemas.ai_analysis_response import AIAnalysisResponse
from app.schemas.pagination import PaginatedResponse
from app.services.ai_analysis_query import (
    AIAnalysisNotFoundError,
    AIAnalysisQueryService,
)
from app.services.persistent_ai_analysis import (
    IncidentChangedDuringAnalysisError,
    PersistentAIAnalysisService,
)


@pytest.fixture
def analysis() -> AIAnalysis:
    return AIAnalysis(
        id=uuid4(),
        incident_id=uuid4(),
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connection failure.",
        justification="Repeated connection timeouts.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def response(analysis: AIAnalysis) -> AIAnalysisResponse:
    return AIAnalysisResponse.model_validate(analysis)


@pytest.fixture
def persistent_service(analysis: AIAnalysis) -> MagicMock:
    service = MagicMock(spec=PersistentAIAnalysisService)
    service.analyze_incident = AsyncMock(return_value=analysis)
    return service


@pytest.fixture
def query_service(response: AIAnalysisResponse) -> MagicMock:
    service = MagicMock(spec=AIAnalysisQueryService)

    service.get_analysis.return_value = response
    service.get_latest.return_value = response
    service.get_latest_successful.return_value = response

    service.list_analyses.return_value = PaginatedResponse[AIAnalysisResponse](
        items=[response],
        total=1,
        offset=0,
        limit=20,
        has_more=False,
    )

    return service


@pytest.fixture
def client(
    persistent_service: MagicMock,
    query_service: MagicMock,
) -> Generator[TestClient]:
    previous = app.dependency_overrides.copy()

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: (
        persistent_service
    )

    app.dependency_overrides[get_ai_analysis_query_service] = lambda: query_service

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.fixture
def url(analysis: AIAnalysis) -> str:
    return f"/api/v1/incidents/{analysis.incident_id}/analyses"


def test_create_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    persistent_service: MagicMock,
) -> None:
    result = client.post(url)

    assert result.status_code == 201
    assert result.json()["id"] == str(analysis.id)
    assert result.json()["status"] == "succeeded"
    assert result.json()["recommended_priority"] == "high"

    persistent_service.analyze_incident.assert_awaited_once_with(analysis.incident_id)


def test_create_failed_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    persistent_service: MagicMock,
) -> None:
    failed = AIAnalysis(
        id=uuid4(),
        incident_id=analysis.incident_id,
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
        created_at=datetime.now(UTC),
    )

    persistent_service.analyze_incident.return_value = failed

    result = client.post(url)

    assert result.status_code == 201
    assert result.json()["status"] == "failed"
    assert result.json()["error_code"] == "provider_timeout"
    assert result.json()["summary"] is None


def test_create_missing_incident(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    persistent_service: MagicMock,
) -> None:
    persistent_service.analyze_incident.side_effect = IncidentNotFoundError(
        analysis.incident_id
    )

    result = client.post(url)

    assert result.status_code == 404


def test_create_changed_incident(
    client: TestClient,
    url: str,
    persistent_service: MagicMock,
) -> None:
    persistent_service.analyze_incident.side_effect = (
        IncidentChangedDuringAnalysisError("Incident content changed during analysis.")
    )

    result = client.post(url)

    assert result.status_code == 409
    assert result.json()["detail"] == ("Incident content changed during analysis.")


def test_list_analyses(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
) -> None:
    result = client.get(url)

    assert result.status_code == 200
    assert result.json()["total"] == 1
    assert result.json()["items"][0]["id"] == str(analysis.id)
    assert result.json()["has_more"] is False

    query_service.list_analyses.assert_called_once_with(
        analysis.incident_id,
        offset=0,
        limit=20,
        status=None,
    )


def test_empty_analysis_history(
    client: TestClient,
    url: str,
    query_service: MagicMock,
) -> None:
    query_service.list_analyses.return_value = PaginatedResponse[AIAnalysisResponse](
        items=[],
        total=0,
        offset=0,
        limit=20,
        has_more=False,
    )

    result = client.get(url)

    assert result.status_code == 200
    assert result.json()["items"] == []
    assert result.json()["total"] == 0


def test_list_missing_incident(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
) -> None:
    query_service.list_analyses.side_effect = IncidentNotFoundError(
        analysis.incident_id
    )

    assert client.get(url).status_code == 404


def test_analysis_pagination(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    response: AIAnalysisResponse,
    query_service: MagicMock,
) -> None:
    query_service.list_analyses.return_value = PaginatedResponse[AIAnalysisResponse](
        items=[response],
        total=10,
        offset=2,
        limit=1,
        has_more=True,
    )

    result = client.get(
        url,
        params={"offset": 2, "limit": 1},
    )

    assert result.status_code == 200
    assert result.json()["offset"] == 2
    assert result.json()["limit"] == 1
    assert result.json()["has_more"] is True

    query_service.list_analyses.assert_called_once_with(
        analysis.incident_id,
        offset=2,
        limit=1,
        status=None,
    )


@pytest.mark.parametrize(
    "status",
    [
        AIAnalysisStatus.SUCCEEDED,
        AIAnalysisStatus.FAILED,
    ],
)
def test_status_filter(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
    status: AIAnalysisStatus,
) -> None:
    result = client.get(
        url,
        params={"status": status.value},
    )

    assert result.status_code == 200

    query_service.list_analyses.assert_called_once_with(
        analysis.incident_id,
        offset=0,
        limit=20,
        status=status,
    )


@pytest.mark.parametrize(
    "params",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": 101},
        {"limit": "invalid"},
        {"status": "unsupported"},
    ],
)
def test_invalid_query_parameters(
    client: TestClient,
    url: str,
    query_service: MagicMock,
    params: dict[str, int | str],
) -> None:
    result = client.get(url, params=params)

    assert result.status_code == 422
    query_service.list_analyses.assert_not_called()


def test_get_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
) -> None:
    result = client.get(f"{url}/{analysis.id}")

    assert result.status_code == 200
    assert result.json()["id"] == str(analysis.id)

    query_service.get_analysis.assert_called_once_with(
        analysis.incident_id,
        analysis.id,
    )


def test_get_latest_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
) -> None:
    result = client.get(f"{url}/latest")

    assert result.status_code == 200
    assert result.json()["id"] == str(analysis.id)

    query_service.get_latest.assert_called_once_with(analysis.incident_id)

    query_service.get_analysis.assert_not_called()


def test_get_latest_successful_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
) -> None:
    result = client.get(f"{url}/latest-successful")

    assert result.status_code == 200
    assert result.json()["status"] == "succeeded"

    query_service.get_latest_successful.assert_called_once_with(analysis.incident_id)

    query_service.get_analysis.assert_not_called()


@pytest.mark.parametrize(
    ("suffix", "method"),
    [
        ("/latest", "get_latest"),
        ("/latest-successful", "get_latest_successful"),
        ("/individual", "get_analysis"),
    ],
)
@pytest.mark.parametrize("missing_incident", [True, False])
def test_missing_analysis_resources(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    query_service: MagicMock,
    suffix: str,
    method: str,
    missing_incident: bool,
) -> None:
    error = (
        IncidentNotFoundError(analysis.incident_id)
        if missing_incident
        else AIAnalysisNotFoundError("The requested AI analysis was not found.")
    )

    getattr(query_service, method).side_effect = error

    if suffix == "/individual":
        suffix = f"/{analysis.id}"

    assert client.get(url + suffix).status_code == 404


@pytest.mark.parametrize("method", ["get", "post"])
def test_invalid_incident_uuid(
    client: TestClient,
    method: str,
) -> None:
    result = client.request(
        method.upper(),
        "/api/v1/incidents/invalid/analyses",
    )

    assert result.status_code == 422


def test_invalid_analysis_uuid(
    client: TestClient,
    url: str,
) -> None:
    result = client.get(f"{url}/invalid")

    assert result.status_code == 422


def test_get_endpoints_do_not_generate_analysis(
    client: TestClient,
    url: str,
    analysis: AIAnalysis,
    persistent_service: MagicMock,
) -> None:
    assert client.get(url).status_code == 200
    assert client.get(f"{url}/latest").status_code == 200
    assert client.get(f"{url}/latest-successful").status_code == 200
    assert client.get(f"{url}/{analysis.id}").status_code == 200

    persistent_service.analyze_incident.assert_not_awaited()


def test_unexpected_generation_failure_returns_500(
    persistent_service: MagicMock,
    url: str,
    client: TestClient,
) -> None:
    persistent_service.analyze_incident.side_effect = RuntimeError(
        "Synthetic internal failure."
    )

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as error_client:
        result = error_client.post(url)

    assert result.status_code == 500
    assert "Synthetic internal failure" not in result.text


def test_openapi_analysis_operations(
    client: TestClient,
) -> None:
    result = client.get("/openapi.json")

    assert result.status_code == 200

    paths = result.json()["paths"]

    prefix = "/api/v1/incidents/{incident_id}/analyses"

    assert "post" in paths[prefix]
    assert "get" in paths[prefix]
    assert "get" in paths[prefix + "/latest"]
    assert "get" in paths[prefix + "/latest-successful"]
    assert "get" in paths[prefix + "/{analysis_id}"]

    assert "201" in paths[prefix]["post"]["responses"]
    assert "409" in paths[prefix]["post"]["responses"]
