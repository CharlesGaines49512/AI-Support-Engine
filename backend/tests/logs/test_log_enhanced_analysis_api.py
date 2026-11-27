from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.ai_dependencies import (
    get_persistent_ai_analysis_service,
)
from app.core.exceptions import IncidentNotFoundError
from app.logs.ai_evidence_contracts import InvalidLogEvidenceError
from app.logs.exceptions import (
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.main import app
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.parsers.exceptions import (
    LogResourceLimitError,
    UnsafeLogContentError,
)
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.prompts.log_enhanced_analysis import (
    LOG_ENHANCED_PROMPT_VERSION,
)
from app.schemas.ai_analysis import (
    IncidentCategory,
    IncidentSeverity,
)
from app.schemas.ai_analysis_response import AIAnalysisResponse
from app.services.persistent_ai_analysis import (
    IncidentChangedDuringAnalysisError,
    LogEvidenceChangedDuringAnalysisError,
    PersistentAIAnalysisService,
)


@pytest.fixture
def incident_id() -> UUID:
    return uuid4()


@pytest.fixture
def submission_id() -> UUID:
    return uuid4()


@pytest.fixture
def standard_result(
    incident_id: UUID,
) -> AIAnalysisResponse:
    return AIAnalysisResponse(
        id=uuid4(),
        incident_id=incident_id,
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category=IncidentCategory.DATABASE,
        recommended_priority=IncidentPriority.HIGH,
        recommended_severity=IncidentSeverity.HIGH,
        summary="Database connectivity failure detected.",
        justification=("The incident describes a database connection failure."),
        confidence=0.85,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version=INCIDENT_ANALYSIS_PROMPT_VERSION,
        request_id="synthetic-request",
        input_tokens=1000,
        output_tokens=200,
        total_tokens=1200,
        cached_input_tokens=100,
        estimated_cost_usd=None,
        latency_ms=250.0,
        redaction_count=0,
        input_characters=1000,
        error_code=None,
        error_message=None,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def enhanced_result(
    standard_result: AIAnalysisResponse,
    submission_id: UUID,
) -> AIAnalysisResponse:
    return standard_result.model_copy(
        update={
            "prompt_version": LOG_ENHANCED_PROMPT_VERSION,
            "log_submission_id": submission_id,
            "log_evidence_version": "1.0.0",
            "log_evidence_sha256": "a" * 64,
            "log_evidence_event_count": 2,
        }
    )


@pytest.fixture
def service(
    standard_result: AIAnalysisResponse,
) -> MagicMock:
    mock = MagicMock(
        spec=PersistentAIAnalysisService,
    )

    mock.analyze_incident = AsyncMock(
        return_value=standard_result,
    )

    return mock


@pytest.fixture
def client(
    service: MagicMock,
) -> Generator[TestClient]:
    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: service

    try:
        with TestClient(app) as test_client:
            yield test_client

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)


@pytest.fixture
def endpoint(
    incident_id: UUID,
) -> str:
    return f"/api/v1/incidents/{incident_id}/analyses"


def test_standard_analysis_without_body(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
) -> None:
    response = client.post(endpoint)

    assert response.status_code == 201

    data = response.json()

    assert data["incident_id"] == str(incident_id)
    assert data["status"] == "succeeded"
    assert data["log_submission_id"] is None
    assert data["log_evidence_version"] is None
    assert data["log_evidence_sha256"] is None
    assert data["log_evidence_event_count"] is None

    service.analyze_incident.assert_awaited_once_with(incident_id)


@pytest.mark.parametrize(
    "body",
    [
        "{}",
        "null",
        '{"log_submission_id":null}',
    ],
)
def test_standard_analysis_optional_body(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    body: str,
) -> None:
    response = client.post(
        endpoint,
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 201
    assert response.json()["log_submission_id"] is None

    service.analyze_incident.assert_awaited_once_with(incident_id)


def test_enhanced_analysis(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    submission_id: UUID,
    enhanced_result: AIAnalysisResponse,
) -> None:
    service.analyze_incident.return_value = enhanced_result

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["incident_id"] == str(incident_id)
    assert data["status"] == "succeeded"

    assert data["log_submission_id"] == str(submission_id)

    assert data["prompt_version"] == (LOG_ENHANCED_PROMPT_VERSION)

    assert data["log_evidence_version"] == "1.0.0"
    assert data["log_evidence_sha256"] == "a" * 64
    assert data["log_evidence_event_count"] == 2

    assert data["suggested_category"] == "database"
    assert data["recommended_priority"] == "high"
    assert data["confidence"] == 0.85

    service.analyze_incident.assert_awaited_once_with(
        incident_id,
        submission_id=submission_id,
    )


def test_enhanced_analysis_excludes_internal_data(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
    enhanced_result: AIAnalysisResponse,
) -> None:
    service.analyze_incident.return_value = enhanced_result

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 201

    data = response.json()

    forbidden_fields = {
        "raw_payload",
        "system_prompt",
        "user_prompt",
        "api_key",
        "evidence",
        "log_context",
    }

    assert forbidden_fields.isdisjoint(data)


def test_enhanced_analysis_with_zero_selected_events(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
    enhanced_result: AIAnalysisResponse,
) -> None:
    service.analyze_incident.return_value = enhanced_result.model_copy(
        update={
            "log_evidence_event_count": 0,
        },
    )

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 201

    assert response.json()["log_evidence_event_count"] == 0


def test_failed_enhanced_analysis_preserves_provenance(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
    enhanced_result: AIAnalysisResponse,
) -> None:
    service.analyze_incident.return_value = enhanced_result.model_copy(
        update={
            "status": AIAnalysisStatus.FAILED,
            "suggested_category": None,
            "recommended_priority": None,
            "recommended_severity": None,
            "summary": None,
            "justification": None,
            "confidence": None,
            "insufficient_evidence": None,
            "missing_information": None,
            "request_id": None,
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
            "cached_input_tokens": None,
            "error_code": "provider_timeout",
            "error_message": ("The AI provider request timed out."),
        },
    )

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["status"] == "failed"
    assert data["summary"] is None
    assert data["confidence"] is None
    assert data["error_code"] == "provider_timeout"
    assert data["log_submission_id"] == str(submission_id)
    assert data["log_evidence_sha256"] == "a" * 64
    assert data["log_evidence_event_count"] == 2


@pytest.mark.parametrize(
    "value",
    [
        "",
        "invalid-uuid",
        123,
        True,
        [],
        {},
    ],
)
def test_invalid_submission_identifier(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    value: object,
) -> None:
    response = client.post(
        endpoint,
        json={
            "log_submission_id": value,
        },
    )

    assert response.status_code == 422

    service.analyze_incident.assert_not_awaited()


@pytest.mark.parametrize(
    "field",
    [
        "incident_id",
        "submission_id",
        "model",
        "provider",
        "api_key",
        "system_prompt",
        "user_prompt",
        "raw_payload",
        "evidence",
        "confidence",
        "priority",
    ],
)
def test_unknown_analysis_request_fields_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
    field: str,
) -> None:
    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
            field: "synthetic-value",
        },
    )

    assert response.status_code == 422

    service.analyze_incident.assert_not_awaited()


@pytest.mark.parametrize(
    "body",
    [
        '{"log_submission_id":',
        "not-json",
        "[]",
        '"synthetic-string"',
        "123",
    ],
)
def test_invalid_analysis_request_body(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    body: str,
) -> None:
    response = client.post(
        endpoint,
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422

    service.analyze_incident.assert_not_awaited()


def test_invalid_incident_identifier(
    client: TestClient,
    service: MagicMock,
    submission_id: UUID,
) -> None:
    response = client.post(
        "/api/v1/incidents/invalid-id/analyses",
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 422

    service.analyze_incident.assert_not_awaited()


def test_enhanced_analysis_missing_incident(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    submission_id: UUID,
) -> None:
    service.analyze_incident.side_effect = IncidentNotFoundError(incident_id)

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 404

    service.analyze_incident.assert_awaited_once_with(
        incident_id,
        submission_id=submission_id,
    )


def test_enhanced_analysis_missing_submission(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
) -> None:
    error = LogSubmissionNotFoundError()
    error.args = ("SYNTHETIC_SECRET_CANARY",)

    service.analyze_incident.side_effect = error

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Application log submission was not found.",
    }

    assert "SYNTHETIC_SECRET_CANARY" not in response.text


def test_enhanced_analysis_foreign_submission(
    client: TestClient,
    service: MagicMock,
    submission_id: UUID,
) -> None:
    other_incident_id = uuid4()

    service.analyze_incident.side_effect = LogSubmissionNotFoundError()

    response = client.post(
        f"/api/v1/incidents/{other_incident_id}/analyses",
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 404

    service.analyze_incident.assert_awaited_once_with(
        other_incident_id,
        submission_id=submission_id,
    )


def test_incident_content_conflict(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
) -> None:
    service.analyze_incident.side_effect = IncidentChangedDuringAnalysisError(
        "Incident content changed during analysis."
    )

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 409

    assert response.json()["detail"] == ("Incident content changed during analysis.")


def test_evidence_content_conflict(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
) -> None:
    service.analyze_incident.side_effect = LogEvidenceChangedDuringAnalysisError(
        "SYNTHETIC_SECRET_CANARY"
    )

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 409

    assert response.json()["detail"] == ("Diagnostic evidence changed during analysis.")

    assert "SYNTHETIC_SECRET_CANARY" not in response.text


@pytest.mark.parametrize(
    "error_type",
    [
        InvalidLogEvidenceError,
        LogPersistenceIntegrityError,
        LogResourceLimitError,
        UnsafeLogContentError,
    ],
)
def test_invalid_diagnostic_evidence(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
    error_type: type[Exception],
) -> None:
    if error_type is LogPersistenceIntegrityError:
        error: Exception = LogPersistenceIntegrityError()
        error.args = ("SYNTHETIC_SECRET_CANARY",)
    else:
        error = error_type("SYNTHETIC_SECRET_CANARY")

    service.analyze_incident.side_effect = error

    response = client.post(
        endpoint,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 409

    assert response.json() == {
        "detail": "Diagnostic evidence could not be verified.",
    }

    assert "SYNTHETIC_SECRET_CANARY" not in response.text


def test_enhanced_analysis_openapi(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    document = response.json()

    operation = document["paths"]["/api/v1/incidents/{incident_id}/analyses"]["post"]

    assert {
        "201",
        "404",
        "409",
        "422",
    }.issubset(operation["responses"])

    request_body = operation["requestBody"]

    assert request_body.get("required", False) is False

    assert "application/json" in request_body["content"]

    schema = document["components"]["schemas"]["AIAnalysisRequest"]

    assert schema["additionalProperties"] is False

    assert set(schema["properties"]) == {
        "log_submission_id",
    }


def test_existing_analysis_operations_preserved(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json()["paths"]

    prefix = "/api/v1/incidents/{incident_id}/analyses"

    assert "post" in paths[prefix]
    assert "get" in paths[prefix]
    assert "get" in paths[prefix + "/latest"]
    assert "get" in paths[prefix + "/latest-successful"]
    assert "get" in paths[prefix + "/{analysis_id}"]
