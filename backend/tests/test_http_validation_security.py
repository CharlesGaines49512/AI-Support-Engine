from collections.abc import Generator
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.ai_dependencies import (
    get_ai_analysis_query_service,
    get_persistent_ai_analysis_service,
)
from app.api.dependencies import get_incident_service
from app.api.log_dependencies import (
    get_log_ingestion_service,
    get_log_query_service,
)
from app.core.config import Settings, get_settings
from app.main import app

SECRET = "synthetic-confidential-validation-value"
BASE = "/api/v1/incidents"
INCIDENT = f"{BASE}/{uuid4()}"
SUBMISSION = f"{INCIDENT}/logs/{uuid4()}"

SAFE_RESPONSE = {
    "detail": [
        {
            "loc": [],
            "msg": "Request validation failed.",
            "type": "request_validation_error",
        }
    ]
}


@pytest.fixture
def service() -> MagicMock:
    return MagicMock()


@pytest.fixture
def client(service: MagicMock) -> Generator[TestClient]:
    previous = app.dependency_overrides.copy()

    app.dependency_overrides.update(
        {
            get_incident_service: lambda: service,
            get_ai_analysis_query_service: lambda: service,
            get_persistent_ai_analysis_service: lambda: service,
            get_log_ingestion_service: lambda: service,
            get_log_query_service: lambda: service,
            get_settings: lambda: Settings(),
        }
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"{BASE}/{SECRET}"),
        ("PATCH", f"{BASE}/{SECRET}"),
        ("DELETE", f"{BASE}/{SECRET}"),
        ("GET", f"{BASE}?limit={SECRET}"),
        ("GET", f"{BASE}?offset={SECRET}"),
        ("GET", f"{BASE}?status={SECRET}"),
        ("GET", f"{BASE}?priority={SECRET}"),
        ("GET", f"{INCIDENT}/analyses/{SECRET}"),
        ("GET", f"{INCIDENT}/analyses?status={SECRET}"),
        ("GET", f"{INCIDENT}/analyses?limit={SECRET}"),
        ("GET", f"{INCIDENT}/logs/{SECRET}"),
        ("DELETE", f"{INCIDENT}/logs/{SECRET}"),
        ("GET", f"{SUBMISSION}/entries/{SECRET}"),
        ("GET", f"{SUBMISSION}/entries?severity={SECRET}"),
        ("GET", f"{SUBMISSION}/entries?offset={SECRET}"),
        ("GET", f"{INCIDENT}/logs?limit={SECRET}"),
        ("GET", f"{INCIDENT}/logs/{SECRET}/evidence"),
    ],
)
def test_invalid_path_and_query_values_are_not_exposed(
    client: TestClient,
    service: MagicMock,
    method: str,
    path: str,
) -> None:
    response = client.request(method, path)

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


@pytest.mark.parametrize(
    "payload",
    [
        {"log_submission_id": SECRET},
        {SECRET: "synthetic-value"},
        {"log_submission_id": [SECRET]},
        {"log_submission_id": {"token": SECRET}},
        [SECRET],
        SECRET,
        {
            "log_submission_id": SECRET,
            SECRET: SECRET,
        },
    ],
)
def test_invalid_analysis_body_is_not_exposed(
    client: TestClient,
    service: MagicMock,
    payload: object,
) -> None:
    response = client.post(
        f"{INCIDENT}/analyses",
        json=payload,
    )

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


@pytest.mark.parametrize(
    "payload",
    [
        {"title": SECRET},
        {"title": SECRET, "description": [SECRET]},
        {
            "title": "Synthetic incident",
            "description": "Synthetic description",
            "priority": SECRET,
        },
        {
            "title": "Synthetic incident",
            "description": "Synthetic description",
            SECRET: SECRET,
        },
        {
            "title": "Synthetic incident",
            "description": SECRET * 1000,
        },
    ],
)
def test_invalid_incident_body_is_not_exposed(
    client: TestClient,
    service: MagicMock,
    payload: dict[str, object],
) -> None:
    response = client.post(BASE, json=payload)

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


def test_model_validation_context_is_not_exposed(
    client: TestClient,
    service: MagicMock,
) -> None:
    response = client.patch(
        INCIDENT,
        json={"title": None, "resolution": SECRET},
    )

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


@pytest.mark.parametrize(
    "path",
    [
        BASE,
        f"{INCIDENT}/analyses",
    ],
)
def test_malformed_json_is_not_exposed(
    client: TestClient,
    service: MagicMock,
    path: str,
) -> None:
    response = client.post(
        path,
        content='{"token":"' + SECRET,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


def test_invalid_log_format_is_not_exposed(
    client: TestClient,
    service: MagicMock,
) -> None:
    response = client.post(
        f"{INCIDENT}/logs",
        params={"source_format": SECRET},
        content=SECRET,
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert SECRET not in response.text
    assert service.mock_calls == []


def test_multiple_errors_return_one_safe_response(
    client: TestClient,
    service: MagicMock,
) -> None:
    response = client.get(
        BASE,
        params={
            "offset": SECRET,
            "limit": SECRET,
            "priority": SECRET,
            "status": SECRET,
        },
    )

    assert response.status_code == 422
    assert response.json() == SAFE_RESPONSE
    assert service.mock_calls == []


def test_validation_response_uses_json_media_type(
    client: TestClient,
) -> None:
    response = client.get(f"{BASE}/{SECRET}")

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/json"


def test_business_http_exception_is_preserved(
    client: TestClient,
    service: MagicMock,
) -> None:
    service.get_incident.side_effect = HTTPException(
        status_code=409,
        detail="Synthetic business conflict.",
    )

    response = client.get(INCIDENT)

    assert response.status_code == 409
    assert response.json() == {"detail": "Synthetic business conflict."}


def test_unmatched_route_preserves_not_found(
    client: TestClient,
) -> None:
    response = client.get("/nonexistent-security-test-route")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_health_endpoint_is_unaffected(
    client: TestClient,
) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
