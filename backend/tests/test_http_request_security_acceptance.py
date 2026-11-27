from collections.abc import Generator
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from app.api.ai_dependencies import (
    get_persistent_ai_analysis_service,
)
from app.api.ai_requests import MAX_AI_REQUEST_BYTES
from app.api.log_dependencies import get_log_ingestion_service
from app.core.config import Settings, get_settings
from app.main import app

CANARY = "SYNTHETIC_CONFIDENTIAL_HTTP_ACCEPTANCE_VALUE"

SAFE_VALIDATION_RESPONSE = {
    "detail": [
        {
            "loc": [],
            "msg": "Request validation failed.",
            "type": "request_validation_error",
        }
    ]
}


@pytest.fixture
def services() -> tuple[MagicMock, MagicMock]:
    return MagicMock(), MagicMock()


@pytest.fixture
def client(
    services: tuple[MagicMock, MagicMock],
) -> Generator[TestClient]:
    ingestion, analysis = services
    previous = app.dependency_overrides.copy()

    app.dependency_overrides.update(
        {
            get_log_ingestion_service: lambda: ingestion,
            get_persistent_ai_analysis_service: lambda: analysis,
            get_settings: lambda: Settings(
                log_max_payload_bytes=1024,
                log_max_metadata_chars=100,
            ),
        }
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.fixture
def incident_path() -> str:
    return f"/api/v1/incidents/{uuid4()}"


def assert_rejected(
    response: Response,
    services: tuple[MagicMock, MagicMock],
    expected_status: int,
) -> None:
    assert response.status_code == expected_status
    assert CANARY not in response.text

    assert response.headers["content-type"] == ("application/json")

    assert set(response.json()) == {"detail"}

    if expected_status == 422:
        assert response.json() == SAFE_VALIDATION_RESPONSE

    for service in services:
        assert service.mock_calls == []


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Type", "text/plain"),
            ],
            400,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "4"),
                ("Content-Length", "5"),
            ],
            400,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Encoding", "identity"),
                ("Content-Encoding", "gzip"),
            ],
            400,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("X-Log-Source-Name", CANARY),
                ("X-Log-Source-Name", "application.log"),
            ],
            400,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "4"),
                ("Transfer-Encoding", "chunked"),
            ],
            400,
        ),
        (
            [
                (
                    "Content-Type",
                    "text/plain; charset=utf-8; charset=utf-8",
                )
            ],
            415,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Encoding", "gzip"),
            ],
            415,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "1025"),
            ],
            413,
        ),
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "1"),
            ],
            400,
        ),
    ],
)
def test_log_endpoint_rejects_unsafe_headers(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
    headers: list[tuple[str, str]],
    expected_status: int,
) -> None:
    response = client.post(
        f"{incident_path}/logs",
        params={"source_format": "text"},
        content=CANARY.encode(),
        headers=headers,
    )

    assert_rejected(
        response,
        services,
        expected_status,
    )


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        (
            [
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            ],
            400,
        ),
        (
            [
                ("Content-Length", "2"),
                ("Content-Length", "3"),
            ],
            400,
        ),
        (
            [
                ("Content-Length", "2"),
                ("Transfer-Encoding", "chunked"),
            ],
            400,
        ),
        (
            [
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
            ],
            415,
        ),
        (
            [
                (
                    "Content-Type",
                    "application/json; charset=ascii",
                )
            ],
            415,
        ),
        (
            [
                ("Content-Type", "text/plain"),
            ],
            415,
        ),
        (
            [
                (
                    "Content-Length",
                    str(MAX_AI_REQUEST_BYTES + 1),
                ),
            ],
            413,
        ),
        (
            [
                ("Content-Length", "1"),
            ],
            400,
        ),
    ],
)
def test_ai_endpoint_rejects_unsafe_headers(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
    headers: list[tuple[str, str]],
    expected_status: int,
) -> None:
    response = client.post(
        f"{incident_path}/analyses",
        content=b"{}",
        headers=headers,
    )

    assert_rejected(
        response,
        services,
        expected_status,
    )


@pytest.mark.parametrize(
    ("suffix", "limit", "content_type", "params"),
    [
        (
            "/logs",
            1024,
            "text/plain",
            {"source_format": "text"},
        ),
        (
            "/analyses",
            MAX_AI_REQUEST_BYTES,
            "application/json",
            {},
        ),
    ],
)
def test_endpoints_reject_streaming_overflow(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
    suffix: str,
    limit: int,
    content_type: str,
    params: dict[str, str],
) -> None:
    response = client.post(
        incident_path + suffix,
        params=params,
        headers={"Content-Type": content_type},
        content=iter(
            [
                b" " * limit,
                CANARY.encode(),
            ]
        ),
    )

    assert_rejected(response, services, 413)


@pytest.mark.parametrize(
    "payload",
    [
        {"log_submission_id": CANARY},
        {CANARY: CANARY},
        {"log_submission_id": [CANARY]},
        {"log_submission_id": {"secret": CANARY}},
        [CANARY],
        CANARY,
    ],
)
def test_ai_validation_never_exposes_input(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
    payload: object,
) -> None:
    response = client.post(
        f"{incident_path}/analyses",
        json=payload,
    )

    assert_rejected(response, services, 422)


def test_malformed_ai_json_never_exposes_input(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
) -> None:
    response = client.post(
        f"{incident_path}/analyses",
        content='{"secret":"' + CANARY,
        headers={"Content-Type": "application/json"},
    )

    assert_rejected(response, services, 422)


def test_invalid_log_format_never_exposes_input(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
) -> None:
    response = client.post(
        f"{incident_path}/logs",
        params={"source_format": CANARY},
        content=CANARY.encode(),
        headers={"Content-Type": "text/plain"},
    )

    assert_rejected(response, services, 422)


def test_invalid_ai_path_never_exposes_input(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
) -> None:
    response = client.post(
        f"/api/v1/incidents/{CANARY}/analyses",
        json={},
    )

    assert_rejected(response, services, 422)


def test_invalid_log_path_never_exposes_input(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
) -> None:
    response = client.post(
        f"/api/v1/incidents/{CANARY}/logs",
        params={"source_format": "text"},
        content=CANARY.encode(),
        headers={"Content-Type": "text/plain"},
    )

    assert_rejected(response, services, 422)


def test_invalid_ai_utf8_rejected(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
) -> None:
    response = client.post(
        f"{incident_path}/analyses",
        content=CANARY.encode() + bytes([255]),
        headers={"Content-Type": "application/json"},
    )

    assert_rejected(response, services, 400)


def test_oversized_ai_body_rejected_before_validation(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
    incident_path: str,
) -> None:
    response = client.post(
        f"{incident_path}/analyses",
        json={"log_submission_id": CANARY * 1000},
    )

    assert_rejected(response, services, 413)


def test_application_health_unaffected(
    client: TestClient,
    services: tuple[MagicMock, MagicMock],
) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

    for service in services:
        assert service.mock_calls == []
