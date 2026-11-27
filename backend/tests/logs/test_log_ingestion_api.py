import asyncio
from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from starlette.types import Message

from app.api.log_dependencies import (
    get_log_ingestion_service,
)
from app.api.log_requests import read_log_payload
from app.core.config import Settings, get_settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.extraction_contracts import EvidencePackage
from app.logs.ingestion_contracts import LogIngestionResult
from app.main import app
from app.models.log_enums import LogFormat
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.services.log_ingestion import LogIngestionService


@pytest.fixture
def incident_id() -> UUID:
    return uuid4()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        log_max_payload_bytes=1024,
        log_max_metadata_chars=100,
    )


@pytest.fixture
def service(
    incident_id: UUID,
) -> MagicMock:
    mock = MagicMock(
        spec=LogIngestionService,
    )

    mock.ingest.return_value = LogIngestionResult(
        submission_id=uuid4(),
        incident_id=incident_id,
        source_format=LogFormat.TEXT,
        source_name=None,
        payload_bytes=32,
        entry_count=1,
        redaction_count=0,
        created_at=datetime.now(UTC),
        evidence=EvidencePackage(
            source_format=LogFormat.TEXT,
            total_events=1,
            diagnostic_events=0,
            events=(),
        ),
    )

    return mock


@pytest.fixture
def client(
    service: MagicMock,
    settings: Settings,
) -> Generator[TestClient]:
    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_log_ingestion_service] = lambda: service

    app.dependency_overrides[get_settings] = lambda: settings

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
    return f"/api/v1/incidents/{incident_id}/logs"


@pytest.mark.parametrize(
    ("source_format", "content_type", "payload"),
    [
        (
            LogFormat.TEXT,
            "text/plain",
            b"ERROR Database connection failed.",
        ),
        (
            LogFormat.XML,
            "application/xml",
            b'<event severity="ERROR" message="Failure"/>',
        ),
        (
            LogFormat.XML,
            "text/xml",
            b'<event severity="ERROR" message="Failure"/>',
        ),
        (
            LogFormat.JSON,
            "application/json",
            b'{"severity":"ERROR","message":"Failure"}',
        ),
        (
            LogFormat.TEXT,
            "text/plain; charset=UTF-8",
            b"ERROR Database connection failed.",
        ),
        (
            LogFormat.JSON,
            'application/json; charset="utf-8"',
            b'{"severity":"ERROR","message":"Failure"}',
        ),
    ],
)
def test_ingest_supported_log_formats(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    source_format: LogFormat,
    content_type: str,
    payload: bytes,
) -> None:
    from dataclasses import replace

    previous: LogIngestionResult = service.ingest.return_value

    service.ingest.return_value = replace(
        previous,
        source_format=source_format,
        payload_bytes=len(payload),
        evidence=replace(
            previous.evidence,
            source_format=source_format,
        ),
    )

    response = client.post(
        endpoint,
        params={"source_format": source_format.value},
        content=payload,
        headers={"Content-Type": content_type},
    )

    assert response.status_code == 201

    data = response.json()

    assert data["incident_id"] == str(incident_id)
    assert data["source_format"] == source_format.value
    assert data["payload_bytes"] == len(payload)
    assert data["entry_count"] == 1
    assert data["was_redacted"] is False
    assert data["has_diagnostic_evidence"] is False
    assert "raw_payload" not in data

    service.ingest.assert_called_once_with(
        incident_id,
        payload,
        source_format,
        source_name=None,
    )


def test_ingestion_passes_source_name(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
) -> None:
    payload = b"INFO Application started."

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=payload,
        headers={
            "Content-Type": "text/plain",
            "X-Log-Source-Name": "application.log",
        },
    )

    assert response.status_code == 201

    service.ingest.assert_called_once_with(
        incident_id,
        payload,
        LogFormat.TEXT,
        source_name="application.log",
    )


@pytest.mark.parametrize(
    ("source_format", "content_type"),
    [
        ("text", "application/json"),
        ("json", "text/plain"),
        ("xml", "application/json"),
        ("text", "application/octet-stream"),
        ("text", "multipart/form-data"),
        ("text", ""),
        ("text", "text/plain; charset=utf-16"),
        ("text", "text/plain; charset=ascii"),
        ("text", "text/plain; charset"),
        ("text", "text/plain; boundary=synthetic"),
    ],
)
def test_unsupported_content_type(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    source_format: str,
    content_type: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": source_format},
        content=b"INFO Application started.",
        headers={"Content-Type": content_type},
    )

    assert response.status_code == 415

    service.ingest.assert_not_called()


@pytest.mark.parametrize(
    "encoding",
    ["gzip", "deflate", "br", "identity,gzip"],
)
def test_compressed_requests_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    encoding: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"synthetic-payload",
        headers={
            "Content-Type": "text/plain",
            "Content-Encoding": encoding,
        },
    )

    assert response.status_code == 415

    service.ingest.assert_not_called()


@pytest.mark.parametrize(
    "source_format",
    ["unsupported", "", "csv"],
)
def test_invalid_source_format(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    source_format: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": source_format},
        content=b"INFO Application started.",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 422

    service.ingest.assert_not_called()


def test_missing_source_format(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        content=b"INFO Application started.",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 422

    service.ingest.assert_not_called()


def test_invalid_incident_identifier(
    client: TestClient,
    service: MagicMock,
) -> None:
    response = client.post(
        "/api/v1/incidents/invalid-id/logs",
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 422

    service.ingest.assert_not_called()


def test_empty_log_request(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 400

    service.ingest.assert_not_called()


def test_exact_payload_limit_accepted(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
) -> None:
    payload = b"A" * 1024

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=payload,
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 201

    service.ingest.assert_called_once_with(
        incident_id,
        payload,
        LogFormat.TEXT,
        source_name=None,
    )


def test_payload_over_limit_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"A" * 1025,
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 413

    service.ingest.assert_not_called()


@pytest.mark.parametrize(
    "length",
    ["invalid", "-1", "1.5", "+32", ""],
)
def test_invalid_content_length(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    length: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers={
            "Content-Type": "text/plain",
            "Content-Length": length,
        },
    )

    assert response.status_code == 400

    service.ingest.assert_not_called()


def test_declared_length_over_limit(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers={
            "Content-Type": "text/plain",
            "Content-Length": "1025",
        },
    )

    assert response.status_code == 413

    service.ingest.assert_not_called()


def test_extreme_content_length(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"A",
        headers={
            "Content-Type": "text/plain",
            "Content-Length": "9" * 5000,
        },
    )

    assert response.status_code == 413

    service.ingest.assert_not_called()


def test_source_name_over_limit(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers={
            "Content-Type": "text/plain",
            "X-Log-Source-Name": "A" * 101,
        },
    )

    assert response.status_code == 413

    service.ingest.assert_not_called()


def test_missing_incident_returns_not_found(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
) -> None:
    service.ingest.side_effect = IncidentNotFoundError(incident_id)

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == ("Incident was not found.")

    service.ingest.assert_called_once()


@pytest.mark.parametrize(
    ("exception_type", "expected_status"),
    [
        (InvalidLogPayloadError, 400),
        (InvalidLogEncodingError, 400),
        (MalformedLogError, 400),
        (UnsafeLogContentError, 400),
        (LogPayloadTooLargeError, 413),
        (LogResourceLimitError, 413),
    ],
)
def test_service_errors_do_not_expose_credentials(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    exception_type: type[Exception],
    expected_status: int,
) -> None:
    canary = "SYNTHETIC_SECRET_CANARY"

    service.ingest.side_effect = exception_type(canary)

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"ERROR Database connection failed.",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == expected_status
    assert canary not in response.text

    service.ingest.assert_called_once()


@pytest.mark.parametrize(
    "declared_length",
    [None, b"1"],
)
def test_actual_stream_size_limit(
    declared_length: bytes | None,
) -> None:
    headers = [
        (b"content-type", b"text/plain"),
    ]

    if declared_length is not None:
        headers.append((b"content-length", declared_length))

    messages: list[Message] = [
        {
            "type": "http.request",
            "body": b"A" * 600,
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": b"B" * 425,
            "more_body": False,
        },
    ]

    async def receive() -> Message:
        return messages.pop(0)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logs",
            "headers": headers,
        },
        receive,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 413


def test_multiple_stream_chunks_accepted() -> None:
    messages: list[Message] = [
        {
            "type": "http.request",
            "body": b"ERROR ",
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": b"Database failure.",
            "more_body": False,
        },
    ]

    async def receive() -> Message:
        return messages.pop(0)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logs",
            "headers": [
                (b"content-type", b"text/plain"),
            ],
        },
        receive,
    )

    result = asyncio.run(
        read_log_payload(
            request,
            LogFormat.TEXT,
            1024,
        )
    )

    assert result == b"ERROR Database failure."


def test_interrupted_stream_rejected() -> None:
    messages: list[Message] = [
        {
            "type": "http.request",
            "body": b"ERROR ",
            "more_body": True,
        },
        {
            "type": "http.disconnect",
        },
    ]

    async def receive() -> Message:
        return messages.pop(0)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logs",
            "headers": [
                (b"content-type", b"text/plain"),
            ],
        },
        receive,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400
    assert error.value.detail == ("Log upload was interrupted.")


def test_log_ingestion_openapi_registration(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    document = response.json()

    operation = document["paths"]["/api/v1/incidents/{incident_id}/logs"]["post"]

    assert operation["tags"] == ["Application Logs"]

    request_body = operation["requestBody"]

    assert request_body["required"] is True

    assert set(request_body["content"]) == {
        "application/xml",
        "text/xml",
        "application/json",
        "text/plain",
    }

    assert {
        "201",
        "400",
        "404",
        "413",
        "415",
        "422",
    }.issubset(operation["responses"])


@pytest.mark.parametrize(
    "source_name",
    (
        "application.log",
        "production-server",
        "Service 01",
        "logs/application.log",
        "database_backup-2026",
        "caf%C3%A9",
        "service+worker",
        "A" * 100,
    ),
)
def test_ascii_source_name_contract(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    source_name: str,
) -> None:
    payload = b"INFO Application started."

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=payload,
        headers={
            "Content-Type": "text/plain",
            "X-Log-Source-Name": source_name,
        },
    )

    assert response.status_code == 201

    service.ingest.assert_called_once_with(
        incident_id,
        payload,
        LogFormat.TEXT,
        source_name=source_name,
    )


@pytest.mark.parametrize(
    "raw_value",
    (
        b"caf\xe9",
        "caf\u00e9".encode(),
        "cafe\u0301".encode(),
        "\u30b5\u30fc\u30d3\u30b9".encode(),
        "\u63a5\u7d9a\u5931\u6557".encode(),
        "\u0645\u06cc\u200c\u0631\u0648\u062f".encode(),
        "\u0915\u094d\u200d\u0937".encode(),
        "\U0001f469\u200d\U0001f4bb".encode(),
        "\uff53\uff45\uff52\uff56\uff49\uff43\uff45".encode(),
        b"\xff",
        b"\xc0\xaf",
        b"\xe2\x82",
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\x80",
        b"\xa0",
        b"\xef\xbb\xbfservice",
        "service\u200bname".encode(),
        "service\u202ename".encode(),
        "service\u3000name".encode(),
    ),
)
def test_non_ascii_source_name_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    raw_value: bytes,
) -> None:
    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers=[
            (b"content-type", b"text/plain"),
            (b"x-log-source-name", raw_value),
        ],
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": ("Log source name must contain only printable ASCII characters."),
    }

    service.ingest.assert_not_called()


@pytest.mark.parametrize(
    "control",
    (0, 1, 8, 9, 11, 12, 27, 31, 127),
)
def test_source_name_control_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    control: int,
) -> None:
    raw_value = b"service" + bytes([control]) + b"name"

    response = client.post(
        endpoint,
        params={"source_format": "text"},
        content=b"INFO Application started.",
        headers=[
            (b"content-type", b"text/plain"),
            (b"x-log-source-name", raw_value),
        ],
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": ("Log source name must contain only printable ASCII characters."),
    }

    service.ingest.assert_not_called()


@pytest.mark.parametrize(
    ("source_format", "content_type", "payload"),
    (
        (
            LogFormat.TEXT,
            "text/plain",
            "ERROR \u63a5\u7d9a\u5931\u6557".encode(),
        ),
        (
            LogFormat.JSON,
            "application/json",
            '{"message":"caf\u00e9"}'.encode(),
        ),
        (
            LogFormat.XML,
            "application/xml",
            "<entry><message>\u63a5\u7d9a</message></entry>".encode(),
        ),
    ),
)
def test_ascii_header_preserves_unicode_log_body(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    source_format: LogFormat,
    content_type: str,
    payload: bytes,
) -> None:
    from dataclasses import replace

    previous: LogIngestionResult = service.ingest.return_value

    service.ingest.return_value = replace(
        previous,
        source_format=source_format,
        payload_bytes=len(payload),
        evidence=replace(
            previous.evidence,
            source_format=source_format,
        ),
    )

    response = client.post(
        endpoint,
        params={"source_format": source_format.value},
        content=payload,
        headers={
            "Content-Type": content_type,
            "X-Log-Source-Name": "international-service",
        },
    )

    assert response.status_code == 201

    service.ingest.assert_called_once_with(
        incident_id,
        payload,
        source_format,
        source_name="international-service",
    )


def test_source_name_openapi_encoding_contract(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    operation = response.json()["paths"]["/api/v1/incidents/{incident_id}/logs"]["post"]

    parameters = [
        parameter
        for parameter in operation["parameters"]
        if parameter["name"] == "X-Log-Source-Name"
    ]

    assert len(parameters) == 1

    header = parameters[0]

    assert header["in"] == "header"
    assert header["required"] is False
    assert "printable ASCII" in header["description"]
    assert "400" in operation["responses"]
    assert "413" in operation["responses"]
