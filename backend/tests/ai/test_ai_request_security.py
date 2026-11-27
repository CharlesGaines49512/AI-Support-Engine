import asyncio
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from starlette.types import Message

from app.api.ai_dependencies import get_persistent_ai_analysis_service
from app.api.ai_requests import (
    MAX_AI_REQUEST_BYTES,
    read_ai_request_body,
)
from app.core.exceptions import IncidentNotFoundError
from app.main import app

SECRET = "SYNTHETIC_AI_REQUEST_SECURITY_CANARY"


def make_request(
    headers: list[tuple[bytes, bytes]],
    chunks: list[Message],
) -> Request:
    messages = list(chunks)

    async def receive() -> Message:
        return messages.pop(0)

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/analyses",
            "headers": headers,
        },
        receive,
    )


def single_body(
    payload: bytes,
) -> list[Message]:
    return [
        {
            "type": "http.request",
            "body": payload,
            "more_body": False,
        }
    ]


@pytest.fixture
def service() -> MagicMock:
    mock = MagicMock()
    return mock


@pytest.fixture
def client(
    service: MagicMock,
) -> Generator[TestClient]:
    previous = app.dependency_overrides.copy()

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: service

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.fixture
def endpoint() -> str:
    return f"/api/v1/incidents/{uuid4()}/analyses"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{}",
        b"null",
        b'{"log_submission_id":null}',
        b" " * (MAX_AI_REQUEST_BYTES - 2) + b"{}",
    ],
)
def test_bounded_body_accepts_valid_sizes(
    payload: bytes,
) -> None:
    request = make_request(
        [(b"content-type", b"application/json")],
        single_body(payload),
    )

    assert asyncio.run(read_ai_request_body(request)) == payload


@pytest.mark.parametrize(
    "length",
    [
        b"4097",
        b"999999999999999999999999999999999",
        b"0004097",
    ],
)
def test_oversized_declared_length_rejected(
    length: bytes,
) -> None:
    request = make_request(
        [(b"content-length", length)],
        [],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 413


@pytest.mark.parametrize(
    "length",
    [
        b"",
        b"-1",
        b"+4",
        b"4,4",
        b"4.0",
        b"invalid",
    ],
)
def test_invalid_length_rejected(
    length: bytes,
) -> None:
    request = make_request(
        [(b"content-length", length)],
        [],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (b"content-length", b"2"),
        (b"content-type", b"application/json"),
        (b"content-encoding", b"identity"),
        (b"transfer-encoding", b"chunked"),
    ],
)
def test_duplicate_headers_rejected(
    header: bytes,
    value: bytes,
) -> None:
    request = make_request(
        [
            (header, value),
            (header, value),
        ],
        [],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "headers",
    [
        [
            (b"content-length", b"2"),
            (b"transfer-encoding", b"chunked"),
        ],
        [(b"transfer-encoding", b"gzip")],
        [(b"transfer-encoding", b"chunked, chunked")],
    ],
)
def test_ambiguous_framing_rejected(
    headers: list[tuple[bytes, bytes]],
) -> None:
    request = make_request(headers, [])

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "encoding",
    [b"gzip", b"deflate", b"br", b"identity,gzip"],
)
def test_compressed_requests_rejected(
    encoding: bytes,
) -> None:
    request = make_request(
        [(b"content-encoding", encoding)],
        [],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 415


@pytest.mark.parametrize(
    "media_type",
    [
        b"text/plain",
        b"application/xml",
        b"application/json; charset=ascii",
        b'application/json; charset="utf-8',
        b"application/json; charset=utf-8; charset=utf-8",
        b"application/json; charset",
        b"application/json; boundary=synthetic",
    ],
)
def test_invalid_content_type_rejected(
    media_type: bytes,
) -> None:
    request = make_request(
        [(b"content-type", media_type)],
        [],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 415


@pytest.mark.parametrize(
    "media_type",
    [
        b"application/json",
        b"application/json; charset=UTF-8",
        b'application/json; charset="utf-8"',
    ],
)
def test_supported_content_type_preserved(
    media_type: bytes,
) -> None:
    request = make_request(
        [
            (b"content-type", media_type),
            (b"content-length", b"0002"),
            (b"content-encoding", b"identity"),
        ],
        single_body(b"{}"),
    )

    assert asyncio.run(read_ai_request_body(request)) == b"{}"


def test_chunked_request_preserved() -> None:
    request = make_request(
        [(b"transfer-encoding", b"chunked")],
        [
            {
                "type": "http.request",
                "body": b"{",
                "more_body": True,
            },
            {
                "type": "http.request",
                "body": b"}",
                "more_body": False,
            },
        ],
    )

    assert asyncio.run(read_ai_request_body(request)) == b"{}"


def test_streaming_overflow_rejected() -> None:
    request = make_request(
        [],
        [
            {
                "type": "http.request",
                "body": b" " * MAX_AI_REQUEST_BYTES,
                "more_body": True,
            },
            {
                "type": "http.request",
                "body": b"x",
                "more_body": False,
            },
        ],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 413


@pytest.mark.parametrize(
    "length",
    [b"0", b"1", b"3"],
)
def test_content_length_mismatch_rejected(
    length: bytes,
) -> None:
    request = make_request(
        [(b"content-length", length)],
        single_body(b"{}"),
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


def test_interrupted_request_rejected() -> None:
    request = make_request(
        [],
        [{"type": "http.disconnect"}],
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


def test_invalid_utf8_rejected() -> None:
    request = make_request(
        [],
        single_body(bytes([255])),
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_ai_request_body(request))

    assert error.value.status_code == 400


def test_oversized_endpoint_request_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        json={"log_submission_id": SECRET * 1000},
    )

    assert response.status_code == 413
    assert SECRET not in response.text
    assert service.mock_calls == []


def test_streamed_endpoint_request_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.post(
        endpoint,
        content=iter(
            [
                b" " * MAX_AI_REQUEST_BYTES,
                b"{}",
            ]
        ),
        headers={
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 413
    assert service.mock_calls == []


@pytest.mark.parametrize(
    "header",
    [
        "Content-Type",
        "Content-Encoding",
        "Content-Length",
    ],
)
def test_duplicate_endpoint_headers_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    header: str,
) -> None:
    values = {
        "Content-Type": "application/json",
        "Content-Encoding": "identity",
        "Content-Length": "2",
    }

    response = client.post(
        endpoint,
        content=b"{}",
        headers=[
            (header, values[header]),
            (header, values[header]),
        ],
    )

    assert response.status_code == 400
    assert service.mock_calls == []


def test_endpoint_size_boundary(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    incident_id = endpoint.split("/")[-2]

    service.analyze_incident = AsyncMock(
        side_effect=IncidentNotFoundError(UUID(incident_id))
    )

    response = client.post(
        endpoint,
        content=b" " * (MAX_AI_REQUEST_BYTES - 2) + b"{}",
        headers={
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 404

    service.analyze_incident.assert_called_once_with(UUID(incident_id))


@pytest.mark.parametrize(
    "subsequent_message",
    [
        {"type": "http.disconnect"},
        {
            "type": "http.request",
            "body": b"",
            "more_body": False,
        },
    ],
)
def test_bounded_route_preserves_subsequent_receive(
    subsequent_message: Message,
) -> None:
    from fastapi import FastAPI
    from starlette.responses import JSONResponse
    from starlette.types import Scope

    from app.api.ai_requests import BoundedAIRequestRoute

    test_app = FastAPI()

    test_app.router.route_class = BoundedAIRequestRoute

    @test_app.post("/replay")
    async def replay(request: Request) -> JSONResponse:
        first = await request.receive()
        second = await request.receive()

        assert first == {
            "type": "http.request",
            "body": b"{}",
            "more_body": False,
        }

        assert second == subsequent_message

        return JSONResponse(
            content={"verified": True},
        )

    messages: list[Message] = [
        {
            "type": "http.request",
            "body": b"{",
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": b"}",
            "more_body": False,
        },
        subsequent_message,
    ]

    sent: list[Message] = []

    async def receive() -> Message:
        return messages.pop(0)

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {
            "version": "3.0",
            "spec_version": "2.4",
        },
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/replay",
        "raw_path": b"/replay",
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    asyncio.run(test_app(scope, receive, send))

    assert messages == []

    assert len(sent) == 2

    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 200

    assert sent[1]["type"] == "http.response.body"
    assert sent[1]["body"] == b'{"verified":true}'
