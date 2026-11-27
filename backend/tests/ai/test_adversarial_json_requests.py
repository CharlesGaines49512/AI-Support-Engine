import codecs
import json
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.ai_dependencies import (
    get_persistent_ai_analysis_service,
)
from app.core.exceptions import IncidentNotFoundError
from app.main import app

INCIDENT_ID = UUID("10000000-0000-4000-8000-000000000001")
SUBMISSION_ID = UUID("20000000-0000-4000-8000-000000000002")

ENDPOINT = f"/api/v1/incidents/{INCIDENT_ID}/analyses"

CANARY = "SYNTHETIC_JSON_SECURITY_CANARY"

CONTENT_TYPES = (
    "application/json",
    "application/json; charset=utf-8",
    None,
)

UNSUPPORTED_ENCODINGS = (
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "utf-32",
    "utf-32-le",
    "utf-32-be",
)

INVALID_PAYLOADS = (
    b"\xff",
    b"\xc0\xaf",
    b"\xed\xa0\x80",
    b"\xf4\x90\x80\x80",
    b"{}\x00",
    b"\x00{}",
    b"{\x00}",
    b'{"log_submission_id":"\x00"}',
)

DUPLICATE_DOCUMENTS = (
    '{"log_submission_id":null,"log_submission_id":null}',
    ('{"log_submission_id":"' + CANARY + '","log_submission_id":null}'),
    ('{"log_submission_id":null,"log_submission_id":"' + CANARY + '"}'),
    r'{"log_submission_id":null,"log_submission_\u0069d":null}',
    '{"log_submission_id":null,"unknown":{"x":1,"x":2}}',
)

NONSTANDARD_DOCUMENTS = (
    '{"log_submission_id":NaN}',
    '{"log_submission_id":Infinity}',
    '{"log_submission_id":-Infinity}',
    '{"unknown":NaN}',
    '{"unknown":Infinity}',
    '{"unknown":-Infinity}',
)

MALFORMED_DOCUMENTS = (
    "{",
    "[",
    '{"log_submission_id":}',
    '{"log_submission_id":null,}',
    '{"log_submission_id":null}{}',
    '{"log_submission_id":null} trailing',
    '{"log_submission_id":"' + CANARY,
    "true false",
)


@pytest.fixture
def service() -> MagicMock:
    mock = MagicMock()

    mock.analyze_incident = AsyncMock(side_effect=IncidentNotFoundError(INCIDENT_ID))

    return mock


@pytest.fixture
def client(
    service: MagicMock,
) -> Generator[TestClient]:
    previous = app.dependency_overrides.copy()

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: service

    try:
        with TestClient(
            app,
            raise_server_exceptions=False,
        ) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def request_headers(
    content_type: str | None,
) -> dict[str, str]:
    if content_type is None:
        return {}

    return {"Content-Type": content_type}


@pytest.mark.parametrize(
    "encoding",
    UNSUPPORTED_ENCODINGS,
)
@pytest.mark.parametrize(
    "document",
    ("{}", "null", '{"log_submission_id":null}'),
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_unsupported_json_encoding_rejected(
    client: TestClient,
    service: MagicMock,
    encoding: str,
    document: str,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=document.encode(encoding),
        headers=request_headers(content_type),
    )

    assert response.status_code == 400
    assert CANARY not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    INVALID_PAYLOADS,
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_invalid_json_bytes_rejected(
    client: TestClient,
    service: MagicMock,
    payload: bytes,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=payload,
        headers=request_headers(content_type),
    )

    assert response.status_code == 400
    assert CANARY not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "document",
    DUPLICATE_DOCUMENTS,
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_duplicate_json_keys_rejected(
    client: TestClient,
    service: MagicMock,
    document: str,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=document.encode("utf-8"),
        headers=request_headers(content_type),
    )

    assert response.status_code == 400
    assert CANARY not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "document",
    NONSTANDARD_DOCUMENTS,
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_nonstandard_json_constants_rejected(
    client: TestClient,
    service: MagicMock,
    document: str,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=document.encode("utf-8"),
        headers=request_headers(content_type),
    )

    assert response.status_code == 400
    assert CANARY not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "depth",
    (33, 64, 128, 512, 1000, 1500),
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_excessive_json_nesting_rejected(
    client: TestClient,
    service: MagicMock,
    depth: int,
    content_type: str | None,
) -> None:
    payload = ("[" * depth + "null" + "]" * depth).encode("utf-8")

    response = client.post(
        ENDPOINT,
        content=payload,
        headers=request_headers(content_type),
    )

    assert response.status_code == 400
    assert CANARY not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "document",
    MALFORMED_DOCUMENTS,
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_malformed_json_remains_confidential(
    client: TestClient,
    service: MagicMock,
    document: str,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=document.encode("utf-8"),
        headers=request_headers(content_type),
    )

    assert response.status_code in (400, 422)
    assert CANARY not in response.text
    assert "Traceback" not in response.text
    service.analyze_incident.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    (
        b"",
        b"{}",
        b"null",
        b'{"log_submission_id":null}',
        b" \r\n{}\t ",
        codecs.BOM_UTF8 + b"{}",
        codecs.BOM_UTF8 + b"null",
        codecs.BOM_UTF8 + b'{"log_submission_id":null}',
    ),
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_valid_optional_json_preserved(
    client: TestClient,
    service: MagicMock,
    payload: bytes,
    content_type: str | None,
) -> None:
    response = client.post(
        ENDPOINT,
        content=payload,
        headers=request_headers(content_type),
    )

    assert response.status_code == 404
    service.analyze_incident.assert_awaited_once_with(INCIDENT_ID)


@pytest.mark.parametrize(
    "prefix",
    (b"", codecs.BOM_UTF8),
)
@pytest.mark.parametrize(
    "content_type",
    CONTENT_TYPES,
)
def test_valid_log_submission_uuid_preserved(
    client: TestClient,
    service: MagicMock,
    prefix: bytes,
    content_type: str | None,
) -> None:
    payload = prefix + json.dumps({"log_submission_id": str(SUBMISSION_ID)}).encode(
        "utf-8"
    )

    response = client.post(
        ENDPOINT,
        content=payload,
        headers=request_headers(content_type),
    )

    assert response.status_code == 404

    service.analyze_incident.assert_awaited_once_with(
        INCIDENT_ID,
        submission_id=SUBMISSION_ID,
    )


@pytest.mark.parametrize("depth", (1, 15, 31, 32))
@pytest.mark.parametrize("structure", ("array", "object", "mixed"))
def test_json_depth_within_limit(
    depth: int,
    structure: str,
) -> None:
    from app.api.ai_requests import validate_ai_json_payload

    document = "null"

    for index in range(depth):
        if structure == "array":
            document = "[" + document + "]"
        elif structure == "object":
            document = '{"value":' + document + "}"
        elif index % 2 == 0:
            document = "[" + document + "]"
        else:
            document = '{"value":' + document + "}"

    validate_ai_json_payload(document.encode("utf-8"))


@pytest.mark.parametrize("depth", (33, 34, 64, 128))
@pytest.mark.parametrize("structure", ("array", "object", "mixed"))
def test_json_depth_exceeds_limit(
    depth: int,
    structure: str,
) -> None:
    from fastapi import HTTPException

    from app.api.ai_requests import validate_ai_json_payload

    document = "null"

    for index in range(depth):
        if structure == "array":
            document = "[" + document + "]"
        elif structure == "object":
            document = '{"value":' + document + "}"
        elif index % 2 == 0:
            document = "[" + document + "]"
        else:
            document = '{"value":' + document + "}"

    with pytest.raises(HTTPException) as captured:
        validate_ai_json_payload(document.encode("utf-8"))

    assert captured.value.status_code == 400


@pytest.mark.parametrize(
    "value",
    (
        "[" * 100,
        "]" * 100,
        "{" * 100,
        "}" * 100,
        "[{}]" * 100,
        '"' * 100,
        "\\" * 100,
        '\\"[{]}\\' * 30,
        "NaN Infinity -Infinity",
        "SYNTHETIC_JSON_SECURITY_CANARY",
    ),
)
def test_json_string_content_not_counted_as_structure(
    value: str,
) -> None:
    from app.api.ai_requests import validate_ai_json_payload

    document = json.dumps({"value": value})

    validate_ai_json_payload(document.encode("utf-8"))


@pytest.mark.parametrize(
    "payload",
    (
        b"}",
        b"]",
        b"{}]",
        b"[]}",
        b"}{}",
        b"][",
    ),
)
def test_unmatched_json_closing_structure_rejected(
    payload: bytes,
) -> None:
    from fastapi import HTTPException

    from app.api.ai_requests import validate_ai_json_payload

    with pytest.raises(HTTPException) as captured:
        validate_ai_json_payload(payload)

    assert captured.value.status_code == 400


@pytest.mark.parametrize(
    "payload",
    (
        codecs.BOM_UTF8,
        codecs.BOM_UTF8 * 2 + b"{}",
        b" " + codecs.BOM_UTF8 + b"{}",
        b"{}" + codecs.BOM_UTF8,
        codecs.BOM_UTF8 + b" ",
        codecs.BOM_UTF8 + b"{}\x00",
    ),
)
def test_invalid_bom_placement_rejected(
    payload: bytes,
) -> None:
    from fastapi import HTTPException

    from app.api.ai_requests import validate_ai_json_payload

    with pytest.raises(HTTPException) as captured:
        validate_ai_json_payload(payload)

    assert captured.value.status_code == 400
