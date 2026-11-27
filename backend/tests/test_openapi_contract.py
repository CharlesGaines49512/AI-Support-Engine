"""Regression tests for the published API contract."""

from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.ai_requests import (
    MAX_AI_JSON_DEPTH,
    MAX_AI_REQUEST_BYTES,
)
from app.core.config import Settings
from app.main import app
from app.parsers.json_parser import (
    COLLECTION_FIELDS,
    SUPPORTED_FIELDS,
)
from app.services.log_query import (
    MAX_PAGE_OFFSET,
    MAX_PAGE_SIZE,
)

INCIDENTS = "/api/v1/incidents"
INCIDENT = INCIDENTS + "/{incident_id}"
ANALYSES = INCIDENT + "/analyses"
LOGS = INCIDENT + "/logs"
SUBMISSION = LOGS + "/{submission_id}"
ENTRIES = SUBMISSION + "/entries"

EXPECTED_OPERATIONS = {
    ("/", "get"): {"200"},
    ("/health", "get"): {"200"},
    ("/ready", "get"): {"200", "503"},
    (INCIDENTS, "post"): {"201", "422"},
    (INCIDENTS, "get"): {"200", "422"},
    (INCIDENT, "get"): {"200", "404", "422"},
    (INCIDENT, "patch"): {"200", "404", "409", "422"},
    (INCIDENT, "delete"): {"204", "404", "422"},
    (ANALYSES, "post"): {
        "201",
        "400",
        "404",
        "409",
        "413",
        "415",
        "422",
    },
    (ANALYSES, "get"): {"200", "404", "422"},
    (ANALYSES + "/latest", "get"): {"200", "404", "422"},
    (ANALYSES + "/latest-successful", "get"): {
        "200",
        "404",
        "422",
    },
    (ANALYSES + "/{analysis_id}", "get"): {
        "200",
        "404",
        "422",
    },
    (LOGS, "post"): {"201", "400", "404", "413", "415", "422"},
    (LOGS, "get"): {"200", "404", "409", "422"},
    (SUBMISSION, "get"): {"200", "404", "409", "422"},
    (SUBMISSION, "delete"): {"204", "404", "422"},
    (ENTRIES, "get"): {"200", "404", "409", "422"},
    (ENTRIES + "/{entry_id}", "get"): {
        "200",
        "404",
        "409",
        "422",
    },
    (SUBMISSION + "/evidence", "get"): {
        "200",
        "404",
        "409",
        "422",
    },
}

VALIDATION_SCHEMA = {
    "type": "object",
    "required": ["detail"],
    "additionalProperties": False,
    "properties": {
        "detail": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "items": {
                "type": "object",
                "required": ["loc", "msg", "type"],
                "additionalProperties": False,
                "properties": {
                    "loc": {
                        "type": "array",
                        "maxItems": 0,
                    },
                    "msg": {
                        "type": "string",
                        "const": "Request validation failed.",
                    },
                    "type": {
                        "type": "string",
                        "const": "request_validation_error",
                    },
                },
            },
        },
    },
}

HTTP_ERROR_SCHEMA = {
    "type": "object",
    "required": ["detail"],
    "additionalProperties": False,
    "properties": {
        "detail": {"type": "string"},
    },
}

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}

STANDARD_ERROR_CASES = [
    (path, method, code)
    for (path, method), codes in EXPECTED_OPERATIONS.items()
    for code in sorted(codes)
    if code in {"400", "404", "409", "413", "415"}
]

VALIDATION_CASES = [
    (path, method)
    for (path, method), codes in EXPECTED_OPERATIONS.items()
    if "422" in codes
]


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return app.openapi()


def test_openapi_operation_inventory(
    schema: dict[str, Any],
) -> None:
    actual = {
        (path, method)
        for path, document in schema["paths"].items()
        for method in document
        if method in HTTP_METHODS
    }

    assert actual == set(EXPECTED_OPERATIONS)
    assert len(actual) == 20
    assert len(schema["paths"]) == 14


def test_openapi_operation_ids_are_unique(
    schema: dict[str, Any],
) -> None:
    identifiers = [
        schema["paths"][path][method]["operationId"]
        for path, method in EXPECTED_OPERATIONS
    ]

    assert all(identifiers)
    assert len(identifiers) == len(set(identifiers))


@pytest.mark.parametrize(
    ("path", "method", "codes"),
    [(path, method, codes) for (path, method), codes in EXPECTED_OPERATIONS.items()],
)
def test_endpoint_response_codes(
    schema: dict[str, Any],
    path: str,
    method: str,
    codes: set[str],
) -> None:
    responses = schema["paths"][path][method]["responses"]

    assert set(responses) == codes


@pytest.mark.parametrize(
    ("path", "method"),
    VALIDATION_CASES,
)
def test_confidential_validation_schema(
    schema: dict[str, Any],
    path: str,
    method: str,
) -> None:
    response = schema["paths"][path][method]["responses"]["422"]

    actual = response["content"]["application/json"]["schema"]

    assert actual == VALIDATION_SCHEMA


@pytest.mark.parametrize(
    ("path", "method", "code"),
    STANDARD_ERROR_CASES,
)
def test_standard_http_error_schema(
    schema: dict[str, Any],
    path: str,
    method: str,
    code: str,
) -> None:
    response = schema["paths"][path][method]["responses"][code]

    assert response["description"]
    assert response["content"]["application/json"]["schema"] == (HTTP_ERROR_SCHEMA)


@pytest.mark.parametrize(
    "path",
    ["/", "/health", "/ready"],
)
def test_system_endpoints_have_no_validation_response(
    schema: dict[str, Any],
    path: str,
) -> None:
    responses = schema["paths"][path]["get"]["responses"]

    assert "422" not in responses


@pytest.mark.parametrize(
    ("healthy", "status_code", "expected"),
    [
        (
            True,
            200,
            {"status": "ready", "database": "healthy"},
        ),
        (
            False,
            503,
            {"status": "not_ready", "database": "unavailable"},
        ),
    ],
)
def test_readiness_documentation_matches_runtime(
    schema: dict[str, Any],
    healthy: bool,
    status_code: int,
    expected: dict[str, str],
) -> None:
    response = schema["paths"]["/ready"]["get"]["responses"][str(status_code)]

    actual = response["content"]["application/json"]["schema"]

    assert actual == {
        "type": "object",
        "required": ["status", "database"],
        "additionalProperties": False,
        "properties": {
            key: {"type": "string", "const": value} for key, value in expected.items()
        },
    }

    with (
        patch(
            "app.main.check_database_health",
            return_value=healthy,
        ) as database_health,
        TestClient(app) as client,
    ):
        result = client.get("/ready")

    database_health.assert_called_once_with()

    assert result.status_code == status_code
    assert result.json() == expected
    assert result.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    ("path", "method"),
    [
        (INCIDENT, "delete"),
        (SUBMISSION, "delete"),
    ],
)
def test_no_content_responses_have_no_body_schema(
    schema: dict[str, Any],
    path: str,
    method: str,
) -> None:
    response = schema["paths"][path][method]["responses"]["204"]

    assert "content" not in response


@pytest.mark.parametrize(
    ("path", "method"),
    list(EXPECTED_OPERATIONS),
)
def test_path_parameter_contracts(
    schema: dict[str, Any],
    path: str,
    method: str,
) -> None:
    parameters = schema["paths"][path][method].get(
        "parameters",
        [],
    )

    path_parameters = [
        parameter for parameter in parameters if parameter["in"] == "path"
    ]

    expected_names = {
        segment[1:-1]
        for segment in path.split("/")
        if segment.startswith("{") and segment.endswith("}")
    }

    assert {parameter["name"] for parameter in path_parameters} == expected_names

    assert len(path_parameters) == len(expected_names)

    for parameter in path_parameters:
        assert parameter["required"] is True
        assert parameter["schema"]["type"] == "string"
        assert parameter["schema"]["format"] == "uuid"


@pytest.mark.parametrize(
    ("path", "maximum_offset"),
    [
        (INCIDENTS, None),
        (ANALYSES, None),
        (LOGS, MAX_PAGE_OFFSET),
        (ENTRIES, MAX_PAGE_OFFSET),
    ],
)
def test_pagination_contracts(
    schema: dict[str, Any],
    path: str,
    maximum_offset: int | None,
) -> None:
    parameters = {
        parameter["name"]: parameter
        for parameter in schema["paths"][path]["get"]["parameters"]
        if parameter["in"] == "query"
    }

    offset = parameters["offset"]
    limit = parameters["limit"]

    assert offset["required"] is False
    assert offset["schema"]["type"] == "integer"
    assert offset["schema"]["minimum"] == 0
    assert offset["schema"]["default"] == 0
    assert offset["schema"].get("maximum") == maximum_offset

    assert limit["required"] is False
    assert limit["schema"]["type"] == "integer"
    assert limit["schema"]["minimum"] == 1
    assert limit["schema"]["maximum"] == MAX_PAGE_SIZE
    assert limit["schema"]["default"] == 20


def test_request_body_inventory(
    schema: dict[str, Any],
) -> None:
    actual = {
        (path, method)
        for path, method in EXPECTED_OPERATIONS
        if "requestBody" in schema["paths"][path][method]
    }

    assert actual == {
        (INCIDENTS, "post"),
        (INCIDENT, "patch"),
        (ANALYSES, "post"),
        (LOGS, "post"),
    }


@pytest.mark.parametrize(
    ("path", "method", "component"),
    [
        (INCIDENTS, "post", "IncidentCreate"),
        (INCIDENT, "patch", "IncidentUpdate"),
    ],
)
def test_incident_request_body_contracts(
    schema: dict[str, Any],
    path: str,
    method: str,
    component: str,
) -> None:
    body = schema["paths"][path][method]["requestBody"]

    assert body["required"] is True
    assert set(body["content"]) == {"application/json"}

    assert body["content"]["application/json"]["schema"] == {
        "$ref": f"#/components/schemas/{component}",
    }


def test_ai_request_body_contract(
    schema: dict[str, Any],
) -> None:
    body = schema["paths"][ANALYSES]["post"]["requestBody"]

    assert not body.get("required", False)
    assert set(body["content"]) == {"application/json"}

    alternatives = body["content"]["application/json"]["schema"]["anyOf"]

    assert len(alternatives) == 2

    assert {"type": "null"} in alternatives
    assert {"$ref": "#/components/schemas/AIAnalysisRequest"} in alternatives


def test_ai_request_component_contract(
    schema: dict[str, Any],
) -> None:
    component = schema["components"]["schemas"]["AIAnalysisRequest"]

    assert component["type"] == "object"
    assert component["additionalProperties"] is False
    assert not component.get("required")
    assert set(component["properties"]) == {"log_submission_id"}

    alternatives = component["properties"]["log_submission_id"]["anyOf"]

    assert len(alternatives) == 2
    assert {"type": "null"} in alternatives
    assert {"type": "string", "format": "uuid"} in alternatives


def test_log_request_media_types(
    schema: dict[str, Any],
) -> None:
    body = schema["paths"][LOGS]["post"]["requestBody"]

    assert body["required"] is True

    assert set(body["content"]) == {
        "application/xml",
        "text/xml",
        "application/json",
        "text/plain",
    }

    for media_type in ("application/xml", "text/xml", "text/plain"):
        assert body["content"][media_type]["schema"] == {
            "type": "string",
        }


def test_structured_json_log_schema(
    schema: dict[str, Any],
) -> None:
    document = schema["paths"][LOGS]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]

    alternatives = document["oneOf"]

    assert len(alternatives) == 5

    entry = alternatives[0]
    array = alternatives[1]

    assert entry["type"] == "object"
    assert entry["required"] == ["message"]
    assert entry["additionalProperties"] is False
    assert set(entry["properties"]) == SUPPORTED_FIELDS

    message = entry["properties"]["message"]

    assert message["type"] == "string"
    assert message["minLength"] == 1

    for name in SUPPORTED_FIELDS - {"message"}:
        assert entry["properties"][name]["type"] == [
            "string",
            "null",
        ]

    assert array["type"] == "array"
    assert array["minItems"] == 1
    assert array["items"] == entry

    wrappers = set()

    for wrapper in alternatives[2:]:
        assert wrapper["type"] == "object"
        assert wrapper["additionalProperties"] is False
        assert len(wrapper["required"]) == 1

        field = wrapper["required"][0]

        assert wrapper["properties"] == {field: array}

        wrappers.add(field)

    assert wrappers == COLLECTION_FIELDS


def test_log_source_format_parameter(
    schema: dict[str, Any],
) -> None:
    parameters = schema["paths"][LOGS]["post"]["parameters"]

    matches = [
        parameter for parameter in parameters if parameter["name"] == "source_format"
    ]

    assert len(matches) == 1

    parameter = matches[0]

    assert parameter["in"] == "query"
    assert parameter["required"] is True
    assert parameter["schema"]["$ref"] == ("#/components/schemas/LogFormat")


def test_log_source_name_header_contract(
    schema: dict[str, Any],
) -> None:
    parameters = schema["paths"][LOGS]["post"]["parameters"]

    matches = [
        parameter
        for parameter in parameters
        if parameter["name"] == "X-Log-Source-Name"
    ]

    assert len(matches) == 1

    header = matches[0]

    assert header["in"] == "header"
    assert header["required"] is False

    limit = Settings.model_fields["log_max_metadata_chars"].default

    description = header["description"]

    assert "printable ASCII" in description
    assert f"defaults to {limit} characters" in description

    assert "Percent-encoded values are not automatically decoded." in description


@pytest.mark.parametrize(
    ("label", "field"),
    [
        ("Payload", "log_max_payload_bytes"),
        ("Entries", "log_max_entries"),
        ("Nesting depth", "log_max_nesting_depth"),
        ("Message and exception fields", "log_max_message_chars"),
        ("Metadata fields", "log_max_metadata_chars"),
    ],
)
def test_documented_log_resource_defaults(
    schema: dict[str, Any],
    label: str,
    field: str,
) -> None:
    value = Settings.model_fields[field].default

    assert isinstance(value, int)

    description = schema["paths"][LOGS]["post"]["description"]

    assert f"{label}: {value:,}" in description

    assert "Deployment configuration may change these limits." in description


def test_documented_ai_resource_limits(
    schema: dict[str, Any],
) -> None:
    description = schema["paths"][ANALYSES]["post"]["description"]

    assert f"Request body: {MAX_AI_REQUEST_BYTES:,} bytes." in description

    assert f"JSON nesting depth: {MAX_AI_JSON_DEPTH}." in description


@pytest.mark.parametrize(
    "restriction",
    [
        "uncompressed UTF-8",
        "application/xml or text/xml",
        "application/json",
        "text/plain",
        "Duplicate singleton headers",
        "conflicting request framing",
        "duplicate keys",
        "Boolean field values",
        "nonempty message",
    ],
)
def test_documented_log_request_restrictions(
    schema: dict[str, Any],
    restriction: str,
) -> None:
    description = schema["paths"][LOGS]["post"]["description"]

    assert restriction in description


@pytest.mark.parametrize(
    "restriction",
    [
        "empty JSON",
        "log_submission_id",
        "same incident",
        "application/json",
        "uncompressed UTF-8",
        "Duplicate JSON keys",
        "unsupported JSON constants",
        "conflicting request framing",
        "Unknown request properties",
        "HTTP 409",
    ],
)
def test_documented_ai_request_restrictions(
    schema: dict[str, Any],
    restriction: str,
) -> None:
    description = schema["paths"][ANALYSES]["post"]["description"]

    assert restriction in description
