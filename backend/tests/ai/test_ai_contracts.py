from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from app.integrations.ai import AIRequest, AIResponse, AIUsage


class ExampleResult(BaseModel):
    """Synthetic structured AI output."""

    summary: str


def request_payload() -> dict[str, Any]:
    """Return a valid synthetic request."""
    return {
        "system_prompt": "Analyze this incident.",
        "user_prompt": "Database connection failed.",
        "prompt_version": "1.0.0",
    }


def response_payload() -> dict[str, Any]:
    """Return a valid synthetic response."""
    return {
        "data": {"summary": "Database connectivity failure."},
        "provider": "openai",
        "model": "gpt-5.4-mini",
        "prompt_version": "1.0.0",
        "request_id": "synthetic-request",
        "latency_ms": 250.0,
    }


def test_valid_ai_request() -> None:
    request = AIRequest.model_validate(request_payload())

    assert request.system_prompt == "Analyze this incident."
    assert request.user_prompt == "Database connection failed."
    assert request.prompt_version == "1.0.0"


def test_request_strips_whitespace() -> None:
    request = AIRequest(
        system_prompt="  System instructions  ",
        user_prompt="  Incident details  ",
        prompt_version="  1.0.0  ",
    )

    assert request.system_prompt == "System instructions"
    assert request.user_prompt == "Incident details"
    assert request.prompt_version == "1.0.0"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("system_prompt", ""),
        ("system_prompt", "   "),
        ("system_prompt", "x" * 30001),
        ("user_prompt", ""),
        ("user_prompt", "   "),
        ("user_prompt", "x" * 100001),
        ("prompt_version", ""),
        ("prompt_version", "   "),
        ("prompt_version", "x" * 51),
        ("unexpected_field", "invalid"),
    ],
)
def test_invalid_ai_request(
    field: str,
    value: str,
) -> None:
    payload = request_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        AIRequest.model_validate(payload)


def test_request_is_frozen() -> None:
    request = AIRequest.model_validate(request_payload())

    with pytest.raises(ValidationError):
        request.user_prompt = "Modified"  # type: ignore[misc]


def test_unknown_usage() -> None:
    usage = AIUsage()

    assert usage.input_tokens is None
    assert usage.output_tokens is None
    assert usage.total_tokens is None
    assert usage.cached_input_tokens is None


def test_complete_usage() -> None:
    usage = AIUsage(
        input_tokens=100,
        output_tokens=50,
        total_tokens=150,
        cached_input_tokens=20,
    )

    assert usage.input_tokens == 100
    assert usage.output_tokens == 50
    assert usage.total_tokens == 150
    assert usage.cached_input_tokens == 20


def test_partial_usage() -> None:
    usage = AIUsage(input_tokens=100)

    assert usage.input_tokens == 100
    assert usage.output_tokens is None
    assert usage.total_tokens is None


def test_zero_usage() -> None:
    usage = AIUsage(
        input_tokens=0,
        output_tokens=0,
        total_tokens=0,
        cached_input_tokens=0,
    )

    assert usage.total_tokens == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"input_tokens": -1},
        {"output_tokens": -1},
        {"total_tokens": -1},
        {"cached_input_tokens": -1},
        {
            "input_tokens": 100,
            "cached_input_tokens": 101,
        },
        {
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 149,
        },
        {
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 151,
        },
        {"unexpected_field": 10},
    ],
)
def test_invalid_usage(
    payload: dict[str, int],
) -> None:
    with pytest.raises(ValidationError):
        AIUsage.model_validate(payload)


def test_usage_is_frozen() -> None:
    usage = AIUsage(input_tokens=100)

    with pytest.raises(ValidationError):
        usage.input_tokens = 200  # type: ignore[misc]


def test_valid_structured_response() -> None:
    response = AIResponse[ExampleResult].model_validate(response_payload())

    assert isinstance(response.data, ExampleResult)
    assert response.data.summary == "Database connectivity failure."
    assert response.provider == "openai"
    assert response.model == "gpt-5.4-mini"
    assert response.prompt_version == "1.0.0"
    assert response.request_id == "synthetic-request"
    assert response.latency_ms == 250.0
    assert response.usage.total_tokens is None


def test_response_serialization() -> None:
    response = AIResponse[ExampleResult].model_validate(response_payload())

    serialized = response.model_dump_json()

    restored = AIResponse[ExampleResult].model_validate_json(serialized)

    assert restored == response


def test_response_optional_metadata() -> None:
    payload = response_payload()
    del payload["request_id"]

    response = AIResponse[ExampleResult].model_validate(payload)

    assert response.request_id is None
    assert response.usage.input_tokens is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "unsupported"),
        ("model", ""),
        ("model", "   "),
        ("model", "x" * 101),
        ("prompt_version", ""),
        ("prompt_version", "   "),
        ("prompt_version", "x" * 51),
        ("request_id", ""),
        ("request_id", "   "),
        ("request_id", "x" * 256),
        ("latency_ms", -1),
        ("latency_ms", float("inf")),
        ("latency_ms", float("-inf")),
        ("latency_ms", float("nan")),
        ("data", {}),
        ("data", {"summary": 123}),
        ("unexpected_field", "invalid"),
    ],
)
def test_invalid_response(
    field: str,
    value: Any,
) -> None:
    payload = response_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        AIResponse[ExampleResult].model_validate(payload)


def test_response_is_frozen() -> None:
    response = AIResponse[ExampleResult].model_validate(response_payload())

    with pytest.raises(ValidationError):
        response.model = "modified"  # type: ignore[misc]
