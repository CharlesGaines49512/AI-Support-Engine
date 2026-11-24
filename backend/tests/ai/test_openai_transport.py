import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from openai import AsyncOpenAI
from pydantic import SecretStr

from app.core.config import Settings
from app.integrations.ai.contracts import AIRequest
from app.integrations.ai.exceptions import (
    AIProviderAuthenticationError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)
from app.integrations.ai.openai_provider import OpenAIProvider
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)


@pytest.fixture
def request_data() -> AIRequest:
    return AIRequest(
        system_prompt="Analyze synthetic technical incidents.",
        user_prompt="The production database is unavailable.",
        prompt_version="1.0.0",
    )


def success_payload() -> dict[str, Any]:
    analysis = {
        "suggested_category": "database",
        "recommended_priority": "critical",
        "recommended_severity": "critical",
        "summary": "Production database outage.",
        "justification": "Production database is unavailable.",
        "confidence": 0.95,
        "insufficient_evidence": False,
        "missing_information": [],
    }

    return {
        "id": "resp_synthetic_transport",
        "object": "response",
        "created_at": 1700000000,
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "model": "synthetic-model",
        "output": [
            {
                "id": "msg_synthetic_transport",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [
                    {
                        "type": "output_text",
                        "text": json.dumps(analysis),
                        "annotations": [],
                        "logprobs": [],
                    }
                ],
            }
        ],
        "parallel_tool_calls": False,
        "temperature": 1.0,
        "tool_choice": "auto",
        "tools": [],
        "top_p": 1.0,
        "background": False,
        "max_output_tokens": 2000,
        "metadata": {},
        "previous_response_id": None,
        "reasoning": None,
        "store": False,
        "text": {
            "format": {
                "type": "text",
            },
        },
        "truncation": "disabled",
        "usage": {
            "input_tokens": 1000,
            "input_tokens_details": {
                "cached_tokens": 400,
            },
            "output_tokens": 500,
            "output_tokens_details": {
                "reasoning_tokens": 0,
            },
            "total_tokens": 1500,
        },
    }


def create_provider(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[
        [httpx2.Request],
        httpx2.Response,
    ],
    *,
    retries: int = 0,
) -> OpenAIProvider:
    transport = httpx2.MockTransport(handler)

    http_client = httpx2.AsyncClient(
        transport=transport,
    )

    def client_factory(
        **kwargs: Any,
    ) -> AsyncOpenAI:
        return AsyncOpenAI(
            **kwargs,
            http_client=http_client,
        )

    monkeypatch.setattr(
        "app.integrations.ai.openai_provider.AsyncOpenAI",
        client_factory,
    )

    settings = Settings(
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("sk-synthetic-transport-key"),
        ai_max_retries=retries,
        ai_max_output_tokens=2000,
    )

    return OpenAIProvider(settings)


def test_real_sdk_structured_response(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        requests.append(request)

        return httpx2.Response(
            200,
            json=success_payload(),
            headers={
                "x-request-id": "req_synthetic_transport",
            },
        )

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            response = await provider.generate_structured(
                request_data,
                IncidentAnalysisResult,
            )

            assert isinstance(
                response.data,
                IncidentAnalysisResult,
            )

            assert response.data.suggested_category == (IncidentCategory.DATABASE)

            assert response.data.recommended_severity == (IncidentSeverity.CRITICAL)

            assert response.provider == "openai"
            assert response.model == "synthetic-model"
            assert response.prompt_version == "1.0.0"

            assert response.request_id == ("req_synthetic_transport")

            assert response.usage.input_tokens == 1000
            assert response.usage.output_tokens == 500
            assert response.usage.cached_input_tokens == 400
            assert response.usage.total_tokens == 1500
            assert response.latency_ms >= 0

        finally:
            await provider.close()

    asyncio.run(execute())

    assert len(requests) == 1

    request = requests[0]

    assert request.method == "POST"
    assert request.url.host == "api.openai.com"
    assert request.url.path == "/v1/responses"

    assert request.headers["authorization"] == ("Bearer sk-synthetic-transport-key")

    body = json.loads(request.content)

    assert body["model"] == "synthetic-model"
    assert body["instructions"] == request_data.system_prompt
    assert body["input"] == request_data.user_prompt
    assert body["max_output_tokens"] == 2000
    assert body["store"] is False

    output_format = body["text"]["format"]

    assert output_format["type"] == "json_schema"
    assert output_format["strict"] is True

    schema = output_format["schema"]

    assert schema["additionalProperties"] is False

    assert {
        "suggested_category",
        "recommended_priority",
        "recommended_severity",
        "summary",
        "justification",
        "confidence",
        "insufficient_evidence",
        "missing_information",
    }.issubset(schema["required"])


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [
        (400, AIProviderRequestError),
        (401, AIProviderAuthenticationError),
        (403, AIProviderAuthenticationError),
        (429, AIProviderRateLimitError),
        (500, AIProviderUnavailableError),
        (503, AIProviderUnavailableError),
    ],
)
def test_real_sdk_http_error_mapping(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
    status_code: int,
    expected_error: type[Exception],
) -> None:
    requests: list[httpx2.Request] = []

    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        requests.append(request)

        return httpx2.Response(
            status_code,
            json={
                "error": {
                    "message": "SYNTHETIC_PRIVATE_ERROR",
                    "type": "synthetic_error",
                    "code": "synthetic_error",
                    "param": None,
                }
            },
        )

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            with pytest.raises(expected_error) as caught:
                await provider.generate_structured(
                    request_data,
                    IncidentAnalysisResult,
                )

            assert "SYNTHETIC_PRIVATE_ERROR" not in str(caught.value)

        finally:
            await provider.close()

    asyncio.run(execute())

    assert len(requests) == 1


@pytest.mark.parametrize(
    ("transport_error", "expected_error"),
    [
        (
            httpx2.ReadTimeout,
            AIProviderTimeoutError,
        ),
        (
            httpx2.ConnectError,
            AIProviderUnavailableError,
        ),
    ],
)
def test_real_sdk_transport_error_mapping(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
    transport_error: type[Exception],
    expected_error: type[Exception],
) -> None:
    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        raise transport_error("Synthetic transport failure.")

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            with pytest.raises(expected_error):
                await provider.generate_structured(
                    request_data,
                    IncidentAnalysisResult,
                )
        finally:
            await provider.close()

    asyncio.run(execute())


@pytest.mark.parametrize(
    "invalid_output",
    [
        "not valid JSON",
        '{"suggested_category": "invalid"}',
    ],
)
def test_real_sdk_invalid_structured_output(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
    invalid_output: str,
) -> None:
    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        payload = success_payload()

        payload["output"][0]["content"][0]["text"] = invalid_output

        return httpx2.Response(
            200,
            json=payload,
        )

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            with pytest.raises(AIProviderResponseError):
                await provider.generate_structured(
                    request_data,
                    IncidentAnalysisResult,
                )
        finally:
            await provider.close()

    asyncio.run(execute())


def test_real_sdk_refusal(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
) -> None:
    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        payload = success_payload()

        payload["output"][0]["content"] = [
            {
                "type": "refusal",
                "refusal": "Synthetic refusal.",
            }
        ]

        return httpx2.Response(
            200,
            json=payload,
        )

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            with pytest.raises(AIProviderResponseError):
                await provider.generate_structured(
                    request_data,
                    IncidentAnalysisResult,
                )
        finally:
            await provider.close()

    asyncio.run(execute())


def test_real_sdk_retry_recovers(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        requests.append(request)

        if len(requests) == 1:
            return httpx2.Response(
                503,
                json={
                    "error": {
                        "message": "Synthetic unavailable error.",
                        "type": "server_error",
                    }
                },
                headers={
                    "retry-after": "0.01",
                },
            )

        return httpx2.Response(
            200,
            json=success_payload(),
        )

    provider = create_provider(
        monkeypatch,
        handler,
        retries=1,
    )

    async def execute() -> None:
        try:
            result = await provider.generate_structured(
                request_data,
                IncidentAnalysisResult,
            )

            assert result.data.suggested_category == (IncidentCategory.DATABASE)

        finally:
            await provider.close()

    asyncio.run(execute())

    assert len(requests) == 2


def test_real_sdk_retry_limit(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
) -> None:
    requests: list[httpx2.Request] = []

    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        requests.append(request)

        return httpx2.Response(
            503,
            json={
                "error": {
                    "message": "Synthetic unavailable error.",
                    "type": "server_error",
                }
            },
            headers={
                "retry-after": "0.01",
            },
        )

    provider = create_provider(
        monkeypatch,
        handler,
        retries=1,
    )

    async def execute() -> None:
        try:
            with pytest.raises(AIProviderUnavailableError):
                await provider.generate_structured(
                    request_data,
                    IncidentAnalysisResult,
                )
        finally:
            await provider.close()

    asyncio.run(execute())

    assert len(requests) == 2


def test_real_sdk_missing_usage(
    monkeypatch: pytest.MonkeyPatch,
    request_data: AIRequest,
) -> None:
    def handler(
        request: httpx2.Request,
    ) -> httpx2.Response:
        payload = success_payload()
        payload["usage"] = None

        return httpx2.Response(
            200,
            json=payload,
        )

    provider = create_provider(
        monkeypatch,
        handler,
    )

    async def execute() -> None:
        try:
            result = await provider.generate_structured(
                request_data,
                IncidentAnalysisResult,
            )

            assert result.usage.input_tokens is None
            assert result.usage.output_tokens is None
            assert result.usage.total_tokens is None
            assert result.usage.cached_input_tokens is None

        finally:
            await provider.close()

    asyncio.run(execute())
