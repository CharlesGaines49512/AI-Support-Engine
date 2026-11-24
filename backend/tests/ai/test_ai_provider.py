import asyncio

import pytest
from pydantic import BaseModel

from app.integrations.ai import (
    AIProvider,
    AIProviderAuthenticationError,
    AIProviderConfigurationError,
    AIProviderDisabledError,
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    AIRequest,
    AIResponse,
    AIUsage,
)


class ExampleResult(BaseModel):
    """Synthetic AI analysis result."""

    summary: str


class MockAIProvider:
    """Deterministic provider used for interface testing."""

    def __init__(self) -> None:
        self.closed = False
        self.request_count = 0

    async def generate_structured[T: BaseModel](
        self,
        request: AIRequest,
        response_schema: type[T],
    ) -> AIResponse[T]:
        if self.closed:
            raise AIProviderUnavailableError("Provider has been closed.")

        self.request_count += 1

        data = response_schema.model_validate(
            {"summary": "Synthetic incident analysis."}
        )

        return AIResponse[T](
            data=data,
            provider="openai",
            model="synthetic-model",
            prompt_version=request.prompt_version,
            usage=AIUsage(
                input_tokens=100,
                output_tokens=20,
                total_tokens=120,
            ),
            latency_ms=1.0,
        )

    async def close(self) -> None:
        self.closed = True


def create_request() -> AIRequest:
    return AIRequest(
        system_prompt="Analyze the incident.",
        user_prompt="Synthetic database failure.",
        prompt_version="1.0.0",
    )


def test_provider_protocol_compatibility() -> None:
    provider: AIProvider = MockAIProvider()

    assert isinstance(provider, AIProvider)


def test_invalid_provider_protocol() -> None:
    assert not isinstance(object(), AIProvider)


def test_structured_generation() -> None:
    provider = MockAIProvider()

    result = asyncio.run(
        provider.generate_structured(
            create_request(),
            ExampleResult,
        )
    )

    assert isinstance(result.data, ExampleResult)
    assert result.data.summary == "Synthetic incident analysis."
    assert result.prompt_version == "1.0.0"
    assert result.usage.total_tokens == 120
    assert provider.request_count == 1


def test_provider_resource_cleanup() -> None:
    provider = MockAIProvider()

    asyncio.run(provider.close())

    assert provider.closed is True


def test_closed_provider_rejects_requests() -> None:
    provider = MockAIProvider()

    asyncio.run(provider.close())

    with pytest.raises(AIProviderUnavailableError):
        asyncio.run(
            provider.generate_structured(
                create_request(),
                ExampleResult,
            )
        )

    assert provider.request_count == 0


@pytest.mark.parametrize(
    "exception_type",
    [
        AIProviderAuthenticationError,
        AIProviderConfigurationError,
        AIProviderDisabledError,
        AIProviderRateLimitError,
        AIProviderRequestError,
        AIProviderResponseError,
        AIProviderTimeoutError,
        AIProviderUnavailableError,
    ],
)
def test_provider_exception_hierarchy(
    exception_type: type[AIProviderError],
) -> None:
    error = exception_type("Synthetic provider failure.")

    assert isinstance(error, AIProviderError)
    assert str(error) == "Synthetic provider failure."

    with pytest.raises(AIProviderError):
        raise error
