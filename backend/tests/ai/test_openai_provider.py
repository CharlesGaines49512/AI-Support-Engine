import asyncio
from collections.abc import Generator
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    PermissionDeniedError,
    RateLimitError,
)
from pydantic import BaseModel, SecretStr

from app.core.config import Settings
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
    OpenAIProvider,
    create_ai_provider,
)


class ExampleResult(BaseModel):
    """Synthetic structured AI response."""

    summary: str


@pytest.fixture
def settings() -> Settings:
    """Return isolated synthetic provider configuration."""
    return Settings(
        _env_file=None,
        ai_enabled=True,
        ai_model="gpt-5.4-mini",
        openai_api_key=SecretStr("synthetic-test-key"),
        ai_request_timeout=30.0,
        ai_max_retries=3,
        ai_max_output_tokens=2000,
        ai_max_input_chars=1000,
    )


@pytest.fixture
def sdk_client() -> Generator[MagicMock]:
    """Replace the SDK client to prevent external network calls."""
    with patch("app.integrations.ai.openai_provider.AsyncOpenAI") as constructor:
        client = constructor.return_value
        client.responses.parse = AsyncMock()
        client.close = AsyncMock()

        yield constructor


@pytest.fixture
def provider(
    settings: Settings,
    sdk_client: MagicMock,
) -> OpenAIProvider:
    """Return a provider backed by the mocked SDK."""
    return OpenAIProvider(settings)


@pytest.fixture
def ai_request() -> AIRequest:
    return AIRequest(
        system_prompt="Analyze the technical support incident.",
        user_prompt="Synthetic database connection failure.",
        prompt_version="1.0.0",
    )


def create_response() -> MagicMock:
    """Construct a successful synthetic SDK response."""
    response = MagicMock()

    response.status = "completed"
    response.model = "gpt-5.4-mini"
    response._request_id = "req_synthetic"
    response.output_parsed = ExampleResult(summary="Database connectivity failure.")
    response.usage = SimpleNamespace(
        input_tokens=100,
        output_tokens=50,
        total_tokens=150,
        input_tokens_details=SimpleNamespace(cached_tokens=20),
    )

    return response


def test_provider_initialization(
    settings: Settings,
    sdk_client: MagicMock,
) -> None:
    provider = OpenAIProvider(settings)

    assert isinstance(provider, AIProvider)

    sdk_client.assert_called_once_with(
        api_key="synthetic-test-key",
        timeout=30.0,
        max_retries=3,
        base_url="https://api.openai.com/v1",
    )


def test_disabled_provider(
    settings: Settings,
    sdk_client: MagicMock,
) -> None:
    settings.ai_enabled = False

    with pytest.raises(AIProviderDisabledError):
        OpenAIProvider(settings)

    sdk_client.assert_not_called()


@pytest.mark.parametrize("api_key", ["", "   "])
def test_missing_credentials(
    settings: Settings,
    sdk_client: MagicMock,
    api_key: str,
) -> None:
    settings.openai_api_key = SecretStr(api_key)

    with pytest.raises(AIProviderConfigurationError):
        OpenAIProvider(settings)

    sdk_client.assert_not_called()


def test_blank_model(
    settings: Settings,
    sdk_client: MagicMock,
) -> None:
    settings.ai_model = "   "

    with pytest.raises(AIProviderConfigurationError):
        OpenAIProvider(settings)

    sdk_client.assert_not_called()


def test_provider_factory(
    settings: Settings,
    sdk_client: MagicMock,
) -> None:
    provider = create_ai_provider(settings)

    assert isinstance(provider, OpenAIProvider)
    sdk_client.assert_called_once()


def test_provider_factory_default_settings(
    settings: Settings,
    sdk_client: MagicMock,
) -> None:
    with patch(
        "app.integrations.ai.factory.get_settings",
        return_value=settings,
    ) as get_settings:
        provider = create_ai_provider()

    assert isinstance(provider, OpenAIProvider)
    get_settings.assert_called_once_with()
    sdk_client.assert_called_once()


def test_successful_structured_response(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    client = sdk_client.return_value
    client.responses.parse.return_value = create_response()

    result = asyncio.run(
        provider.generate_structured(
            ai_request,
            ExampleResult,
        )
    )

    assert isinstance(result.data, ExampleResult)
    assert result.data.summary == "Database connectivity failure."
    assert result.provider == "openai"
    assert result.model == "gpt-5.4-mini"
    assert result.prompt_version == "1.0.0"
    assert result.request_id == "req_synthetic"
    assert result.latency_ms >= 0

    assert result.usage.input_tokens == 100
    assert result.usage.output_tokens == 50
    assert result.usage.total_tokens == 150
    assert result.usage.cached_input_tokens == 20

    client.responses.parse.assert_awaited_once_with(
        model="gpt-5.4-mini",
        instructions=ai_request.system_prompt,
        input=ai_request.user_prompt,
        text_format=ExampleResult,
        max_output_tokens=2000,
        store=False,
    )


def test_missing_usage_metadata(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    response = create_response()
    response.usage = None
    response._request_id = None

    sdk_client.return_value.responses.parse.return_value = response

    result = asyncio.run(
        provider.generate_structured(
            ai_request,
            ExampleResult,
        )
    )

    assert result.usage.input_tokens is None
    assert result.usage.output_tokens is None
    assert result.usage.total_tokens is None
    assert result.request_id is None


@pytest.mark.parametrize(
    "status",
    ["incomplete", "failed", "cancelled", "in_progress"],
)
def test_incomplete_response(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
    status: str,
) -> None:
    response = create_response()
    response.status = status

    sdk_client.return_value.responses.parse.return_value = response

    with pytest.raises(
        AIProviderResponseError,
        match="did not complete",
    ):
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )


def test_missing_structured_output(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    response = create_response()
    response.output_parsed = None

    sdk_client.return_value.responses.parse.return_value = response

    with pytest.raises(
        AIProviderResponseError,
        match="no structured output",
    ):
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )


def test_invalid_structured_output(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    response = create_response()

    response.output_parsed = MagicMock()
    response.output_parsed.model_dump.return_value = {"summary": 123}

    sdk_client.return_value.responses.parse.return_value = response

    with pytest.raises(
        AIProviderResponseError,
        match="invalid structured data",
    ):
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )


def test_invalid_usage_metadata(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    response = create_response()
    response.usage.total_tokens = 999

    sdk_client.return_value.responses.parse.return_value = response

    with pytest.raises(AIProviderResponseError):
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )


def test_oversized_request(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
) -> None:
    request = AIRequest(
        system_prompt="Analyze the incident.",
        user_prompt="x" * 1001,
        prompt_version="1.0.0",
    )

    with pytest.raises(
        AIProviderRequestError,
        match="input limit",
    ):
        asyncio.run(
            provider.generate_structured(
                request,
                ExampleResult,
            )
        )

    sdk_client.return_value.responses.parse.assert_not_awaited()


def test_resource_cleanup(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
) -> None:
    async def execute() -> None:
        await provider.close()
        await provider.close()

    asyncio.run(execute())

    sdk_client.return_value.close.assert_awaited_once()


def test_closed_provider(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    async def execute() -> None:
        await provider.close()

        with pytest.raises(AIProviderUnavailableError):
            await provider.generate_structured(
                ai_request,
                ExampleResult,
            )

    asyncio.run(execute())

    sdk_client.return_value.responses.parse.assert_not_awaited()


@pytest.mark.parametrize(
    ("status_code", "exception_type", "expected_error"),
    [
        (
            401,
            AuthenticationError,
            AIProviderAuthenticationError,
        ),
        (
            403,
            PermissionDeniedError,
            AIProviderAuthenticationError,
        ),
        (
            429,
            RateLimitError,
            AIProviderRateLimitError,
        ),
        (
            500,
            InternalServerError,
            AIProviderUnavailableError,
        ),
        (
            503,
            InternalServerError,
            AIProviderUnavailableError,
        ),
        (
            400,
            BadRequestError,
            AIProviderRequestError,
        ),
    ],
)
def test_http_error_translation(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
    status_code: int,
    exception_type: type[APIStatusError],
    expected_error: type[AIProviderError],
) -> None:
    request = httpx2.Request(
        "POST",
        "https://api.openai.com/v1/responses",
    )

    response = httpx2.Response(
        status_code,
        request=request,
    )

    sdk_error = exception_type(
        "Sensitive synthetic provider error.",
        response=response,
        body=None,
    )

    sdk_client.return_value.responses.parse.side_effect = sdk_error

    with pytest.raises(expected_error) as error:
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )

    assert "Sensitive synthetic" not in str(error.value)


@pytest.mark.parametrize(
    ("exception_type", "expected_error"),
    [
        (APITimeoutError, AIProviderTimeoutError),
        (APIConnectionError, AIProviderUnavailableError),
    ],
)
def test_connection_error_translation(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
    exception_type: type[APIConnectionError],
    expected_error: type[AIProviderError],
) -> None:
    request = httpx2.Request(
        "POST",
        "https://api.openai.com/v1/responses",
    )

    sdk_client.return_value.responses.parse.side_effect = exception_type(
        request=request
    )

    with pytest.raises(expected_error):
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )


def test_unexpected_api_error(
    provider: OpenAIProvider,
    sdk_client: MagicMock,
    ai_request: AIRequest,
) -> None:
    request = httpx2.Request(
        "POST",
        "https://api.openai.com/v1/responses",
    )

    sdk_client.return_value.responses.parse.side_effect = APIError(
        "Sensitive synthetic provider error.",
        request,
        body=None,
    )

    with pytest.raises(AIProviderResponseError) as error:
        asyncio.run(
            provider.generate_structured(
                ai_request,
                ExampleResult,
            )
        )

    assert "Sensitive synthetic" not in str(error.value)
