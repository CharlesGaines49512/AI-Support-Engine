from time import perf_counter

from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    PermissionDeniedError,
    RateLimitError,
)
from pydantic import BaseModel, ValidationError

from app.core.config import Settings
from app.integrations.ai.contracts import (
    AIRequest,
    AIResponse,
    AIUsage,
)
from app.integrations.ai.exceptions import (
    AIProviderAuthenticationError,
    AIProviderConfigurationError,
    AIProviderDisabledError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)


class OpenAIProvider:
    """Asynchronous OpenAI structured response provider."""

    def __init__(self, settings: Settings) -> None:
        if not settings.ai_enabled:
            raise AIProviderDisabledError("AI functionality is disabled.")

        api_key = settings.openai_api_key.get_secret_value().strip()
        model = settings.ai_model.strip()

        if not api_key:
            raise AIProviderConfigurationError(
                "OpenAI API credentials are not configured."
            )

        if not model:
            raise AIProviderConfigurationError("An OpenAI model must be configured.")

        self._model = model
        self._max_output_tokens = settings.ai_max_output_tokens
        self._max_input_chars = settings.ai_max_input_chars
        self._closed = False

        self._client = AsyncOpenAI(
            api_key=api_key,
            timeout=settings.ai_request_timeout,
            max_retries=settings.ai_max_retries,
            base_url="https://api.openai.com/v1",
        )

    async def generate_structured[T: BaseModel](
        self,
        request: AIRequest,
        response_schema: type[T],
    ) -> AIResponse[T]:
        """Generate validated structured output using OpenAI."""
        if self._closed:
            raise AIProviderUnavailableError("The AI provider has been closed.")

        input_length = len(request.system_prompt) + len(request.user_prompt)

        if input_length > self._max_input_chars:
            raise AIProviderRequestError(
                "AI request exceeds the configured input limit."
            )

        started_at = perf_counter()

        try:
            response = await self._client.responses.parse(
                model=self._model,
                instructions=request.system_prompt,
                input=request.user_prompt,
                text_format=response_schema,
                max_output_tokens=self._max_output_tokens,
                store=False,
            )

            latency_ms = (perf_counter() - started_at) * 1000

            if response.status != "completed":
                raise AIProviderResponseError(
                    "The AI provider did not complete the response."
                )

            parsed = response.output_parsed

            if parsed is None:
                raise AIProviderResponseError(
                    "The AI provider returned no structured output."
                )

            validated = response_schema.model_validate(parsed.model_dump())

            usage = AIUsage()

            if response.usage is not None:
                usage = AIUsage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    total_tokens=response.usage.total_tokens,
                    cached_input_tokens=(
                        response.usage.input_tokens_details.cached_tokens
                    ),
                )

            return AIResponse[T](
                data=validated,
                provider="openai",
                model=response.model,
                prompt_version=request.prompt_version,
                request_id=response._request_id,
                usage=usage,
                latency_ms=latency_ms,
            )

        except AuthenticationError, PermissionDeniedError:
            raise AIProviderAuthenticationError(
                "OpenAI authentication or authorization failed."
            ) from None

        except RateLimitError:
            raise AIProviderRateLimitError(
                "OpenAI request limits have been exceeded."
            ) from None

        except APITimeoutError:
            raise AIProviderTimeoutError("The OpenAI request timed out.") from None

        except APIConnectionError:
            raise AIProviderUnavailableError(
                "Unable to connect to the OpenAI service."
            ) from None

        except APIStatusError as error:
            if error.status_code >= 500:
                raise AIProviderUnavailableError(
                    "The OpenAI service is temporarily unavailable."
                ) from None

            raise AIProviderRequestError("OpenAI rejected the request.") from None

        except ValidationError:
            raise AIProviderResponseError(
                "OpenAI returned invalid structured data."
            ) from None

        except APIError:
            raise AIProviderResponseError(
                "An unexpected OpenAI API error occurred."
            ) from None

    async def close(self) -> None:
        """Release resources owned by the OpenAI client."""
        if not self._closed:
            await self._client.close()
            self._closed = True
