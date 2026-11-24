from dataclasses import dataclass

from app.integrations.ai.exceptions import (
    AIProviderAuthenticationError,
    AIProviderConfigurationError,
    AIProviderDisabledError,
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderRequestError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)


@dataclass(frozen=True, slots=True)
class AIAnalysisFailure:
    """Safe application-generated AI failure information."""

    code: str
    message: str


def describe_ai_failure(
    error: AIProviderError,
) -> AIAnalysisFailure:
    """Translate provider failures into safe operational metadata."""
    match error:
        case AIProviderDisabledError():
            return AIAnalysisFailure(
                "provider_disabled",
                "AI functionality is disabled.",
            )
        case AIProviderConfigurationError():
            return AIAnalysisFailure(
                "provider_configuration",
                "The AI provider is not correctly configured.",
            )
        case AIProviderAuthenticationError():
            return AIAnalysisFailure(
                "provider_authentication",
                "AI provider authentication failed.",
            )
        case AIProviderRateLimitError():
            return AIAnalysisFailure(
                "provider_rate_limit",
                "AI provider request limits were exceeded.",
            )
        case AIProviderTimeoutError():
            return AIAnalysisFailure(
                "provider_timeout",
                "The AI request timed out.",
            )
        case AIProviderUnavailableError():
            return AIAnalysisFailure(
                "provider_unavailable",
                "The AI provider is temporarily unavailable.",
            )
        case AIProviderRequestError():
            return AIAnalysisFailure(
                "provider_request",
                "The AI provider could not process the request.",
            )
        case AIProviderResponseError():
            return AIAnalysisFailure(
                "provider_response",
                "The AI provider returned an invalid response.",
            )
        case _:
            return AIAnalysisFailure(
                "provider_error",
                "An unexpected AI provider error occurred.",
            )
