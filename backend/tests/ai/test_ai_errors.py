import pytest

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
from app.services.ai_errors import (
    AIAnalysisFailure,
    describe_ai_failure,
)


@pytest.mark.parametrize(
    ("exception_type", "expected_code"),
    [
        (
            AIProviderDisabledError,
            "provider_disabled",
        ),
        (
            AIProviderConfigurationError,
            "provider_configuration",
        ),
        (
            AIProviderAuthenticationError,
            "provider_authentication",
        ),
        (
            AIProviderRateLimitError,
            "provider_rate_limit",
        ),
        (
            AIProviderTimeoutError,
            "provider_timeout",
        ),
        (
            AIProviderUnavailableError,
            "provider_unavailable",
        ),
        (
            AIProviderRequestError,
            "provider_request",
        ),
        (
            AIProviderResponseError,
            "provider_response",
        ),
        (
            AIProviderError,
            "provider_error",
        ),
    ],
)
def test_failure_mapping(
    exception_type: type[AIProviderError],
    expected_code: str,
) -> None:
    error = exception_type("Synthetic sensitive provider information.")

    result = describe_ai_failure(error)

    assert isinstance(result, AIAnalysisFailure)
    assert result.code == expected_code
    assert result.message
    assert str(error) not in result.message


def test_failure_does_not_expose_credentials() -> None:
    error = AIProviderAuthenticationError("password=synthetic-password")

    result = describe_ai_failure(error)

    assert "synthetic-password" not in result.message


def test_failure_mapping_is_deterministic() -> None:
    first = describe_ai_failure(AIProviderTimeoutError("First synthetic error"))

    second = describe_ai_failure(AIProviderTimeoutError("Second synthetic error"))

    assert first == second
