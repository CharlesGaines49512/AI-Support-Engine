class AIProviderError(Exception):
    """Base exception for AI provider failures."""


class AIProviderDisabledError(AIProviderError):
    """Raised when AI functionality is disabled."""


class AIProviderConfigurationError(AIProviderError):
    """Raised when provider configuration is invalid."""


class AIProviderAuthenticationError(AIProviderError):
    """Raised when provider authentication fails."""


class AIProviderTimeoutError(AIProviderError):
    """Raised when an external AI request times out."""


class AIProviderRateLimitError(AIProviderError):
    """Raised when the provider enforces a rate limit."""


class AIProviderUnavailableError(AIProviderError):
    """Raised when an AI provider is temporarily unavailable."""


class AIProviderResponseError(AIProviderError):
    """Raised when the provider returns an invalid response."""


class AIProviderRequestError(AIProviderError):
    """Raised when the provider rejects an AI request."""
