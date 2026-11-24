from app.core.config import Settings, get_settings
from app.integrations.ai.openai_provider import OpenAIProvider
from app.integrations.ai.provider import AIProvider


def create_ai_provider(
    settings: Settings | None = None,
) -> AIProvider:
    """Create the configured AI provider."""
    configuration = settings if settings is not None else get_settings()

    return OpenAIProvider(configuration)
