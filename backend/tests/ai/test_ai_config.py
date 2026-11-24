import os

import pytest
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture(autouse=True)
def isolate_ai_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prevent external configuration from affecting AI tests."""
    ai_fields = {
        "AI_ENABLED",
        "AI_PROVIDER",
        "AI_MODEL",
        "OPENAI_API_KEY",
        "AI_REQUEST_TIMEOUT",
        "AI_MAX_RETRIES",
        "AI_MAX_OUTPUT_TOKENS",
        "AI_MAX_INPUT_CHARS",
    }

    for key in tuple(os.environ):
        if key.upper() in ai_fields:
            monkeypatch.delenv(key, raising=False)


def test_default_ai_configuration() -> None:
    """Verify safe and predictable AI configuration defaults."""
    settings = Settings(_env_file=None)

    assert settings.ai_enabled is False
    assert settings.ai_provider == "openai"
    assert settings.ai_model == "gpt-5.4-mini"
    assert settings.openai_api_key.get_secret_value() == ""
    assert settings.ai_request_timeout == 30.0
    assert settings.ai_max_retries == 3
    assert settings.ai_max_output_tokens == 2000
    assert settings.ai_max_input_chars == 20000


def test_ai_environment_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that AI settings accept environment overrides."""
    overrides = {
        "AI_ENABLED": "true",
        "AI_PROVIDER": "openai",
        "AI_MODEL": "test-model",
        "OPENAI_API_KEY": "synthetic-test-key",
        "AI_REQUEST_TIMEOUT": "45",
        "AI_MAX_RETRIES": "2",
        "AI_MAX_OUTPUT_TOKENS": "1000",
        "AI_MAX_INPUT_CHARS": "10000",
    }

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)

    settings = Settings(_env_file=None)

    assert settings.ai_enabled is True
    assert settings.ai_provider == "openai"
    assert settings.ai_model == "test-model"
    assert settings.openai_api_key.get_secret_value() == "synthetic-test-key"
    assert settings.ai_request_timeout == 45.0
    assert settings.ai_max_retries == 2
    assert settings.ai_max_output_tokens == 1000
    assert settings.ai_max_input_chars == 10000


def test_ai_api_key_is_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that ordinary settings output masks credentials."""
    secret = "synthetic-private-api-key"

    monkeypatch.setenv("OPENAI_API_KEY", secret)

    settings = Settings(_env_file=None)

    assert settings.openai_api_key.get_secret_value() == secret
    assert secret not in str(settings)
    assert secret not in repr(settings)
    assert secret not in settings.model_dump_json()
    assert str(settings.openai_api_key) == "**********"


def test_ai_disabled_without_credentials() -> None:
    """Verify that missing credentials permit application startup."""
    settings = Settings(_env_file=None)

    assert settings.ai_enabled is False
    assert not settings.openai_api_key.get_secret_value()


def test_ai_enabled_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defer missing credential enforcement to the provider."""
    monkeypatch.setenv("AI_ENABLED", "true")

    settings = Settings(_env_file=None)

    assert settings.ai_enabled is True
    assert not settings.openai_api_key.get_secret_value()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AI_ENABLED", "invalid"),
        ("AI_PROVIDER", "unsupported"),
        ("AI_MODEL", ""),
        ("AI_MODEL", "x" * 101),
        ("AI_REQUEST_TIMEOUT", "0"),
        ("AI_REQUEST_TIMEOUT", "-1"),
        ("AI_REQUEST_TIMEOUT", "121"),
        ("AI_MAX_RETRIES", "-1"),
        ("AI_MAX_RETRIES", "6"),
        ("AI_MAX_OUTPUT_TOKENS", "255"),
        ("AI_MAX_OUTPUT_TOKENS", "16001"),
        ("AI_MAX_INPUT_CHARS", "999"),
        ("AI_MAX_INPUT_CHARS", "100001"),
    ],
)
def test_invalid_ai_configuration(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    """Reject unsupported or out-of-range configuration values."""
    monkeypatch.setenv(key, value)

    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None)

    assert any(item["loc"] == (key.lower(),) for item in error.value.errors())


@pytest.mark.parametrize(
    ("retries", "tokens", "characters"),
    [
        (0, 256, 1000),
        (5, 16000, 100000),
    ],
)
def test_ai_configuration_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    retries: int,
    tokens: int,
    characters: int,
) -> None:
    """Accept valid minimum and maximum configuration boundaries."""
    monkeypatch.setenv("AI_MAX_RETRIES", str(retries))
    monkeypatch.setenv("AI_MAX_OUTPUT_TOKENS", str(tokens))
    monkeypatch.setenv("AI_MAX_INPUT_CHARS", str(characters))

    settings = Settings(_env_file=None)

    assert settings.ai_max_retries == retries
    assert settings.ai_max_output_tokens == tokens
    assert settings.ai_max_input_chars == characters
