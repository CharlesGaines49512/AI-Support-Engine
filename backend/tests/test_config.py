import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove environment overrides for predictable tests."""
    for field_name in Settings.model_fields:
        monkeypatch.delenv(field_name.upper(), raising=False)
        monkeypatch.delenv(field_name.lower(), raising=False)


def test_default_settings() -> None:
    """Verify default application configuration."""
    settings = Settings(_env_file=None)

    assert settings.app_name == "AI Support Engine"
    assert settings.app_version == "0.1.0"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.log_level == "INFO"
    assert settings.request_timeout == 30.0
    assert settings.max_retries == 3


def test_environment_variable_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify environment variables override default settings."""
    monkeypatch.setenv("APP_NAME", "Test Support Engine")
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("MAX_RETRIES", "5")

    settings = Settings(_env_file=None)

    assert settings.app_name == "Test Support Engine"
    assert settings.environment == "testing"
    assert settings.debug is True
    assert settings.max_retries == 5


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("ENVIRONMENT", "invalid"),
        ("LOG_LEVEL", "invalid"),
        ("REQUEST_TIMEOUT", "0"),
        ("REQUEST_TIMEOUT", "-10"),
        ("MAX_RETRIES", "-1"),
        ("MAX_RETRIES", "6"),
        ("DEBUG", "invalid"),
    ],
)
def test_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
    value: str,
) -> None:
    """Verify invalid configuration values are rejected."""
    monkeypatch.setenv(variable, value)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_are_cached() -> None:
    """Verify repeated calls reuse the settings instance."""
    assert get_settings() is get_settings()
