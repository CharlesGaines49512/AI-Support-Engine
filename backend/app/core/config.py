from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    ai_pricing_model: str | None = None
    ai_pricing_input_usd_per_million: Decimal | None = None
    ai_pricing_cached_input_usd_per_million: Decimal | None = None
    ai_pricing_output_usd_per_million: Decimal | None = None

    """Centralized application configuration."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    app_name: str = "AI Support Engine"
    app_version: str = "0.1.0"
    environment: Literal["development", "testing", "production"] = "development"
    debug: bool = False

    # API settings
    api_v1_prefix: str = "/api/v1"

    # Logging settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # External service settings
    request_timeout: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0, le=5)

    # AI configuration
    ai_enabled: bool = False
    ai_provider: Literal["openai"] = "openai"
    ai_model: str = Field(
        default="gpt-5.4-mini",
        min_length=1,
        max_length=100,
    )
    openai_api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    ai_request_timeout: float = Field(
        default=30.0,
        gt=0,
        le=120,
    )
    ai_max_retries: int = Field(default=3, ge=0, le=5)
    ai_max_output_tokens: int = Field(
        default=2000,
        ge=256,
        le=16000,
    )
    ai_max_input_chars: int = Field(
        default=20000,
        ge=1000,
        le=100000,
    )

    # Database configuration
    postgres_db: str = "ai_support_engine"
    postgres_user: str = "ai_support_user"
    postgres_password: SecretStr = Field(default_factory=lambda: SecretStr(""))
    postgres_host: str = "localhost"
    postgres_port: int = Field(
        default=5432,
        ge=1,
        le=65535,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached application settings instance."""
    return Settings()
