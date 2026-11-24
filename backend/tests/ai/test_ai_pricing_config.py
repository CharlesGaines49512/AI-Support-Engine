from decimal import Decimal

import pytest

from app.core.config import Settings
from app.integrations.ai.contracts import AIUsage
from app.integrations.ai.pricing_config import (
    estimate_configured_ai_cost,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        ai_pricing_model="synthetic-model",
        ai_pricing_input_usd_per_million=Decimal("2"),
        ai_pricing_cached_input_usd_per_million=Decimal("0.5"),
        ai_pricing_output_usd_per_million=Decimal("8"),
    )


@pytest.fixture
def usage() -> AIUsage:
    return AIUsage(
        input_tokens=1000,
        cached_input_tokens=400,
        output_tokens=500,
        total_tokens=1500,
    )


def test_matching_model_pricing(
    settings: Settings,
    usage: AIUsage,
) -> None:
    result = estimate_configured_ai_cost(
        settings,
        provider="openai",
        model="synthetic-model",
        usage=usage,
    )

    assert result == Decimal("0.0054000000")


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("unknown-provider", "synthetic-model"),
        ("openai", "unknown-model"),
    ],
)
def test_unmatched_pricing(
    settings: Settings,
    usage: AIUsage,
    provider: str,
    model: str,
) -> None:
    assert (
        estimate_configured_ai_cost(
            settings,
            provider=provider,
            model=model,
            usage=usage,
        )
        is None
    )


@pytest.mark.parametrize(
    "field",
    [
        "ai_pricing_model",
        "ai_pricing_input_usd_per_million",
        "ai_pricing_cached_input_usd_per_million",
        "ai_pricing_output_usd_per_million",
    ],
)
def test_incomplete_pricing(
    settings: Settings,
    usage: AIUsage,
    field: str,
) -> None:
    incomplete = settings.model_copy(update={field: None})

    assert (
        estimate_configured_ai_cost(
            incomplete,
            provider="openai",
            model="synthetic-model",
            usage=usage,
        )
        is None
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "ai_pricing_input_usd_per_million",
            Decimal("-1"),
        ),
        (
            "ai_pricing_cached_input_usd_per_million",
            Decimal("10"),
        ),
    ],
)
def test_invalid_pricing(
    settings: Settings,
    usage: AIUsage,
    field: str,
    value: Decimal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    invalid = settings.model_copy(update={field: value})

    assert (
        estimate_configured_ai_cost(
            invalid,
            provider="openai",
            model="synthetic-model",
            usage=usage,
        )
        is None
    )

    assert "AI cost could not be estimated" in caplog.text


def test_missing_usage(
    settings: Settings,
) -> None:
    assert (
        estimate_configured_ai_cost(
            settings,
            provider="openai",
            model="synthetic-model",
            usage=AIUsage(),
        )
        is None
    )


def test_cost_overflow(
    settings: Settings,
) -> None:
    expensive = settings.model_copy(
        update={
            "ai_pricing_input_usd_per_million": Decimal("1000000000"),
        }
    )

    usage = AIUsage(
        input_tokens=1000000,
        cached_input_tokens=0,
        output_tokens=0,
    )

    assert (
        estimate_configured_ai_cost(
            expensive,
            provider="openai",
            model="synthetic-model",
            usage=usage,
        )
        is None
    )
