from decimal import Decimal

import pytest

from app.integrations.ai.contracts import AIUsage
from app.integrations.ai.pricing import (
    AIModelPricing,
    estimate_ai_cost,
)


@pytest.fixture
def pricing() -> AIModelPricing:
    return AIModelPricing(
        input_price=Decimal("2.00"),
        cached_input_price=Decimal("0.50"),
        output_price=Decimal("8.00"),
    )


def test_cost_without_cached_tokens(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
        cached_input_tokens=0,
        total_tokens=1500,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0060000000")


def test_cost_with_cached_tokens(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
        cached_input_tokens=400,
        total_tokens=1500,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0054000000")


def test_all_input_tokens_cached(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=0,
        cached_input_tokens=1000,
        total_tokens=1000,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0005000000")


def test_zero_token_usage(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        total_tokens=0,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0000000000")


def test_unknown_pricing() -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
        cached_input_tokens=0,
    )

    assert estimate_ai_cost(usage, None) is None


def test_unknown_usage(
    pricing: AIModelPricing,
) -> None:
    assert (
        estimate_ai_cost(
            AIUsage(),
            pricing,
        )
        is None
    )


def test_missing_input_usage(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(output_tokens=500)

    assert estimate_ai_cost(usage, pricing) is None


def test_missing_output_usage(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(input_tokens=1000)

    assert estimate_ai_cost(usage, pricing) is None


def test_unknown_cached_usage(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
    )

    assert estimate_ai_cost(usage, pricing) is None


def test_unknown_cache_with_equal_prices() -> None:
    pricing = AIModelPricing(
        input_price=Decimal("2"),
        cached_input_price=Decimal("2"),
        output_price=Decimal("8"),
    )

    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0060000000")


def test_unknown_cache_with_zero_input(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=0,
        output_tokens=500,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0040000000")


def test_total_token_count_not_required(
    pricing: AIModelPricing,
) -> None:
    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
        cached_input_tokens=0,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0060000000")


def test_zero_pricing() -> None:
    pricing = AIModelPricing(
        input_price=Decimal("0"),
        cached_input_price=Decimal("0"),
        output_price=Decimal("0"),
    )

    usage = AIUsage(
        input_tokens=1000,
        output_tokens=500,
        cached_input_tokens=100,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0000000000")


def test_cost_precision() -> None:
    pricing = AIModelPricing(
        input_price=Decimal("0.123456"),
        cached_input_price=Decimal("0.01"),
        output_price=Decimal("1.23456"),
    )

    usage = AIUsage(
        input_tokens=1,
        output_tokens=1,
        cached_input_tokens=0,
    )

    result = estimate_ai_cost(usage, pricing)

    assert result == Decimal("0.0000013580")
    assert result is not None
    assert result.as_tuple().exponent == -10


def test_cost_rounding() -> None:
    pricing = AIModelPricing(
        input_price=Decimal("0.00005"),
        cached_input_price=Decimal("0"),
        output_price=Decimal("0"),
    )

    usage = AIUsage(
        input_tokens=1,
        output_tokens=0,
        cached_input_tokens=0,
    )

    assert estimate_ai_cost(
        usage,
        pricing,
    ) == Decimal("0.0000000001")


@pytest.mark.parametrize(
    "invalid_price",
    [
        Decimal("-1"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
    ],
)
@pytest.mark.parametrize(
    "field",
    [
        "input_price",
        "cached_input_price",
        "output_price",
    ],
)
def test_invalid_pricing(
    invalid_price: Decimal,
    field: str,
) -> None:
    values = {
        "input_price": Decimal("2"),
        "cached_input_price": Decimal("0.5"),
        "output_price": Decimal("8"),
    }

    values[field] = invalid_price

    with pytest.raises(
        ValueError,
        match="finite and nonnegative",
    ):
        AIModelPricing(**values)


def test_cached_price_cannot_exceed_input_price() -> None:
    with pytest.raises(
        ValueError,
        match="cannot exceed input price",
    ):
        AIModelPricing(
            input_price=Decimal("1"),
            cached_input_price=Decimal("2"),
            output_price=Decimal("8"),
        )


def test_cost_storage_overflow() -> None:
    pricing = AIModelPricing(
        input_price=Decimal("1000000000"),
        cached_input_price=Decimal("0"),
        output_price=Decimal("0"),
    )

    usage = AIUsage(
        input_tokens=1000000,
        output_tokens=0,
        cached_input_tokens=0,
    )

    with pytest.raises(
        ValueError,
        match="storage precision",
    ):
        estimate_ai_cost(usage, pricing)
