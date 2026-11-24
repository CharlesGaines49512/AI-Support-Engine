from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from app.integrations.ai.contracts import AIUsage

TOKENS_PER_MILLION = Decimal("1000000")
COST_PRECISION = Decimal("0.0000000001")
MAX_STORED_COST = Decimal("99999999.9999999999")


@dataclass(frozen=True, slots=True)
class AIModelPricing:
    """USD pricing per one million tokens."""

    input_price: Decimal
    cached_input_price: Decimal
    output_price: Decimal

    def __post_init__(self) -> None:
        prices = (
            self.input_price,
            self.cached_input_price,
            self.output_price,
        )

        if any(not price.is_finite() or price < 0 for price in prices):
            raise ValueError("Token prices must be finite and nonnegative.")

        if self.cached_input_price > self.input_price:
            raise ValueError("Cached input price cannot exceed input price.")


def estimate_ai_cost(
    usage: AIUsage,
    pricing: AIModelPricing | None,
) -> Decimal | None:
    """Estimate API cost using known usage and model pricing."""
    if pricing is None:
        return None

    input_tokens = usage.input_tokens
    output_tokens = usage.output_tokens
    cached_tokens = usage.cached_input_tokens

    if input_tokens is None or output_tokens is None:
        return None

    if cached_tokens is None:
        if input_tokens == 0 or pricing.input_price == pricing.cached_input_price:
            cached_tokens = 0
        else:
            return None

    uncached_tokens = input_tokens - cached_tokens

    input_cost = Decimal(uncached_tokens) * pricing.input_price

    cached_cost = Decimal(cached_tokens) * pricing.cached_input_price

    output_cost = Decimal(output_tokens) * pricing.output_price

    estimated_cost = (input_cost + cached_cost + output_cost) / TOKENS_PER_MILLION

    if estimated_cost > MAX_STORED_COST:
        raise ValueError("Estimated cost exceeds supported storage precision.")

    return estimated_cost.quantize(
        COST_PRECISION,
        rounding=ROUND_HALF_UP,
    )
