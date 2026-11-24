import logging
from decimal import Decimal, DecimalException

from app.core.config import Settings
from app.integrations.ai.contracts import AIUsage
from app.integrations.ai.pricing import (
    AIModelPricing,
    estimate_ai_cost,
)

logger = logging.getLogger(__name__)


def estimate_configured_ai_cost(
    settings: Settings,
    *,
    provider: str,
    model: str,
    usage: AIUsage,
) -> Decimal | None:
    """Estimate cost using explicitly configured model prices."""
    if provider != settings.ai_provider:
        return None

    if model != settings.ai_pricing_model:
        return None

    input_price = settings.ai_pricing_input_usd_per_million
    cached_price = settings.ai_pricing_cached_input_usd_per_million
    output_price = settings.ai_pricing_output_usd_per_million

    if input_price is None or cached_price is None or output_price is None:
        return None

    try:
        pricing = AIModelPricing(
            input_price=input_price,
            cached_input_price=cached_price,
            output_price=output_price,
        )

        return estimate_ai_cost(
            usage,
            pricing,
        )

    except ValueError, DecimalException:
        logger.warning("AI cost could not be estimated using configured pricing.")

        return None
