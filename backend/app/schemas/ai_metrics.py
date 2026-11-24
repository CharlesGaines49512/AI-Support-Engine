from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


class AIUsageMetrics(BaseModel):
    """Aggregated AI execution and usage statistics."""

    model_config = ConfigDict(frozen=True)

    total_analyses: int = Field(ge=0)
    successful_analyses: int = Field(ge=0)
    failed_analyses: int = Field(ge=0)

    success_rate_percent: float | None = Field(
        ge=0,
        le=100,
    )

    average_latency_ms: float | None = Field(
        ge=0,
        allow_inf_nan=False,
    )

    latency_sample_count: int = Field(ge=0)

    total_input_tokens: int | None = Field(ge=0)
    total_output_tokens: int | None = Field(ge=0)
    total_cached_input_tokens: int | None = Field(ge=0)
    total_tokens: int | None = Field(ge=0)

    input_usage_sample_count: int = Field(ge=0)
    output_usage_sample_count: int = Field(ge=0)
    cached_usage_sample_count: int = Field(ge=0)
    total_usage_sample_count: int = Field(ge=0)

    estimated_cost_usd: Decimal | None = Field(
        ge=0,
        allow_inf_nan=False,
    )

    costed_analyses: int = Field(ge=0)
    uncosted_analyses: int = Field(ge=0)
