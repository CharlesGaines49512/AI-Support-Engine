from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


class AIRequest(BaseModel):
    """Provider-independent request for structured AI processing."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    system_prompt: str = Field(
        min_length=1,
        max_length=30000,
    )
    user_prompt: str = Field(
        min_length=1,
        max_length=100000,
    )
    prompt_version: str = Field(
        min_length=1,
        max_length=50,
    )


class AIUsage(BaseModel):
    """Token usage reported by the external AI provider."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    cached_input_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_token_usage(self) -> Self:
        """Ensure reported token counts are internally consistent."""
        if (
            self.input_tokens is not None
            and self.cached_input_tokens is not None
            and self.cached_input_tokens > self.input_tokens
        ):
            raise ValueError("Cached input tokens cannot exceed input tokens.")

        if (
            self.input_tokens is not None
            and self.output_tokens is not None
            and self.total_tokens is not None
            and self.total_tokens != self.input_tokens + self.output_tokens
        ):
            raise ValueError("Total tokens must equal input plus output tokens.")

        return self


class AIResponse[T: BaseModel](BaseModel):
    """Validated structured response and provider metadata."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    data: T
    provider: Literal["openai"]
    model: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=50)
    request_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    usage: AIUsage = Field(default_factory=AIUsage)
    latency_ms: float = Field(ge=0, allow_inf_nan=False)
