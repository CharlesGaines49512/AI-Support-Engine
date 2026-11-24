from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from app.integrations.ai.contracts import AIRequest, AIResponse


@runtime_checkable
class AIProvider(Protocol):
    """Contract implemented by structured AI providers."""

    async def generate_structured[T: BaseModel](
        self,
        request: AIRequest,
        response_schema: type[T],
    ) -> AIResponse[T]:
        """Generate and validate a structured AI response."""
        ...

    async def close(self) -> None:
        """Release resources owned by the provider."""
        ...
