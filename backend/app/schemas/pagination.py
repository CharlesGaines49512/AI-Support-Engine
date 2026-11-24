from pydantic import BaseModel, Field


class PaginatedResponse[T](BaseModel):
    """Standard paginated API response."""

    items: list[T]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    has_more: bool
