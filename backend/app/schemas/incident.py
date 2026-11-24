from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import IncidentPriority, IncidentStatus


class IncidentBase(BaseModel):
    """Shared incident fields and validation."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=20000)
    priority: IncidentPriority = IncidentPriority.MEDIUM
    category: str | None = Field(default=None, min_length=1, max_length=100)


class IncidentCreate(IncidentBase):
    """Validate requests to create incidents."""


class IncidentUpdate(BaseModel):
    """Validate partial updates to existing incidents."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=20000,
    )
    status: IncidentStatus | None = None
    priority: IncidentPriority | None = None
    category: str | None = Field(default=None, min_length=1, max_length=100)
    resolution: str | None = Field(
        default=None,
        min_length=1,
        max_length=20000,
    )

    @model_validator(mode="after")
    def validate_required_fields(self) -> IncidentUpdate:
        """Prevent required database fields from being set to null."""
        for field_name in ("title", "description", "status", "priority"):
            if (
                field_name in self.model_fields_set
                and getattr(self, field_name) is None
            ):
                raise ValueError(f"{field_name} cannot be null")

        return self


class IncidentResponse(IncidentBase):
    """Represent incident data returned by the API."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    id: UUID
    status: IncidentStatus
    resolution: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
