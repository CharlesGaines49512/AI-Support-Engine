from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.schemas.incident import (
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
)


def test_incident_create_defaults() -> None:
    """Verify default values for new incidents."""
    incident = IncidentCreate(
        title="Network issue",
        description="Connection failed",
    )

    assert incident.priority == IncidentPriority.MEDIUM
    assert incident.category is None


def test_incident_create_strips_whitespace() -> None:
    """Verify unnecessary whitespace is removed."""
    incident = IncidentCreate(
        title="  Network issue  ",
        description="  Connection failed  ",
        category="  Networking  ",
    )

    assert incident.title == "Network issue"
    assert incident.description == "Connection failed"
    assert incident.category == "Networking"


@pytest.mark.parametrize(
    "data",
    [
        {"title": "", "description": "Connection failed"},
        {"title": "   ", "description": "Connection failed"},
        {"title": "A" * 256, "description": "Connection failed"},
        {"title": "Network issue"},
        {"description": "Connection failed"},
        {"title": "Network issue", "description": ""},
        {"title": "Network issue", "description": "A" * 20001},
        {
            "title": "Network issue",
            "description": "Connection failed",
            "priority": "urgent",
        },
        {
            "title": "Network issue",
            "description": "Connection failed",
            "category": "A" * 101,
        },
        {
            "title": "Network issue",
            "description": "Connection failed",
            "unknown_field": "invalid",
        },
    ],
)
def test_incident_create_rejects_invalid_data(
    data: dict[str, str],
) -> None:
    """Reject invalid incident creation requests."""
    with pytest.raises(ValidationError):
        IncidentCreate.model_validate(data)


def test_incident_partial_update() -> None:
    """Verify only explicitly provided fields are updated."""
    update = IncidentUpdate(status=IncidentStatus.IN_PROGRESS)

    assert update.model_dump(
        exclude_unset=True,
        mode="json",
    ) == {"status": "in_progress"}


def test_incident_empty_update() -> None:
    """Verify omitted fields are excluded."""
    update = IncidentUpdate()

    assert update.model_dump(exclude_unset=True) == {}


@pytest.mark.parametrize("field", ["category", "resolution"])
def test_incident_clear_optional_field(field: str) -> None:
    """Allow nullable fields to be explicitly cleared."""
    update = IncidentUpdate.model_validate({field: None})

    assert update.model_dump(exclude_unset=True) == {field: None}


@pytest.mark.parametrize(
    "field",
    ["title", "description", "status", "priority"],
)
def test_incident_update_rejects_null(field: str) -> None:
    """Prevent required fields from being set to null."""
    with pytest.raises(ValidationError):
        IncidentUpdate.model_validate({field: None})


@pytest.mark.parametrize(
    "data",
    [
        {"title": ""},
        {"description": "   "},
        {"status": "invalid"},
        {"priority": "urgent"},
        {"category": "A" * 101},
        {"resolution": "A" * 20001},
        {"unknown_field": "invalid"},
        {"resolved_at": "2026-01-01"},
    ],
)
def test_incident_update_rejects_invalid_data(
    data: dict[str, str],
) -> None:
    """Reject invalid incident update requests."""
    with pytest.raises(ValidationError):
        IncidentUpdate.model_validate(data)


def test_incident_response_serialization() -> None:
    """Verify serialization of a SQLAlchemy incident object."""
    incident_id = uuid4()
    timestamp = datetime.now(UTC)

    incident = Incident(
        id=incident_id,
        title="Network issue",
        description="Connection failed",
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
        resolution=None,
        created_at=timestamp,
        updated_at=timestamp,
        resolved_at=None,
    )

    response = IncidentResponse.model_validate(incident)
    data = response.model_dump(mode="json")

    assert response.id == incident_id
    assert data["id"] == str(incident_id)
    assert data["title"] == "Network issue"
    assert data["status"] == "open"
    assert data["priority"] == "high"
    assert data["category"] == "Networking"
    assert data["resolution"] is None
    assert data["resolved_at"] is None
    assert response.created_at == timestamp
    assert response.updated_at == timestamp
