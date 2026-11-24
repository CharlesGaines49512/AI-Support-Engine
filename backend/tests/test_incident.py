from sqlalchemy import ColumnDefault, Enum

from app.core.base import Base
from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus


def test_incident_table_registration() -> None:
    """Verify incident table registration."""
    assert "incidents" in Base.metadata.tables
    assert Incident.__tablename__ == "incidents"


def test_incident_columns() -> None:
    """Verify all required incident columns exist."""
    table = Base.metadata.tables["incidents"]

    assert set(table.columns.keys()) == {
        "id",
        "title",
        "description",
        "status",
        "priority",
        "category",
        "resolution",
        "created_at",
        "updated_at",
        "resolved_at",
    }


def test_incident_primary_key() -> None:
    """Verify the incident primary key."""
    table = Base.metadata.tables["incidents"]

    assert list(table.primary_key.columns.keys()) == ["id"]
    assert table.primary_key.name == "pk_incidents"


def test_incident_status_values() -> None:
    """Verify supported incident statuses."""
    assert {status.value for status in IncidentStatus} == {
        "open",
        "in_progress",
        "pending",
        "resolved",
        "closed",
    }


def test_incident_priority_values() -> None:
    """Verify supported incident priorities."""
    assert {priority.value for priority in IncidentPriority} == {
        "low",
        "medium",
        "high",
        "critical",
    }


def test_incident_required_columns() -> None:
    """Verify required fields cannot be null."""
    table = Base.metadata.tables["incidents"]

    for name in (
        "id",
        "title",
        "description",
        "status",
        "priority",
        "created_at",
        "updated_at",
    ):
        assert table.columns[name].nullable is False


def test_incident_optional_columns() -> None:
    """Verify optional incident fields allow null values."""
    table = Base.metadata.tables["incidents"]

    for name in ("category", "resolution", "resolved_at"):
        assert table.columns[name].nullable is True


def test_incident_indexes() -> None:
    """Verify indexes for common incident queries."""
    table = Base.metadata.tables["incidents"]

    assert {index.name for index in table.indexes} == {
        "ix_incidents_category",
        "ix_incidents_created_at",
        "ix_incidents_priority",
        "ix_incidents_status",
    }


def test_incident_enum_types() -> None:
    """Verify PostgreSQL enum configuration."""
    table = Base.metadata.tables["incidents"]

    status_type = table.columns["status"].type
    priority_type = table.columns["priority"].type

    assert isinstance(status_type, Enum)
    assert isinstance(priority_type, Enum)

    assert status_type.name == "incident_status"
    assert priority_type.name == "incident_priority"

    assert status_type.enums == [status.value for status in IncidentStatus]
    assert priority_type.enums == [priority.value for priority in IncidentPriority]


def test_incident_initialization() -> None:
    """Verify incident model initialization."""
    incident = Incident(
        title="Network connectivity issue",
        description="Unable to connect to the network.",
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
    )

    assert incident.title == "Network connectivity issue"
    assert incident.status == IncidentStatus.OPEN
    assert incident.priority == IncidentPriority.HIGH
    assert incident.category == "Networking"
    assert incident.resolution is None
    assert incident.resolved_at is None


def test_incident_defaults() -> None:
    """Verify default status and priority configuration."""
    table = Base.metadata.tables["incidents"]

    status_default = table.columns["status"].default
    priority_default = table.columns["priority"].default

    assert isinstance(status_default, ColumnDefault)
    assert isinstance(priority_default, ColumnDefault)

    assert status_default.arg == IncidentStatus.OPEN
    assert priority_default.arg == IncidentPriority.MEDIUM
