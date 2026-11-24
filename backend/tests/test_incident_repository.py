from unittest.mock import MagicMock
from uuid import uuid4

from sqlalchemy import create_engine

from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.repositories import IncidentRepository


def test_repository_initialization() -> None:
    """Verify database session dependency injection."""
    session = MagicMock()
    repository = IncidentRepository(session)

    assert repository.session is session


def test_create_incident() -> None:
    """Verify incident creation and refresh."""
    session = MagicMock()
    repository = IncidentRepository(session)

    incident = Incident(
        title="Network issue",
        description="Connection failed",
    )

    result = repository.create(incident)

    assert result is incident
    session.add.assert_called_once_with(incident)
    session.flush.assert_called_once()
    session.refresh.assert_called_once_with(incident)
    session.commit.assert_not_called()


def test_get_incident_by_id() -> None:
    """Retrieve an existing incident."""
    session = MagicMock()
    repository = IncidentRepository(session)

    incident = Incident(id=uuid4())
    session.get.return_value = incident

    assert repository.get_by_id(incident.id) is incident
    session.get.assert_called_once_with(Incident, incident.id)


def test_get_missing_incident() -> None:
    """Return None for an unknown incident."""
    session = MagicMock()
    repository = IncidentRepository(session)

    session.get.return_value = None

    assert repository.get_by_id(uuid4()) is None


def test_list_all_incidents() -> None:
    """Retrieve incidents with default pagination."""
    session = MagicMock()
    repository = IncidentRepository(session)

    incidents = [Incident(id=uuid4()), Incident(id=uuid4())]
    session.scalars.return_value.all.return_value = incidents

    assert repository.list_all() == incidents

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=create_engine("postgresql+psycopg://").dialect)
    sql = str(compiled)

    assert "ORDER BY" in sql
    assert "incidents.created_at DESC" in sql
    assert "incidents.id DESC" in sql
    assert "LIMIT" in sql
    assert "OFFSET" in sql
    assert "WHERE" not in sql


def test_list_filtered_incidents() -> None:
    """Verify status, priority and category filtering."""
    session = MagicMock()
    repository = IncidentRepository(session)

    session.scalars.return_value.all.return_value = []

    result = repository.list_all(
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
    )

    assert result == []

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=create_engine("postgresql+psycopg://").dialect)
    sql = str(compiled)
    values = list(compiled.params.values())

    assert "WHERE" in sql
    assert "incidents.status =" in sql
    assert "incidents.priority =" in sql
    assert "incidents.category =" in sql

    assert IncidentStatus.OPEN in values
    assert IncidentPriority.HIGH in values
    assert "Networking" in values


def test_incident_pagination() -> None:
    """Verify offset and limit are included in the query."""
    session = MagicMock()
    repository = IncidentRepository(session)

    session.scalars.return_value.all.return_value = []

    repository.list_all(offset=20, limit=10)

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=create_engine("postgresql+psycopg://").dialect)

    assert 20 in compiled.params.values()
    assert 10 in compiled.params.values()


def test_count_all_incidents() -> None:
    """Return the total number of incidents."""
    session = MagicMock()
    repository = IncidentRepository(session)

    session.execute.return_value.scalar_one.return_value = 5

    assert repository.count() == 5

    statement = session.execute.call_args.args[0]
    sql = str(statement).lower()

    assert "count(" in sql
    assert "where" not in sql


def test_count_filtered_incidents() -> None:
    """Count incidents using the supplied filters."""
    session = MagicMock()
    repository = IncidentRepository(session)

    session.execute.return_value.scalar_one.return_value = 2

    result = repository.count(
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
    )

    assert result == 2

    statement = session.execute.call_args.args[0]
    compiled = statement.compile(dialect=create_engine("postgresql+psycopg://").dialect)
    sql = str(compiled)
    values = list(compiled.params.values())

    assert "incidents.status =" in sql
    assert "incidents.priority =" in sql
    assert "incidents.category =" in sql

    assert IncidentStatus.OPEN in values
    assert IncidentPriority.HIGH in values
    assert "Networking" in values


def test_update_incident() -> None:
    """Verify incident updates are flushed and refreshed."""
    session = MagicMock()
    repository = IncidentRepository(session)

    incident = Incident(
        id=uuid4(),
        status=IncidentStatus.IN_PROGRESS,
    )

    assert repository.update(incident) is incident

    session.flush.assert_called_once()
    session.refresh.assert_called_once_with(incident)
    session.commit.assert_not_called()


def test_delete_incident() -> None:
    """Verify incident deletion without committing."""
    session = MagicMock()
    repository = IncidentRepository(session)

    incident = Incident(id=uuid4())

    repository.delete(incident)

    session.delete.assert_called_once_with(incident)
    session.flush.assert_called_once()
    session.commit.assert_not_called()
