from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.repositories import IncidentRepository


@pytest.fixture
def repository(
    integration_session: Session,
) -> IncidentRepository:
    """Provide a repository connected to PostgreSQL."""
    return IncidentRepository(integration_session)


@pytest.fixture
def category() -> str:
    """Generate an isolated category for each test."""
    return f"Integration-{uuid4()}"


def test_create_incident(
    repository: IncidentRepository,
    category: str,
) -> None:
    incident = repository.create(
        Incident(
            title="Network issue",
            description="Connection failed",
            category=category,
        )
    )

    assert incident.id is not None
    assert incident.status == IncidentStatus.OPEN
    assert incident.priority == IncidentPriority.MEDIUM
    assert incident.created_at is not None
    assert incident.updated_at is not None
    assert incident.resolved_at is None


def test_retrieve_incident(
    repository: IncidentRepository,
    integration_session: Session,
    category: str,
) -> None:
    incident = repository.create(
        Incident(
            title="Application issue",
            description="Login failed",
            category=category,
        )
    )

    incident_id = incident.id
    integration_session.expunge_all()

    retrieved = repository.get_by_id(incident_id)

    assert retrieved is not None
    assert retrieved.id == incident_id
    assert retrieved.title == "Application issue"
    assert retrieved.category == category


def test_missing_incident(
    repository: IncidentRepository,
) -> None:
    assert repository.get_by_id(uuid4()) is None


def test_filter_incidents(
    repository: IncidentRepository,
    category: str,
) -> None:
    first = repository.create(
        Incident(
            title="Network outage",
            description="Connection unavailable",
            priority=IncidentPriority.CRITICAL,
            category=category,
        )
    )

    repository.create(
        Incident(
            title="Login issue",
            description="Authentication failed",
            priority=IncidentPriority.LOW,
            category=category,
        )
    )

    first.status = IncidentStatus.IN_PROGRESS
    repository.update(first)

    incidents = repository.list_all(
        status=IncidentStatus.IN_PROGRESS,
        priority=IncidentPriority.CRITICAL,
        category=category,
    )

    assert len(incidents) == 1
    assert incidents[0].id == first.id


def test_incident_pagination(
    repository: IncidentRepository,
    category: str,
) -> None:
    created_ids = set()

    for index in range(5):
        incident = repository.create(
            Incident(
                title=f"Incident {index}",
                description="Pagination test",
                category=category,
            )
        )

        created_ids.add(incident.id)

    first_page = repository.list_all(
        offset=0,
        limit=2,
        category=category,
    )

    second_page = repository.list_all(
        offset=2,
        limit=2,
        category=category,
    )

    third_page = repository.list_all(
        offset=4,
        limit=2,
        category=category,
    )

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert len(third_page) == 1

    returned_ids = [incident.id for incident in first_page + second_page + third_page]

    assert len(set(returned_ids)) == 5
    assert set(returned_ids) == created_ids


def test_incident_count(
    repository: IncidentRepository,
    category: str,
) -> None:
    for priority in (
        IncidentPriority.HIGH,
        IncidentPriority.HIGH,
        IncidentPriority.LOW,
    ):
        repository.create(
            Incident(
                title="Count test",
                description="Counting incidents",
                priority=priority,
                category=category,
            )
        )

    assert repository.count(category=category) == 3

    assert (
        repository.count(
            priority=IncidentPriority.HIGH,
            category=category,
        )
        == 2
    )

    assert (
        repository.count(
            priority=IncidentPriority.CRITICAL,
            category=category,
        )
        == 0
    )


def test_update_incident(
    repository: IncidentRepository,
    integration_session: Session,
    category: str,
) -> None:
    incident = repository.create(
        Incident(
            title="Original title",
            description="Original description",
            category=category,
        )
    )

    incident_id = incident.id
    incident.title = "Updated title"
    incident.status = IncidentStatus.IN_PROGRESS
    incident.priority = IncidentPriority.HIGH

    repository.update(incident)
    integration_session.expunge_all()

    retrieved = repository.get_by_id(incident_id)

    assert retrieved is not None
    assert retrieved.title == "Updated title"
    assert retrieved.status == IncidentStatus.IN_PROGRESS
    assert retrieved.priority == IncidentPriority.HIGH


def test_delete_incident(
    repository: IncidentRepository,
    category: str,
) -> None:
    incident = repository.create(
        Incident(
            title="Delete test",
            description="Temporary incident",
            category=category,
        )
    )

    incident_id = incident.id
    repository.delete(incident)

    assert repository.get_by_id(incident_id) is None
    assert repository.count(category=category) == 0


def test_transaction_rollback(
    repository: IncidentRepository,
    integration_session: Session,
    category: str,
) -> None:
    repository.create(
        Incident(
            title="Rollback test",
            description="Uncommitted incident",
            category=category,
        )
    )

    assert repository.count(category=category) == 1

    integration_session.rollback()

    assert repository.count(category=category) == 0


def test_database_integrity_constraint(
    repository: IncidentRepository,
    integration_session: Session,
) -> None:
    incident = Incident(
        description="Incident without required title",
    )

    with pytest.raises(IntegrityError):
        repository.create(incident)

    integration_session.rollback()

    recovered = repository.create(
        Incident(
            title="Recovery test",
            description="Session recovered after rollback",
        )
    )

    assert recovered.id is not None
