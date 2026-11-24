from collections.abc import Generator
from uuid import uuid4

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    IncidentNotFoundError,
    IncidentResolutionRequiredError,
    InvalidIncidentTransitionError,
)
from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services import IncidentService


@pytest.fixture
def category(
    integration_engine: Engine,
) -> Generator[str]:
    """Isolate committed test records and remove them afterward."""
    value = f"Service-Integration-{uuid4()}"

    try:
        yield value
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(Incident).where(Incident.category == value))


@pytest.fixture
def service(
    integration_session: Session,
) -> IncidentService:
    """Provide a service connected to PostgreSQL."""
    return IncidentService(integration_session)


@pytest.fixture
def incident(
    service: IncidentService,
    category: str,
) -> Incident:
    """Create a committed test incident."""
    return service.create_incident(
        IncidentCreate(
            title="Network issue",
            description="Connection failed",
            category=category,
            priority=IncidentPriority.HIGH,
        )
    )


def test_committed_incident_persistence(
    integration_engine: Engine,
    incident: Incident,
) -> None:
    with Session(integration_engine) as session:
        service = IncidentService(session)
        retrieved = service.get_incident(incident.id)

        assert retrieved.title == incident.title
        assert retrieved.status == IncidentStatus.OPEN
        assert retrieved.priority == IncidentPriority.HIGH


def test_committed_incident_update(
    integration_engine: Engine,
    service: IncidentService,
    incident: Incident,
) -> None:
    service.update_incident(
        incident.id,
        IncidentUpdate(
            title="Updated network issue",
            status=IncidentStatus.IN_PROGRESS,
        ),
    )

    with Session(integration_engine) as session:
        retrieved = IncidentService(session).get_incident(incident.id)

        assert retrieved.title == "Updated network issue"
        assert retrieved.status == IncidentStatus.IN_PROGRESS


def test_invalid_transition_preserves_database_state(
    integration_engine: Engine,
    service: IncidentService,
    incident: Incident,
) -> None:
    with pytest.raises(InvalidIncidentTransitionError):
        service.update_incident(
            incident.id,
            IncidentUpdate(
                title="Invalid update",
                status=IncidentStatus.CLOSED,
            ),
        )

    with Session(integration_engine) as session:
        retrieved = IncidentService(session).get_incident(incident.id)

        assert retrieved.status == IncidentStatus.OPEN
        assert retrieved.title == "Network issue"


def test_resolution_required(
    service: IncidentService,
    incident: Incident,
) -> None:
    service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.IN_PROGRESS),
    )

    with pytest.raises(IncidentResolutionRequiredError):
        service.update_incident(
            incident.id,
            IncidentUpdate(status=IncidentStatus.RESOLVED),
        )

    retrieved = service.get_incident(incident.id)

    assert retrieved.status == IncidentStatus.IN_PROGRESS
    assert retrieved.resolved_at is None


def test_resolve_and_close_incident(
    integration_engine: Engine,
    service: IncidentService,
    incident: Incident,
) -> None:
    service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.IN_PROGRESS),
    )

    resolved = service.update_incident(
        incident.id,
        IncidentUpdate(
            status=IncidentStatus.RESOLVED,
            resolution="Replaced network adapter.",
        ),
    )

    timestamp = resolved.resolved_at
    assert timestamp is not None

    service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.CLOSED),
    )

    with Session(integration_engine) as session:
        retrieved = IncidentService(session).get_incident(incident.id)

        assert retrieved.status == IncidentStatus.CLOSED
        assert retrieved.resolved_at == timestamp
        assert retrieved.resolution == "Replaced network adapter."


def test_reopen_incident(
    integration_engine: Engine,
    service: IncidentService,
    incident: Incident,
) -> None:
    service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.IN_PROGRESS),
    )

    service.update_incident(
        incident.id,
        IncidentUpdate(
            status=IncidentStatus.RESOLVED,
            resolution="Connection restored.",
        ),
    )

    service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.IN_PROGRESS),
    )

    with Session(integration_engine) as session:
        retrieved = IncidentService(session).get_incident(incident.id)

        assert retrieved.status == IncidentStatus.IN_PROGRESS
        assert retrieved.resolved_at is None


def test_service_filtering_and_counting(
    service: IncidentService,
    category: str,
    incident: Incident,
) -> None:
    service.create_incident(
        IncidentCreate(
            title="Application issue",
            description="Login failed",
            category=category,
            priority=IncidentPriority.LOW,
        )
    )

    assert service.count_incidents(category=category) == 2

    results = service.list_incidents(
        category=category,
        priority=IncidentPriority.HIGH,
    )

    assert len(results) == 1
    assert results[0].id == incident.id


def test_committed_incident_deletion(
    integration_engine: Engine,
    service: IncidentService,
    incident: Incident,
) -> None:
    incident_id = incident.id
    service.delete_incident(incident_id)

    with Session(integration_engine) as session:
        with pytest.raises(IncidentNotFoundError):
            IncidentService(session).get_incident(incident_id)


def test_service_transaction_rollback(
    integration_engine: Engine,
    integration_session: Session,
    service: IncidentService,
    incident: Incident,
    category: str,
) -> None:
    incident_id = incident.id

    duplicate = Incident(
        id=incident_id,
        title="Duplicate incident",
        description="Duplicate primary key test",
        category=category,
    )

    integration_session.expunge(incident)
    integration_session.add(duplicate)

    with pytest.raises(IntegrityError):
        service.create_incident(
            IncidentCreate(
                title="Rollback incident",
                description="This transaction must fail.",
                category=category,
            )
        )

    with Session(integration_engine) as session:
        statement = select(Incident).where(Incident.category == category)

        records = list(session.scalars(statement).all())

        assert len(records) == 1
        assert records[0].id == incident_id
        assert records[0].title == "Network issue"

    recovered = service.create_incident(
        IncidentCreate(
            title="Recovery incident",
            description="Session recovered after rollback.",
            category=category,
        )
    )

    assert recovered.id != incident_id
    assert service.count_incidents(category=category) == 2
