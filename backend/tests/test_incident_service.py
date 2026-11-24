from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

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
def session() -> MagicMock:
    """Provide a mocked database session."""
    return MagicMock()


@pytest.fixture
def service(session: MagicMock) -> IncidentService:
    """Provide an incident service."""
    return IncidentService(session)


@pytest.fixture
def incident(session: MagicMock) -> Incident:
    """Provide an existing incident."""
    record = Incident(
        id=uuid4(),
        title="Network issue",
        description="Connection failed",
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.MEDIUM,
        category="Networking",
        resolution=None,
        resolved_at=None,
    )

    session.get.return_value = record
    return record


def test_create_incident(
    service: IncidentService,
    session: MagicMock,
) -> None:
    result = service.create_incident(
        IncidentCreate(
            title="Network issue",
            description="Connection failed",
        )
    )

    assert result.status == IncidentStatus.OPEN
    assert result.priority == IncidentPriority.MEDIUM
    assert result.title == "Network issue"

    session.add.assert_called_once_with(result)
    session.commit.assert_called_once()


def test_create_rollback(
    service: IncidentService,
    session: MagicMock,
) -> None:
    session.flush.side_effect = SQLAlchemyError("Database failure")

    with pytest.raises(SQLAlchemyError):
        service.create_incident(
            IncidentCreate(
                title="Network issue",
                description="Connection failed",
            )
        )

    session.rollback.assert_called_once()
    session.commit.assert_not_called()


def test_get_incident(
    service: IncidentService,
    incident: Incident,
) -> None:
    assert service.get_incident(incident.id) is incident


def test_get_missing_incident(
    service: IncidentService,
    session: MagicMock,
) -> None:
    incident_id = uuid4()
    session.get.return_value = None

    with pytest.raises(IncidentNotFoundError) as error:
        service.get_incident(incident_id)

    assert error.value.incident_id == incident_id


def test_list_incidents(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.scalars.return_value.all.return_value = [incident]

    result = service.list_incidents(
        offset=0,
        limit=10,
        status=IncidentStatus.OPEN,
    )

    assert result == [incident]


def test_count_incidents(
    service: IncidentService,
    session: MagicMock,
) -> None:
    session.execute.return_value.scalar_one.return_value = 3

    assert service.count_incidents(priority=IncidentPriority.HIGH) == 3


def test_update_incident(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    result = service.update_incident(
        incident.id,
        IncidentUpdate(
            title="Updated network issue",
            status=IncidentStatus.IN_PROGRESS,
        ),
    )

    assert result.title == "Updated network issue"
    assert result.status == IncidentStatus.IN_PROGRESS

    session.commit.assert_called_once()


def test_empty_update(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    assert (
        service.update_incident(
            incident.id,
            IncidentUpdate(),
        )
        is incident
    )

    session.commit.assert_not_called()
    session.flush.assert_not_called()


def test_invalid_transition(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    with pytest.raises(InvalidIncidentTransitionError):
        service.update_incident(
            incident.id,
            IncidentUpdate(status=IncidentStatus.CLOSED),
        )

    assert incident.status == IncidentStatus.OPEN
    session.commit.assert_not_called()


def test_resolution_required(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    incident.status = IncidentStatus.IN_PROGRESS

    with pytest.raises(IncidentResolutionRequiredError):
        service.update_incident(
            incident.id,
            IncidentUpdate(status=IncidentStatus.RESOLVED),
        )

    assert incident.status == IncidentStatus.IN_PROGRESS
    session.commit.assert_not_called()


def test_resolve_incident(
    service: IncidentService,
    incident: Incident,
) -> None:
    incident.status = IncidentStatus.IN_PROGRESS
    before = datetime.now(UTC)

    result = service.update_incident(
        incident.id,
        IncidentUpdate(
            status=IncidentStatus.RESOLVED,
            resolution="Replaced network adapter.",
        ),
    )

    assert result.status == IncidentStatus.RESOLVED
    assert result.resolution == "Replaced network adapter."
    assert result.resolved_at is not None
    assert before <= result.resolved_at <= datetime.now(UTC)


def test_reopen_incident(
    service: IncidentService,
    incident: Incident,
) -> None:
    incident.status = IncidentStatus.RESOLVED
    incident.resolution = "Reset network configuration."
    incident.resolved_at = datetime.now(UTC)

    result = service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.IN_PROGRESS),
    )

    assert result.status == IncidentStatus.IN_PROGRESS
    assert result.resolved_at is None


def test_close_incident(
    service: IncidentService,
    incident: Incident,
) -> None:
    timestamp = datetime.now(UTC)
    incident.status = IncidentStatus.RESOLVED
    incident.resolution = "Connection restored."
    incident.resolved_at = timestamp

    result = service.update_incident(
        incident.id,
        IncidentUpdate(status=IncidentStatus.CLOSED),
    )

    assert result.status == IncidentStatus.CLOSED
    assert result.resolved_at == timestamp


def test_cannot_clear_required_resolution(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    incident.status = IncidentStatus.RESOLVED
    incident.resolution = "Connection restored."

    with pytest.raises(IncidentResolutionRequiredError):
        service.update_incident(
            incident.id,
            IncidentUpdate(resolution=None),
        )

    assert incident.resolution == "Connection restored."
    session.commit.assert_not_called()


def test_update_rollback(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.commit.side_effect = SQLAlchemyError("Commit failure")

    with pytest.raises(SQLAlchemyError):
        service.update_incident(
            incident.id,
            IncidentUpdate(title="Updated title"),
        )

    session.rollback.assert_called_once()


def test_delete_incident(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    service.delete_incident(incident.id)

    session.delete.assert_called_once_with(incident)
    session.commit.assert_called_once()


def test_delete_rollback(
    service: IncidentService,
    session: MagicMock,
    incident: Incident,
) -> None:
    session.flush.side_effect = SQLAlchemyError("Delete failure")

    with pytest.raises(SQLAlchemyError):
        service.delete_incident(incident.id)

    session.rollback.assert_called_once()
    session.commit.assert_not_called()
