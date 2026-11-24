from unittest.mock import MagicMock

from sqlalchemy.orm import Session

from app.api.dependencies import get_incident_service
from app.repositories import IncidentRepository
from app.services import IncidentService


def test_get_incident_service() -> None:
    """Verify incident service dependency initialization."""
    session = MagicMock(spec=Session)

    service = get_incident_service(session)

    assert isinstance(service, IncidentService)
    assert service.session is session
    assert isinstance(service.repository, IncidentRepository)
    assert service.repository.session is session
