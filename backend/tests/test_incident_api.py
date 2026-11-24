from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_incident_service
from app.core.exceptions import (
    IncidentNotFoundError,
    IncidentResolutionRequiredError,
    InvalidIncidentTransitionError,
)
from app.main import app
from app.models import Incident
from app.models.enums import IncidentPriority, IncidentStatus
from app.services import IncidentService

BASE_URL = "/api/v1/incidents"


@pytest.fixture
def service() -> MagicMock:
    """Provide a mocked incident service."""
    return MagicMock(spec=IncidentService)


@pytest.fixture
def client(service: MagicMock) -> Generator[TestClient]:
    """Provide an API client with overridden dependencies."""
    app.dependency_overrides[get_incident_service] = lambda: service

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_incident_service, None)


@pytest.fixture
def incident() -> Incident:
    """Provide a sample incident for API responses."""
    timestamp = datetime.now(UTC)

    return Incident(
        id=uuid4(),
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


def test_create_incident(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.create_incident.return_value = incident

    response = client.post(
        BASE_URL,
        json={
            "title": "Network issue",
            "description": "Connection failed",
            "priority": "high",
            "category": "Networking",
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == str(incident.id)
    assert response.json()["status"] == "open"
    assert response.json()["priority"] == "high"

    service.create_incident.assert_called_once()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": "", "description": "Connection failed"},
        {"title": "Network issue"},
        {
            "title": "Network issue",
            "description": "Connection failed",
            "priority": "invalid",
        },
        {
            "title": "Network issue",
            "description": "Connection failed",
            "status": "closed",
        },
    ],
)
def test_create_invalid_incident(
    client: TestClient,
    service: MagicMock,
    payload: dict[str, str],
) -> None:
    response = client.post(BASE_URL, json=payload)

    assert response.status_code == 422
    service.create_incident.assert_not_called()


def test_get_incident(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.get_incident.return_value = incident

    response = client.get(f"{BASE_URL}/{incident.id}")

    assert response.status_code == 200
    assert response.json()["id"] == str(incident.id)
    service.get_incident.assert_called_once_with(incident.id)


def test_get_missing_incident(
    client: TestClient,
    service: MagicMock,
) -> None:
    incident_id = uuid4()
    service.get_incident.side_effect = IncidentNotFoundError(incident_id)

    response = client.get(f"{BASE_URL}/{incident_id}")

    assert response.status_code == 404
    assert str(incident_id) in response.json()["detail"]


def test_get_invalid_uuid(
    client: TestClient,
    service: MagicMock,
) -> None:
    response = client.get(f"{BASE_URL}/invalid-id")

    assert response.status_code == 422
    service.get_incident.assert_not_called()


def test_list_incidents(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.list_incidents.return_value = [incident]
    service.count_incidents.return_value = 1

    response = client.get(BASE_URL)

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 1
    assert data["total"] == 1
    assert data["offset"] == 0
    assert data["limit"] == 20
    assert data["has_more"] is False


def test_list_empty_incidents(
    client: TestClient,
    service: MagicMock,
) -> None:
    service.list_incidents.return_value = []
    service.count_incidents.return_value = 0

    response = client.get(BASE_URL)

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["total"] == 0
    assert response.json()["has_more"] is False


def test_list_filtered_incidents(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.list_incidents.return_value = [incident]
    service.count_incidents.return_value = 1

    response = client.get(
        BASE_URL,
        params={
            "status": "open",
            "priority": "high",
            "category": "Networking",
            "offset": 0,
            "limit": 10,
        },
    )

    assert response.status_code == 200
    assert response.json()["limit"] == 10

    service.list_incidents.assert_called_once_with(
        offset=0,
        limit=10,
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
    )

    service.count_incidents.assert_called_once_with(
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.HIGH,
        category="Networking",
    )


def test_pagination_has_more(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.list_incidents.return_value = [incident]
    service.count_incidents.return_value = 5

    response = client.get(
        BASE_URL,
        params={"offset": 0, "limit": 1},
    )

    assert response.status_code == 200
    assert response.json()["has_more"] is True


@pytest.mark.parametrize(
    "params",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": 101},
        {"status": "invalid"},
        {"priority": "invalid"},
    ],
)
def test_invalid_query_parameters(
    client: TestClient,
    service: MagicMock,
    params: dict[str, int | str],
) -> None:
    response = client.get(BASE_URL, params=params)

    assert response.status_code == 422
    service.list_incidents.assert_not_called()


def test_update_incident(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    incident.status = IncidentStatus.IN_PROGRESS
    service.update_incident.return_value = incident

    response = client.patch(
        f"{BASE_URL}/{incident.id}",
        json={"status": "in_progress"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"

    service.update_incident.assert_called_once()


def test_update_missing_incident(
    client: TestClient,
    service: MagicMock,
) -> None:
    incident_id = uuid4()
    service.update_incident.side_effect = IncidentNotFoundError(incident_id)

    response = client.patch(
        f"{BASE_URL}/{incident_id}",
        json={"title": "Updated title"},
    )

    assert response.status_code == 404


def test_update_invalid_transition(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.update_incident.side_effect = InvalidIncidentTransitionError(
        IncidentStatus.OPEN,
        IncidentStatus.CLOSED,
    )

    response = client.patch(
        f"{BASE_URL}/{incident.id}",
        json={"status": "closed"},
    )

    assert response.status_code == 409


def test_update_missing_resolution(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    service.update_incident.side_effect = IncidentResolutionRequiredError()

    response = client.patch(
        f"{BASE_URL}/{incident.id}",
        json={"status": "resolved"},
    )

    assert response.status_code == 409


def test_update_invalid_payload(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    response = client.patch(
        f"{BASE_URL}/{incident.id}",
        json={"title": None},
    )

    assert response.status_code == 422
    service.update_incident.assert_not_called()


def test_delete_incident(
    client: TestClient,
    service: MagicMock,
    incident: Incident,
) -> None:
    response = client.delete(f"{BASE_URL}/{incident.id}")

    assert response.status_code == 204
    assert response.content == b""

    service.delete_incident.assert_called_once_with(incident.id)


def test_delete_missing_incident(
    client: TestClient,
    service: MagicMock,
) -> None:
    incident_id = uuid4()
    service.delete_incident.side_effect = IncidentNotFoundError(incident_id)

    response = client.delete(f"{BASE_URL}/{incident_id}")

    assert response.status_code == 404


def test_openapi_incident_endpoints(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json()["paths"]

    assert "get" in paths[BASE_URL]
    assert "post" in paths[BASE_URL]

    detail_path = BASE_URL + "/{incident_id}"

    assert "get" in paths[detail_path]
    assert "patch" in paths[detail_path]
    assert "delete" in paths[detail_path]
