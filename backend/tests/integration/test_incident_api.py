from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.main import app
from app.models import Incident

BASE_URL = "/api/v1/incidents"


@pytest.fixture
def category(
    integration_engine: Engine,
) -> Generator[str]:
    """Isolate and clean up committed API test records."""
    value = f"API-Integration-{uuid4()}"

    try:
        yield value
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(Incident).where(Incident.category == value))


@pytest.fixture
def client(
    integration_engine: Engine,
) -> Generator[TestClient]:
    """Connect the API to the isolated PostgreSQL database."""

    def override_get_db() -> Generator[Session]:
        with Session(
            bind=integration_engine,
            autoflush=False,
            expire_on_commit=False,
        ) as session:
            try:
                yield session
            except Exception:
                session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_api_create_and_retrieve(
    client: TestClient,
    category: str,
) -> None:
    response = client.post(
        BASE_URL,
        json={
            "title": "Network issue",
            "description": "Connection failed",
            "priority": "high",
            "category": category,
        },
    )

    assert response.status_code == 201

    created = response.json()

    assert created["status"] == "open"
    assert created["priority"] == "high"
    assert created["created_at"] is not None
    assert created["resolved_at"] is None

    response = client.get(f"{BASE_URL}/{created['id']}")

    assert response.status_code == 200
    assert response.json() == created


def test_api_complete_incident_lifecycle(
    client: TestClient,
    category: str,
) -> None:
    response = client.post(
        BASE_URL,
        json={
            "title": "Lifecycle test",
            "description": "Test complete incident lifecycle",
            "category": category,
        },
    )

    assert response.status_code == 201

    incident_id = response.json()["id"]
    url = f"{BASE_URL}/{incident_id}"

    for next_status in (
        "in_progress",
        "pending",
        "in_progress",
    ):
        response = client.patch(
            url,
            json={"status": next_status},
        )

        assert response.status_code == 200
        assert response.json()["status"] == next_status

    response = client.patch(
        url,
        json={
            "status": "resolved",
            "resolution": "Connection restored.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"

    timestamp = response.json()["resolved_at"]
    assert timestamp is not None

    response = client.patch(
        url,
        json={"status": "closed"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    assert response.json()["resolved_at"] == timestamp

    response = client.delete(url)

    assert response.status_code == 204
    assert response.content == b""

    assert client.get(url).status_code == 404


def test_api_invalid_transition_preserves_state(
    client: TestClient,
    category: str,
) -> None:
    response = client.post(
        BASE_URL,
        json={
            "title": "Original incident",
            "description": "Transition validation",
            "category": category,
        },
    )

    assert response.status_code == 201

    url = f"{BASE_URL}/{response.json()['id']}"

    response = client.patch(
        url,
        json={
            "title": "Invalid update",
            "status": "closed",
        },
    )

    assert response.status_code == 409

    response = client.get(url)

    assert response.status_code == 200
    assert response.json()["status"] == "open"
    assert response.json()["title"] == "Original incident"


def test_api_resolution_required(
    client: TestClient,
    category: str,
) -> None:
    response = client.post(
        BASE_URL,
        json={
            "title": "Resolution test",
            "description": "Resolution validation",
            "category": category,
        },
    )

    assert response.status_code == 201

    url = f"{BASE_URL}/{response.json()['id']}"

    response = client.patch(
        url,
        json={"status": "in_progress"},
    )

    assert response.status_code == 200

    response = client.patch(
        url,
        json={"status": "resolved"},
    )

    assert response.status_code == 409

    response = client.get(url)

    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"
    assert response.json()["resolved_at"] is None


def test_api_filtering_and_pagination(
    client: TestClient,
    category: str,
) -> None:
    expected_ids: set[str] = set()

    for index in range(5):
        response = client.post(
            BASE_URL,
            json={
                "title": f"Incident {index}",
                "description": "Pagination integration test",
                "priority": "high",
                "category": category,
            },
        )

        assert response.status_code == 201
        expected_ids.add(response.json()["id"])

    response = client.post(
        BASE_URL,
        json={
            "title": "Low priority incident",
            "description": "Filtering integration test",
            "priority": "low",
            "category": category,
        },
    )

    assert response.status_code == 201

    returned_ids: list[str] = []

    for offset in (0, 2, 4):
        response = client.get(
            BASE_URL,
            params={
                "category": category,
                "priority": "high",
                "status": "open",
                "offset": offset,
                "limit": 2,
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["offset"] == offset
        assert data["limit"] == 2
        assert data["has_more"] == (offset < 4)
        assert len(data["items"]) == min(2, 5 - offset)

        returned_ids.extend(item["id"] for item in data["items"])

    assert len(returned_ids) == 5
    assert set(returned_ids) == expected_ids


def test_api_invalid_request_does_not_create_record(
    client: TestClient,
    category: str,
) -> None:
    response = client.post(
        BASE_URL,
        json={
            "title": "",
            "description": "Invalid incident",
            "category": category,
        },
    )

    assert response.status_code == 422

    response = client.get(
        BASE_URL,
        params={"category": category},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0
    assert response.json()["items"] == []


def test_api_missing_incident_operations(
    client: TestClient,
) -> None:
    url = f"{BASE_URL}/{uuid4()}"

    assert client.get(url).status_code == 404

    response = client.patch(
        url,
        json={"title": "Missing incident"},
    )

    assert response.status_code == 404
    assert client.delete(url).status_code == 404
