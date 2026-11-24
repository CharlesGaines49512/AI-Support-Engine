from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_returns_application_information() -> None:
    """Verify that the root endpoint returns application metadata."""
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "application": "AI Support Engine",
        "version": "0.1.0",
    }


def test_health_check_returns_healthy_status() -> None:
    """Verify that the application health endpoint responds."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_unknown_endpoint_returns_not_found() -> None:
    """Verify that an invalid endpoint returns HTTP 404."""
    response = client.get("/invalid-endpoint")

    assert response.status_code == 404


def test_openapi_schema_is_available() -> None:
    """Verify that the API specification is accessible."""
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "AI Support Engine"
    assert "/health" in response.json()["paths"]
