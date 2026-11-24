from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import check_database_health
from app.main import app

client = TestClient(app)


def test_readiness_with_healthy_database() -> None:
    """Return HTTP 200 when PostgreSQL is available."""
    with patch("app.main.check_database_health", return_value=True):
        response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "database": "healthy",
    }


def test_readiness_with_unavailable_database() -> None:
    """Return HTTP 503 when PostgreSQL is unavailable."""
    with patch("app.main.check_database_health", return_value=False):
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "database": "unavailable",
    }


def test_liveness_during_database_outage() -> None:
    """Keep the application healthy during a database outage."""
    with patch("app.main.check_database_health", return_value=False) as check:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
    check.assert_not_called()


def test_database_health_check_success() -> None:
    """Return True when the database query succeeds."""
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalar.return_value = 1

    with patch("app.core.database.get_engine", return_value=engine):
        assert check_database_health() is True


def test_database_health_check_failure() -> None:
    """Return False when a database connection fails."""
    engine = MagicMock()
    engine.connect.side_effect = SQLAlchemyError("Connection failed")

    with patch("app.core.database.get_engine", return_value=engine):
        assert check_database_health() is False


def test_database_health_check_missing_credentials() -> None:
    """Return False when database credentials are unavailable."""
    with patch(
        "app.core.database.get_engine",
        side_effect=ValueError("Database password is not configured"),
    ):
        assert check_database_health() is False


def test_database_health_check_unexpected_result() -> None:
    """Return False when the database returns an unexpected result."""
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalar.return_value = None

    with patch("app.core.database.get_engine", return_value=engine):
        assert check_database_health() is False
