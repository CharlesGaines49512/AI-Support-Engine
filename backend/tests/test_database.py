from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.database import (
    get_database_url,
    get_db,
    get_engine,
    get_session_factory,
)


@pytest.fixture(autouse=True)
def clear_database_caches() -> None:
    """Clear cached database objects before each test."""
    get_session_factory.cache_clear()
    get_engine.cache_clear()


def test_database_url_configuration() -> None:
    """Verify database URL construction."""
    settings = Settings(
        _env_file=None,
        postgres_db="test_database",
        postgres_user="test_user",
        postgres_password=SecretStr("test_password"),
        postgres_host="localhost",
        postgres_port=5432,
    )

    with patch("app.core.database.get_settings", return_value=settings):
        url = get_database_url()

    assert url.drivername == "postgresql+psycopg"
    assert url.username == "test_user"
    assert url.password == "test_password"
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "test_database"


def test_database_url_hides_password() -> None:
    """Verify database URL masks credentials."""
    settings = Settings(
        _env_file=None,
        postgres_password=SecretStr("test_password"),
    )

    with patch("app.core.database.get_settings", return_value=settings):
        url = get_database_url()

    assert "test_password" not in str(url)


def test_missing_database_password() -> None:
    """Reject database connections without a password."""
    settings = Settings(
        _env_file=None,
        postgres_password=SecretStr(""),
    )

    with (
        patch("app.core.database.get_settings", return_value=settings),
        pytest.raises(ValueError, match="Database password is not configured"),
    ):
        get_database_url()


def test_engine_is_cached() -> None:
    """Verify that the database engine is reused."""
    mock_engine = MagicMock()

    with (
        patch("app.core.database.get_database_url"),
        patch(
            "app.core.database.create_engine",
            return_value=mock_engine,
        ) as create_engine,
    ):
        try:
            assert get_engine() is get_engine()
            create_engine.assert_called_once()
        finally:
            get_engine.cache_clear()


def test_session_factory_is_cached() -> None:
    """Verify that the session factory is reused."""
    with (
        patch("app.core.database.get_engine"),
        patch("app.core.database.sessionmaker") as factory,
    ):
        try:
            assert get_session_factory() is get_session_factory()
            factory.assert_called_once()
        finally:
            get_session_factory.cache_clear()


def test_database_session_closes_successfully() -> None:
    """Verify that sessions close after successful use."""
    session = MagicMock()

    with patch("app.core.database.get_session_factory") as factory:
        factory.return_value.return_value = session

        generator = get_db()

        assert next(generator) is session

        with pytest.raises(StopIteration):
            next(generator)

    session.close.assert_called_once()
    session.rollback.assert_not_called()


def test_database_session_rolls_back_on_error() -> None:
    """Verify rollback and cleanup after an exception."""
    session = MagicMock()

    with patch("app.core.database.get_session_factory") as factory:
        factory.return_value.return_value = session

        generator = get_db()
        next(generator)

        with pytest.raises(RuntimeError, match="Test failure"):
            generator.throw(RuntimeError("Test failure"))

    session.rollback.assert_called_once()
    session.close.assert_called_once()
