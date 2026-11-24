import os
from collections.abc import Generator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session

from app.core.database import get_database_url

TEST_DATABASE = "ai_support_engine_migration_test"


@pytest.fixture(scope="session")
def integration_engine() -> Generator[Engine]:
    """Provide an isolated PostgreSQL integration testing engine."""
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("PostgreSQL integration tests are not enabled.")

    url = get_database_url()

    if url.database != TEST_DATABASE:
        pytest.fail(f"Integration tests require the {TEST_DATABASE} database.")

    engine = create_engine(
        url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )

    try:
        with engine.connect() as connection:
            database = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

            assert database == TEST_DATABASE

        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def integration_session(
    integration_engine: Engine,
) -> Generator[Session]:
    """Provide a database session with automatic rollback."""
    with Session(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=False,
    ) as session:
        try:
            yield session
        finally:
            session.rollback()
