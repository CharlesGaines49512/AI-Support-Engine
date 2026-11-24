from sqlalchemy import Engine, inspect, text


def test_postgresql_connection(
    integration_engine: Engine,
) -> None:
    """Verify connectivity to the isolated PostgreSQL database."""
    with integration_engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1


def test_postgresql_database_isolation(
    integration_engine: Engine,
) -> None:
    """Prevent tests from targeting the development database."""
    with integration_engine.connect() as connection:
        database = connection.execute(text("SELECT current_database()")).scalar_one()

        assert database == "ai_support_engine_migration_test"


def test_pgvector_extension(
    integration_engine: Engine,
) -> None:
    """Verify that the vector extension is installed."""
    with integration_engine.connect() as connection:
        version = connection.execute(
            text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        ).scalar_one()

        assert version


def test_pgvector_distance(
    integration_engine: Engine,
) -> None:
    """Verify PostgreSQL vector distance calculations."""
    with integration_engine.connect() as connection:
        distance = connection.execute(
            text("SELECT '[1,2,3]'::vector <-> '[1,2,3]'::vector")
        ).scalar_one()

        assert distance == 0


def test_incidents_table_exists(
    integration_engine: Engine,
) -> None:
    """Verify that incident database migrations are applied."""
    inspector = inspect(integration_engine)

    assert inspector.has_table("incidents")


def test_alembic_revision(
    integration_engine: Engine,
) -> None:
    """Verify the current database migration revision."""
    with integration_engine.connect() as connection:
        revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()

        assert revision == "421c4f9ba04a"
