from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def get_database_url() -> URL:
    """Construct a secure PostgreSQL connection URL."""
    settings = get_settings()

    password = settings.postgres_password.get_secret_value()

    if not password:
        raise ValueError("Database password is not configured.")

    return URL.create(
        drivername="postgresql+psycopg",
        username=settings.postgres_user,
        password=password,
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Create and cache the SQLAlchemy database engine."""
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,
        echo=False,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    """Create and cache the database session factory."""
    return sessionmaker(
        bind=get_engine(),
        autoflush=False,
        expire_on_commit=False,
    )


def get_db() -> Generator[Session]:
    """Provide a database session and ensure proper cleanup."""
    session = get_session_factory()()

    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_database_health() -> bool:
    """Check whether PostgreSQL is available."""
    try:
        with get_engine().connect() as connection:
            return connection.execute(text("SELECT 1")).scalar() == 1
    except SQLAlchemyError, ValueError:
        return False
