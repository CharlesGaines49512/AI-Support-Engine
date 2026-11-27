from typing import get_args, get_origin
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api import log_dependencies
from app.api.log_dependencies import (
    LogIngestionDependency,
    LogQueryDependency,
    get_log_ingestion_service,
    get_log_query_service,
)
from app.core.config import Settings
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService


@pytest.fixture
def settings() -> Settings:
    return Settings(
        log_max_payload_bytes=4096,
        log_max_entries=50,
        log_max_evidence_entries=5,
        log_max_evidence_chars=2000,
    )


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        autoflush=False,
        expire_on_commit=False,
    )


@pytest.fixture
def configured_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> tuple[Mock, Mock]:
    settings_provider = Mock(
        return_value=settings,
    )

    session_provider = Mock(
        return_value=session_factory,
    )

    monkeypatch.setattr(
        log_dependencies,
        "get_settings",
        settings_provider,
    )

    monkeypatch.setattr(
        log_dependencies,
        "get_session_factory",
        session_provider,
    )

    return settings_provider, session_provider


def test_ingestion_dependency_returns_service(
    configured_dependencies: tuple[Mock, Mock],
) -> None:
    service = get_log_ingestion_service()

    assert isinstance(
        service,
        LogIngestionService,
    )

    settings_provider, session_provider = configured_dependencies

    settings_provider.assert_called_once_with()
    session_provider.assert_called_once_with()


def test_query_dependency_returns_service(
    configured_dependencies: tuple[Mock, Mock],
) -> None:
    service = get_log_query_service()

    assert isinstance(
        service,
        LogQueryService,
    )

    settings_provider, session_provider = configured_dependencies

    settings_provider.assert_called_once_with()
    session_provider.assert_called_once_with()


def test_ingestion_dependency_passes_configuration(
    monkeypatch: pytest.MonkeyPatch,
    configured_dependencies: tuple[Mock, Mock],
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> None:
    constructor = MagicMock(
        spec=LogIngestionService,
    )

    monkeypatch.setattr(
        log_dependencies,
        "LogIngestionService",
        constructor,
    )

    service = get_log_ingestion_service()

    constructor.assert_called_once_with(
        session_factory=session_factory,
        settings=settings,
    )

    assert service is constructor.return_value


def test_query_dependency_passes_configuration(
    monkeypatch: pytest.MonkeyPatch,
    configured_dependencies: tuple[Mock, Mock],
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> None:
    constructor = MagicMock(
        spec=LogQueryService,
    )

    monkeypatch.setattr(
        log_dependencies,
        "LogQueryService",
        constructor,
    )

    service = get_log_query_service()

    constructor.assert_called_once_with(
        session_factory=session_factory,
        settings=settings,
    )

    assert service is constructor.return_value


def test_ingestion_dependency_creates_independent_services(
    configured_dependencies: tuple[Mock, Mock],
) -> None:
    first = get_log_ingestion_service()
    second = get_log_ingestion_service()

    assert first is not second

    settings_provider, session_provider = configured_dependencies

    assert settings_provider.call_count == 2
    assert session_provider.call_count == 2


def test_query_dependency_creates_independent_services(
    configured_dependencies: tuple[Mock, Mock],
) -> None:
    first = get_log_query_service()
    second = get_log_query_service()

    assert first is not second

    settings_provider, session_provider = configured_dependencies

    assert settings_provider.call_count == 2
    assert session_provider.call_count == 2


def test_ingestion_dependency_annotation() -> None:
    assert get_origin(LogIngestionDependency) is not None

    service_type, dependency = get_args(LogIngestionDependency)

    assert service_type is LogIngestionService

    assert dependency.dependency is get_log_ingestion_service


def test_query_dependency_annotation() -> None:
    assert get_origin(LogQueryDependency) is not None

    service_type, dependency = get_args(LogQueryDependency)

    assert service_type is LogQueryService

    assert dependency.dependency is get_log_query_service


@pytest.fixture
def dependency_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ingestion")
    def ingestion_endpoint(
        service: LogIngestionDependency,
    ) -> dict[str, str]:
        return {
            "service": type(service).__name__,
        }

    @app.get("/query")
    def query_endpoint(
        service: LogQueryDependency,
    ) -> dict[str, str]:
        return {
            "service": type(service).__name__,
        }

    return app


@pytest.mark.parametrize(
    ("endpoint", "service_name"),
    [
        ("/ingestion", "LogIngestionService"),
        ("/query", "LogQueryService"),
    ],
)
def test_fastapi_resolves_log_dependencies(
    dependency_app: FastAPI,
    configured_dependencies: tuple[Mock, Mock],
    endpoint: str,
    service_name: str,
) -> None:
    with TestClient(dependency_app) as client:
        response = client.get(endpoint)

    assert response.status_code == 200

    assert response.json() == {
        "service": service_name,
    }

    settings_provider, session_provider = configured_dependencies

    settings_provider.assert_called_once_with()
    session_provider.assert_called_once_with()


def test_fastapi_ingestion_dependency_override(
    dependency_app: FastAPI,
    configured_dependencies: tuple[Mock, Mock],
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> None:
    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    override = Mock(return_value=service)

    dependency_app.dependency_overrides[get_log_ingestion_service] = lambda: override()

    try:
        with TestClient(dependency_app) as client:
            response = client.get("/ingestion")

        assert response.status_code == 200

        assert response.json() == {
            "service": "LogIngestionService",
        }

        override.assert_called_once_with()

        settings_provider, session_provider = configured_dependencies

        settings_provider.assert_not_called()
        session_provider.assert_not_called()

    finally:
        dependency_app.dependency_overrides.clear()


def test_fastapi_query_dependency_override(
    dependency_app: FastAPI,
    configured_dependencies: tuple[Mock, Mock],
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> None:
    service = LogQueryService(
        session_factory=session_factory,
        settings=settings,
    )

    override = Mock(return_value=service)

    dependency_app.dependency_overrides[get_log_query_service] = lambda: override()

    try:
        with TestClient(dependency_app) as client:
            response = client.get("/query")

        assert response.status_code == 200

        assert response.json() == {
            "service": "LogQueryService",
        }

        override.assert_called_once_with()

        settings_provider, session_provider = configured_dependencies

        settings_provider.assert_not_called()
        session_provider.assert_not_called()

    finally:
        dependency_app.dependency_overrides.clear()


def test_dependency_resolution_does_not_open_database_session(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
) -> None:
    factory = MagicMock(spec=sessionmaker)

    monkeypatch.setattr(
        log_dependencies,
        "get_session_factory",
        lambda: factory,
    )

    monkeypatch.setattr(
        log_dependencies,
        "get_settings",
        lambda: settings,
    )

    ingestion = get_log_ingestion_service()
    query = get_log_query_service()

    assert isinstance(
        ingestion,
        LogIngestionService,
    )

    assert isinstance(
        query,
        LogQueryService,
    )

    factory.assert_not_called()


def test_dependency_resolution_propagates_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    monkeypatch.setattr(
        log_dependencies,
        "get_session_factory",
        lambda: session_factory,
    )

    def unavailable_settings() -> Settings:
        raise RuntimeError("Synthetic configuration failure.")

    monkeypatch.setattr(
        log_dependencies,
        "get_settings",
        unavailable_settings,
    )

    with pytest.raises(
        RuntimeError,
        match="Synthetic configuration failure",
    ):
        get_log_ingestion_service()

    with pytest.raises(
        RuntimeError,
        match="Synthetic configuration failure",
    ):
        get_log_query_service()
