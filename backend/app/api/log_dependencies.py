from typing import Annotated

from fastapi import Depends

from app.core.config import get_settings
from app.core.database import get_session_factory
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService


def get_log_ingestion_service() -> LogIngestionService:
    """Provide the application log ingestion service."""

    return LogIngestionService(
        session_factory=get_session_factory(),
        settings=get_settings(),
    )


def get_log_query_service() -> LogQueryService:
    """Provide the incident-scoped application log query service."""

    return LogQueryService(
        session_factory=get_session_factory(),
        settings=get_settings(),
    )


LogIngestionDependency = Annotated[
    LogIngestionService,
    Depends(get_log_ingestion_service),
]


LogQueryDependency = Annotated[
    LogQueryService,
    Depends(get_log_query_service),
]
