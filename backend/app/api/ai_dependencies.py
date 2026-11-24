from typing import Annotated

from fastapi import Depends

from app.api.dependencies import DatabaseSession
from app.core.config import get_settings
from app.core.database import get_session_factory
from app.services.ai_analysis_query import AIAnalysisQueryService
from app.services.persistent_ai_analysis import (
    PersistentAIAnalysisService,
)


def get_ai_analysis_query_service(
    session: DatabaseSession,
) -> AIAnalysisQueryService:
    """Provide the AI analysis query service."""
    return AIAnalysisQueryService(session)


def get_persistent_ai_analysis_service() -> PersistentAIAnalysisService:
    """Provide the persistent AI analysis service."""
    return PersistentAIAnalysisService(
        session_factory=get_session_factory(),
        settings=get_settings(),
    )


AIAnalysisQueryDependency = Annotated[
    AIAnalysisQueryService,
    Depends(get_ai_analysis_query_service),
]

PersistentAIAnalysisDependency = Annotated[
    PersistentAIAnalysisService,
    Depends(get_persistent_ai_analysis_service),
]
