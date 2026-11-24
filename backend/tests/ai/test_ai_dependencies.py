from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.api.ai_dependencies import (
    get_ai_analysis_query_service,
    get_persistent_ai_analysis_service,
)
from app.core.config import Settings
from app.services.ai_analysis_query import AIAnalysisQueryService
from app.services.persistent_ai_analysis import (
    PersistentAIAnalysisService,
)


def test_query_service_dependency() -> None:
    session = MagicMock(spec=Session)

    service = get_ai_analysis_query_service(session)

    assert isinstance(service, AIAnalysisQueryService)


def test_persistent_service_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(ai_enabled=False)
    session_factory = MagicMock()

    settings_mock = MagicMock(return_value=settings)
    factory_mock = MagicMock(return_value=session_factory)

    monkeypatch.setattr(
        "app.api.ai_dependencies.get_settings",
        settings_mock,
    )

    monkeypatch.setattr(
        "app.api.ai_dependencies.get_session_factory",
        factory_mock,
    )

    service = get_persistent_ai_analysis_service()

    assert isinstance(service, PersistentAIAnalysisService)

    settings_mock.assert_called_once_with()
    factory_mock.assert_called_once_with()

    session_factory.assert_not_called()
