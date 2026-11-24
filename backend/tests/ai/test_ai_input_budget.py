import asyncio
from unittest.mock import AsyncMock

import pytest

from app.integrations.ai.exceptions import (
    AIProviderRequestError,
    AIProviderTimeoutError,
)
from app.prompts import build_incident_analysis_request
from app.security import sanitize_text
from app.services.ai_analysis import IncidentAnalysisService


def calculate_budget(
    title: str,
    description: str,
) -> int:
    request = build_incident_analysis_request(
        title=sanitize_text(title.strip()).text,
        description=sanitize_text(description.strip()).text,
    )

    return len(request.system_prompt) + len(request.user_prompt)


@pytest.mark.parametrize("budget", [0, -1, -100])
def test_invalid_input_budget(budget: int) -> None:
    provider = AsyncMock()

    with pytest.raises(
        ValueError,
        match="Input budget must be positive",
    ):
        IncidentAnalysisService(
            provider,
            max_input_chars=budget,
        )


def test_exact_budget_reaches_provider() -> None:
    title = "Database unavailable"
    description = "Connection timed out."

    provider = AsyncMock()
    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    service = IncidentAnalysisService(
        provider,
        max_input_chars=calculate_budget(
            title,
            description,
        ),
    )

    with pytest.raises(AIProviderTimeoutError):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_awaited_once()


def test_budget_exceeded_by_one_character() -> None:
    title = "Database unavailable"
    description = "Connection timed out."

    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=(calculate_budget(title, description) - 1),
    )

    with pytest.raises(
        AIProviderRequestError,
        match="configured input limit",
    ):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_system_prompt_counts_toward_budget() -> None:
    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=100,
    )

    with pytest.raises(AIProviderRequestError):
        asyncio.run(
            service.analyze(
                title="Error",
                description="Timeout",
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_json_serialization_counts_toward_budget() -> None:
    title = "Synthetic error"
    description = '"quoted"\npath\\directory\tvalue'

    budget = calculate_budget(title, description)

    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=budget - 1,
    )

    with pytest.raises(AIProviderRequestError):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_redaction_expansion_counts_toward_budget() -> None:
    title = "Authentication failure"
    description = "password=x"

    original_request = build_incident_analysis_request(
        title=title,
        description=description,
    )

    original_budget = len(original_request.system_prompt) + len(
        original_request.user_prompt
    )

    assert (
        calculate_budget(
            title,
            description,
        )
        > original_budget
    )

    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=original_budget,
    )

    with pytest.raises(AIProviderRequestError):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_large_valid_incident_rejected_by_budget() -> None:
    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=20000,
    )

    with pytest.raises(
        AIProviderRequestError,
        match="configured input limit",
    ):
        asyncio.run(
            service.analyze(
                title="Synthetic incident",
                description="x" * 20000,
            )
        )

    provider.generate_structured.assert_not_awaited()


def test_normalization_before_budget_calculation() -> None:
    title = "Synthetic incident"
    description = "Connection failed."

    provider = AsyncMock()
    provider.generate_structured.side_effect = AIProviderTimeoutError(
        "Synthetic timeout."
    )

    service = IncidentAnalysisService(
        provider,
        max_input_chars=calculate_budget(
            title,
            description,
        ),
    )

    with pytest.raises(AIProviderTimeoutError):
        asyncio.run(
            service.analyze(
                title=f"  {title}  ",
                description=f"  {description}  ",
            )
        )

    provider.generate_structured.assert_awaited_once()


def test_unicode_input_budget() -> None:
    title = "Synthetic incident"
    description = "Database failure: \u6570\u636e\u5e93"

    provider = AsyncMock()

    service = IncidentAnalysisService(
        provider,
        max_input_chars=(calculate_budget(title, description) - 1),
    )

    with pytest.raises(AIProviderRequestError):
        asyncio.run(
            service.analyze(
                title=title,
                description=description,
            )
        )

    provider.generate_structured.assert_not_awaited()
