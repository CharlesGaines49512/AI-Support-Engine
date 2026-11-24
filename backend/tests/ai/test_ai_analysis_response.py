import json
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.ai_analysis import AIAnalysis
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentCategory,
    IncidentSeverity,
)
from app.schemas.ai_analysis_response import AIAnalysisResponse


@pytest.fixture
def successful_analysis() -> AIAnalysis:
    return AIAnalysis(
        id=uuid4(),
        incident_id=uuid4(),
        status=AIAnalysisStatus.SUCCEEDED,
        suggested_category="database",
        recommended_priority="high",
        recommended_severity="high",
        summary="Database connectivity failure.",
        justification="The database connection timed out.",
        confidence=0.90,
        insufficient_evidence=False,
        missing_information=[],
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        request_id="req_synthetic_analysis",
        input_tokens=1000,
        output_tokens=200,
        total_tokens=1200,
        cached_input_tokens=100,
        estimated_cost_usd=Decimal("0.0012345678"),
        latency_ms=250.0,
        redaction_count=0,
        input_characters=3000,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def failed_analysis() -> AIAnalysis:
    return AIAnalysis(
        id=uuid4(),
        incident_id=uuid4(),
        status=AIAnalysisStatus.FAILED,
        provider="openai",
        model="synthetic-model",
        prompt_version="1.0.0",
        error_code="provider_timeout",
        error_message="The AI request timed out.",
        latency_ms=30000.0,
        created_at=datetime.now(UTC),
    )


def test_successful_analysis_response(
    successful_analysis: AIAnalysis,
) -> None:
    response = AIAnalysisResponse.model_validate(successful_analysis)

    assert response.id == successful_analysis.id
    assert response.incident_id == (successful_analysis.incident_id)

    assert response.status == AIAnalysisStatus.SUCCEEDED
    assert response.suggested_category == IncidentCategory.DATABASE
    assert response.recommended_priority == IncidentPriority.HIGH
    assert response.recommended_severity == IncidentSeverity.HIGH

    assert response.summary == successful_analysis.summary
    assert response.justification == (successful_analysis.justification)

    assert response.confidence == 0.90
    assert response.insufficient_evidence is False
    assert response.missing_information == []
    assert response.error_code is None
    assert response.error_message is None


def test_failed_analysis_response(
    failed_analysis: AIAnalysis,
) -> None:
    response = AIAnalysisResponse.model_validate(failed_analysis)

    assert response.status == AIAnalysisStatus.FAILED
    assert response.error_code == "provider_timeout"
    assert response.error_message == ("The AI request timed out.")

    assert response.suggested_category is None
    assert response.recommended_priority is None
    assert response.recommended_severity is None
    assert response.summary is None
    assert response.justification is None
    assert response.confidence is None
    assert response.insufficient_evidence is None
    assert response.missing_information is None
    assert response.total_tokens is None
    assert response.estimated_cost_usd is None


def test_operational_metadata_response(
    successful_analysis: AIAnalysis,
) -> None:
    response = AIAnalysisResponse.model_validate(successful_analysis)

    assert response.provider == "openai"
    assert response.model == "synthetic-model"
    assert response.prompt_version == "1.0.0"
    assert response.request_id == "req_synthetic_analysis"
    assert response.input_tokens == 1000
    assert response.output_tokens == 200
    assert response.total_tokens == 1200
    assert response.cached_input_tokens == 100

    assert response.estimated_cost_usd == Decimal("0.0012345678")

    assert response.latency_ms == 250.0
    assert response.redaction_count == 0
    assert response.input_characters == 3000
    assert response.created_at.tzinfo is not None


def test_unknown_recommendations_response(
    successful_analysis: AIAnalysis,
) -> None:
    successful_analysis.suggested_category = "unknown"
    successful_analysis.recommended_priority = None
    successful_analysis.recommended_severity = "unknown"
    successful_analysis.insufficient_evidence = True

    successful_analysis.missing_information = ["Number of affected users"]

    response = AIAnalysisResponse.model_validate(successful_analysis)

    assert response.suggested_category == IncidentCategory.UNKNOWN
    assert response.recommended_priority is None
    assert response.recommended_severity == IncidentSeverity.UNKNOWN
    assert response.insufficient_evidence is True

    assert response.missing_information == ["Number of affected users"]


def test_unknown_usage_remains_null(
    successful_analysis: AIAnalysis,
) -> None:
    successful_analysis.input_tokens = None
    successful_analysis.output_tokens = None
    successful_analysis.total_tokens = None
    successful_analysis.cached_input_tokens = None
    successful_analysis.estimated_cost_usd = None

    response = AIAnalysisResponse.model_validate(successful_analysis)

    assert response.input_tokens is None
    assert response.output_tokens is None
    assert response.total_tokens is None
    assert response.cached_input_tokens is None
    assert response.estimated_cost_usd is None


def test_response_json_serialization(
    successful_analysis: AIAnalysis,
) -> None:
    response = AIAnalysisResponse.model_validate(successful_analysis)

    payload = json.loads(response.model_dump_json())

    assert payload["id"] == str(successful_analysis.id)
    assert payload["incident_id"] == str(successful_analysis.incident_id)

    assert payload["status"] == "succeeded"
    assert payload["suggested_category"] == "database"
    assert payload["recommended_priority"] == "high"
    assert payload["recommended_severity"] == "high"
    assert payload["estimated_cost_usd"] == "0.0012345678"

    assert payload["created_at"]


def test_response_excludes_internal_attributes(
    successful_analysis: AIAnalysis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        successful_analysis,
        "internal_secret",
        "synthetic-private-value",
        raising=False,
    )

    response = AIAnalysisResponse.model_validate(successful_analysis)

    payload = response.model_dump()

    assert "internal_secret" not in payload
    assert "_sa_instance_state" not in payload
    assert "system_prompt" not in payload
    assert "user_prompt" not in payload
    assert "openai_api_key" not in payload
    assert "synthetic-private-value" not in (response.model_dump_json())


@pytest.mark.parametrize(
    "confidence",
    [-0.01, 1.01, float("nan"), float("inf")],
)
def test_invalid_confidence_rejected(
    successful_analysis: AIAnalysis,
    confidence: float,
) -> None:
    successful_analysis.confidence = confidence

    with pytest.raises(ValidationError):
        AIAnalysisResponse.model_validate(successful_analysis)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_tokens", -1),
        ("output_tokens", -1),
        ("total_tokens", -1),
        ("cached_input_tokens", -1),
        ("estimated_cost_usd", Decimal("-0.01")),
        ("latency_ms", -1.0),
        ("latency_ms", float("inf")),
        ("redaction_count", -1),
        ("input_characters", 0),
        ("suggested_category", "unsupported"),
        ("recommended_priority", "unsupported"),
        ("recommended_severity", "unsupported"),
        ("status", "unsupported"),
    ],
)
def test_invalid_response_metadata_rejected(
    successful_analysis: AIAnalysis,
    field: str,
    value: object,
) -> None:
    setattr(successful_analysis, field, value)

    with pytest.raises(ValidationError):
        AIAnalysisResponse.model_validate(successful_analysis)


def test_response_json_schema() -> None:
    schema = AIAnalysisResponse.model_json_schema()

    properties = schema["properties"]

    assert len(properties) == 26
    assert "id" in properties
    assert "incident_id" in properties
    assert "status" in properties
    assert "created_at" in properties

    assert "openai_api_key" not in properties
    assert "system_prompt" not in properties
    assert "user_prompt" not in properties

    assert len(schema["required"]) == 26
