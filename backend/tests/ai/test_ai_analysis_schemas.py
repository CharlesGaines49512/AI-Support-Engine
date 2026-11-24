import pytest
from pydantic import ValidationError

from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)


def valid_payload() -> dict[str, object]:
    """Return a valid synthetic incident analysis."""
    return {
        "suggested_category": "database",
        "recommended_priority": "high",
        "recommended_severity": "high",
        "summary": "The application cannot connect to its database.",
        "justification": (
            "The reported connection failure prevents normal application operation."
        ),
        "confidence": 0.90,
        "insufficient_evidence": False,
        "missing_information": [],
    }


def test_valid_incident_analysis() -> None:
    result = IncidentAnalysisResult.model_validate(valid_payload())

    assert result.suggested_category == IncidentCategory.DATABASE
    assert result.recommended_priority == IncidentPriority.HIGH
    assert result.recommended_severity == IncidentSeverity.HIGH
    assert result.confidence == 0.90
    assert result.insufficient_evidence is False
    assert result.missing_information == []


@pytest.mark.parametrize(
    "category",
    list(IncidentCategory),
)
def test_supported_categories(
    category: IncidentCategory,
) -> None:
    payload = valid_payload()
    payload["suggested_category"] = category

    if category == IncidentCategory.UNKNOWN:
        payload["insufficient_evidence"] = True
        payload["missing_information"] = ["Application error details"]

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.suggested_category == category


@pytest.mark.parametrize(
    "priority",
    list(IncidentPriority),
)
def test_supported_priorities(
    priority: IncidentPriority,
) -> None:
    payload = valid_payload()
    payload["recommended_priority"] = priority

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.recommended_priority == priority


@pytest.mark.parametrize(
    "severity",
    list(IncidentSeverity),
)
def test_supported_severities(
    severity: IncidentSeverity,
) -> None:
    payload = valid_payload()
    payload["recommended_severity"] = severity

    if severity == IncidentSeverity.UNKNOWN:
        payload["insufficient_evidence"] = True
        payload["missing_information"] = ["Number of affected users"]

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.recommended_severity == severity


@pytest.mark.parametrize(
    "confidence",
    [0.0, 0.5, 1.0],
)
def test_valid_confidence(
    confidence: float,
) -> None:
    payload = valid_payload()
    payload["confidence"] = confidence

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.confidence == confidence


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("suggested_category", "invalid"),
        ("recommended_priority", "invalid"),
        ("recommended_severity", "invalid"),
        ("summary", ""),
        ("summary", "   "),
        ("summary", "x" * 2001),
        ("justification", ""),
        ("justification", "   "),
        ("justification", "x" * 3001),
        ("confidence", -0.01),
        ("confidence", 1.01),
        ("confidence", float("inf")),
        ("confidence", float("-inf")),
        ("confidence", float("nan")),
        ("insufficient_evidence", "invalid"),
        ("missing_information", [""]),
        ("missing_information", ["   "]),
        ("missing_information", ["x" * 501]),
        ("missing_information", ["item"] * 11),
        ("unexpected_field", "invalid"),
    ],
)
def test_invalid_analysis(
    field: str,
    value: object,
) -> None:
    payload = valid_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        IncidentAnalysisResult.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    list(valid_payload()),
)
def test_required_analysis_fields(
    field: str,
) -> None:
    payload = valid_payload()
    del payload[field]

    with pytest.raises(ValidationError):
        IncidentAnalysisResult.model_validate(payload)


def test_insufficient_evidence() -> None:
    payload = valid_payload()
    payload["suggested_category"] = "unknown"
    payload["recommended_priority"] = None
    payload["recommended_severity"] = "unknown"
    payload["confidence"] = 0.10
    payload["insufficient_evidence"] = True
    payload["missing_information"] = [
        "Application error message",
        "Affected users",
        "Business impact",
    ]

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.insufficient_evidence is True
    assert result.suggested_category == IncidentCategory.UNKNOWN
    assert result.recommended_priority is None
    assert result.recommended_severity == IncidentSeverity.UNKNOWN
    assert len(result.missing_information) == 3


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("suggested_category", "unknown"),
        ("recommended_priority", None),
        ("recommended_severity", "unknown"),
    ],
)
def test_unknown_without_uncertainty(
    field: str,
    value: object,
) -> None:
    payload = valid_payload()
    payload[field] = value

    with pytest.raises(
        ValidationError,
        match="Unknown recommendations",
    ):
        IncidentAnalysisResult.model_validate(payload)


def test_insufficient_evidence_requires_details() -> None:
    payload = valid_payload()
    payload["insufficient_evidence"] = True

    with pytest.raises(
        ValidationError,
        match="requires missing information",
    ):
        IncidentAnalysisResult.model_validate(payload)


def test_partial_recommendations() -> None:
    payload = valid_payload()
    payload["recommended_priority"] = None
    payload["insufficient_evidence"] = True
    payload["missing_information"] = ["Incident business impact"]

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.suggested_category == IncidentCategory.DATABASE
    assert result.recommended_priority is None


def test_analysis_strips_whitespace() -> None:
    payload = valid_payload()
    payload["summary"] = "  Database unavailable.  "
    payload["justification"] = "  Connection failed.  "
    payload["missing_information"] = ["  Database error code  "]

    result = IncidentAnalysisResult.model_validate(payload)

    assert result.summary == "Database unavailable."
    assert result.justification == "Connection failed."
    assert result.missing_information == ["Database error code"]


def test_analysis_serialization() -> None:
    result = IncidentAnalysisResult.model_validate(valid_payload())

    restored = IncidentAnalysisResult.model_validate_json(result.model_dump_json())

    assert restored == result


def test_analysis_is_frozen() -> None:
    result = IncidentAnalysisResult.model_validate(valid_payload())

    with pytest.raises(ValidationError):
        result.confidence = 0.5  # type: ignore[misc]


def test_structured_output_json_schema() -> None:
    schema = IncidentAnalysisResult.model_json_schema()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False

    assert set(schema["required"]) == {
        "suggested_category",
        "recommended_priority",
        "recommended_severity",
        "summary",
        "justification",
        "confidence",
        "insufficient_evidence",
        "missing_information",
    }
