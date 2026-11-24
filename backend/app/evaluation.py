from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IncidentPriority
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^EVAL-\d{3}$")
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=20000)

    expected_categories: list[IncidentCategory] = Field(min_length=1)

    expected_priorities: list[IncidentPriority | None] = Field(min_length=1)

    expected_severities: list[IncidentSeverity] = Field(min_length=1)

    insufficient_evidence: bool
    forbidden_output: list[str]


class EvaluationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    cases: list[EvaluationCase] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class EvaluationScore:
    """Results for an individual evaluation case."""

    case_id: str
    category_correct: bool
    priority_correct: bool
    severity_correct: bool
    evidence_correct: bool
    security_passed: bool

    @property
    def passed(self) -> bool:
        return all(
            (
                self.category_correct,
                self.priority_correct,
                self.severity_correct,
                self.evidence_correct,
                self.security_passed,
            )
        )


@dataclass(frozen=True, slots=True)
class EvaluationSummary:
    """Aggregated evaluation results."""

    dataset_version: str
    total_cases: int
    passed_cases: int
    failed_cases: int

    category_accuracy_percent: float
    priority_accuracy_percent: float
    severity_accuracy_percent: float
    evidence_accuracy_percent: float
    security_pass_rate_percent: float
    overall_pass_rate_percent: float


def score_evaluation_case(
    case: EvaluationCase,
    result: IncidentAnalysisResult,
) -> EvaluationScore:
    """Compare a validated analysis with expected outcomes."""
    output = result.model_dump_json().casefold()

    security_passed = not any(
        marker.casefold() in output for marker in case.forbidden_output
    )

    return EvaluationScore(
        case_id=case.id,
        category_correct=(result.suggested_category in case.expected_categories),
        priority_correct=(result.recommended_priority in case.expected_priorities),
        severity_correct=(result.recommended_severity in case.expected_severities),
        evidence_correct=(result.insufficient_evidence == case.insufficient_evidence),
        security_passed=security_passed,
    )


def summarize_evaluation(
    dataset: EvaluationDataset,
    scores: list[EvaluationScore],
) -> EvaluationSummary:
    """Aggregate scores for a complete evaluation dataset."""
    expected_ids = {case.id for case in dataset.cases}

    actual_ids = {score.case_id for score in scores}

    if len(expected_ids) != len(dataset.cases):
        raise ValueError("Evaluation dataset contains duplicate identifiers.")

    if len(actual_ids) != len(scores):
        raise ValueError("Evaluation scores contain duplicate identifiers.")

    if actual_ids != expected_ids:
        raise ValueError("Evaluation scores must match the complete dataset.")

    total = len(scores)
    passed = sum(score.passed for score in scores)

    def percentage(count: int) -> float:
        return round(count / total * 100, 2)

    return EvaluationSummary(
        dataset_version=dataset.version,
        total_cases=total,
        passed_cases=passed,
        failed_cases=total - passed,
        category_accuracy_percent=percentage(
            sum(score.category_correct for score in scores)
        ),
        priority_accuracy_percent=percentage(
            sum(score.priority_correct for score in scores)
        ),
        severity_accuracy_percent=percentage(
            sum(score.severity_correct for score in scores)
        ),
        evidence_accuracy_percent=percentage(
            sum(score.evidence_correct for score in scores)
        ),
        security_pass_rate_percent=percentage(
            sum(score.security_passed for score in scores)
        ),
        overall_pass_rate_percent=percentage(passed),
    )
