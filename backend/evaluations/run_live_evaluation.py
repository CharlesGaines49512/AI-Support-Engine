import argparse
import asyncio
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.evaluation import (
    EvaluationDataset,
    EvaluationScore,
    score_evaluation_case,
    summarize_evaluation,
)
from app.integrations.ai.exceptions import AIProviderError
from app.integrations.ai.factory import create_ai_provider
from app.prompts import INCIDENT_ANALYSIS_PROMPT_VERSION
from app.services.ai_analysis import IncidentAnalysisService

DATASET_PATH = Path(__file__).resolve().parent / "incident_cases.json"


async def run_evaluation(
    *,
    smoke: bool,
    allow_paid: bool,
) -> int:
    if not allow_paid:
        print("Live evaluation requires --allow-paid.")
        return 1

    settings = get_settings().model_copy(
        update={
            "ai_enabled": True,
            "ai_max_retries": 0,
        }
    )

    if not settings.openai_api_key.get_secret_value():
        print("ERROR: API key is not configured.")
        return 1

    dataset = EvaluationDataset.model_validate_json(
        DATASET_PATH.read_text(encoding="utf-8-sig")
    )

    if smoke:
        dataset = EvaluationDataset(
            version=dataset.version,
            cases=dataset.cases[:1],
        )

    print("Model:", settings.ai_model)
    print("Dataset:", dataset.version)
    print("Cases:", len(dataset.cases))
    print("Automatic retries: disabled")
    print("Prompt version:", INCIDENT_ANALYSIS_PROMPT_VERSION)

    scores: list[EvaluationScore] = []
    records: list[dict[str, object]] = []

    provider = create_ai_provider(settings)

    service = IncidentAnalysisService(
        provider,
        max_input_chars=settings.ai_max_input_chars,
    )

    try:
        for case in dataset.cases:
            try:
                execution = await service.analyze(
                    title=case.title,
                    description=case.description,
                )

            except AIProviderError as error:
                print(f"{case.id}: PROVIDER FAILURE ({type(error).__name__})")

                score = EvaluationScore(
                    case_id=case.id,
                    category_correct=False,
                    priority_correct=False,
                    severity_correct=False,
                    evidence_correct=False,
                    security_passed=False,
                )

                scores.append(score)

                records.append(
                    {
                        "case_id": case.id,
                        "execution_status": "failed",
                        "error_type": type(error).__name__,
                        "score": asdict(score),
                    }
                )

                continue

            response = execution.response

            score = score_evaluation_case(
                case,
                response.data,
            )

            scores.append(score)

            records.append(
                {
                    "case_id": case.id,
                    "execution_status": "completed",
                    "model": response.model,
                    "prompt_version": response.prompt_version,
                    "score": asdict(score),
                    "category": (response.data.suggested_category.value),
                    "priority": (
                        response.data.recommended_priority.value
                        if response.data.recommended_priority is not None
                        else None
                    ),
                    "severity": (response.data.recommended_severity.value),
                    "confidence": response.data.confidence,
                    "insufficient_evidence": (response.data.insufficient_evidence),
                    "usage": response.usage.model_dump(mode="json"),
                    "latency_ms": response.latency_ms,
                    "redaction_count": execution.redaction_count,
                }
            )

            outcome = "PASS" if score.passed else "FAIL"

            print(
                f"{case.id}: {outcome} | "
                f"category={response.data.suggested_category.value} | "
                f"latency={response.latency_ms:.0f} ms"
            )

    finally:
        await provider.close()

    summary = summarize_evaluation(
        dataset,
        scores,
    )

    report = {
        "executed_at": datetime.now(UTC).isoformat(),
        "evaluation_mode": "smoke" if smoke else "full",
        "configured_model": settings.ai_model,
        "prompt_version": INCIDENT_ANALYSIS_PROMPT_VERSION,
        "summary": asdict(summary),
        "cases": records,
    }

    report_path = DATASET_PATH.parent / (
        "live_smoke_results.json" if smoke else "live_evaluation_results.json"
    )

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print()
    print("EVALUATION SUMMARY")
    print(json.dumps(asdict(summary), indent=2))
    print("Report saved:", report_path.name)

    return 0 if summary.failed_cases == 0 else 2


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--allow-paid",
        action="store_true",
        help="Explicitly permit live API requests.",
    )

    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Evaluate only the first synthetic incident.",
    )

    args = parser.parse_args()

    return asyncio.run(
        run_evaluation(
            smoke=args.smoke,
            allow_paid=args.allow_paid,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
