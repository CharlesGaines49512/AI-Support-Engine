# AI Incident Analysis Evaluation

## Overview

This evaluation suite provides a repeatable synthetic benchmark
for comparing AI incident analysis models and prompt versions.

## Evaluation Components

- incident_cases.json: Versioned dataset containing 16 synthetic cases.
- run_live_evaluation.py: Controlled live evaluation runner.
- Automated dataset validation and scoring tests.

## Evaluation Dimensions

- Incident category agreement.
- Priority agreement.
- Severity agreement.
- Insufficient-evidence handling.
- Security canary compliance.
- Overall case pass rate.

## Offline Testing

Run the following command from the repository root:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend/tests/ai/test_ai_evaluation.py backend/tests/ai/test_ai_evaluation_dataset.py -v
```

The offline evaluation tests do not require an API key
or consume API credits.

## Paid Request Protection

The live evaluation runner requires explicit authorization
before making external API requests.

```powershell
.\backend\.venv\Scripts\python.exe backend/evaluations/run_live_evaluation.py
```

Without the --allow-paid flag, the runner terminates without
making a provider request.

## Optional Live Evaluation

Live testing requires a configured API key, available API
credits, and a supported model.

Single-case smoke test:

```powershell
.\backend\.venv\Scripts\python.exe backend/evaluations/run_live_evaluation.py --allow-paid --smoke
```

Full benchmark:

```powershell
.\backend\.venv\Scripts\python.exe backend/evaluations/run_live_evaluation.py --allow-paid
```

Review the smoke test before running the complete benchmark.

Automatic retries are disabled during live evaluation.

## Proposed Benchmark Targets

| Metric | Target |
| --- | --- |
| Category agreement | At least 90% |
| Priority agreement | At least 90% |
| Severity agreement | At least 90% |
| Insufficient-evidence handling | 100% |
| Security canary compliance | 100% |
| Overall case pass rate | At least 85% |

These targets are not measured results.

## Verification Status

- Dataset validation: passed.
- Automated scoring tests: passed.
- SDK transport verification: passed.
- Live provider evaluation: deferred.

Paid API access has not been configured.

No live model accuracy, latency, or billing measurements
are claimed.

## Limitations

The dataset is synthetic, small, and manually labeled.

Benchmark agreement does not establish comprehensive factual
accuracy, security, remediation effectiveness, or confidence
calibration.

Generated evaluation reports are excluded from source control.

Evaluation failures should be investigated rather than changing
expected outcomes solely to obtain passing results.
