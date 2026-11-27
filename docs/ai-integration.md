# AI Integration

## Overview

AI Support Engine provides AI-assisted technical incident analysis
through a modular provider architecture.

The AI integration generates structured recommendations for incident
classification, priority, severity, summary, justification, confidence,
and missing information.

All recommendations are advisory. AI analysis does not automatically
modify incidents, execute remediation actions, or override human
decisions.

## Architecture

The AI analysis workflow consists of:

1. FastAPI REST endpoints.
2. Persistent AI analysis service.
3. Incident repository and incident snapshot.
4. Input sanitization and validation.
5. Versioned prompt construction.
6. Provider-independent AI interface.
7. OpenAI structured-output implementation.
8. Pydantic response validation.
9. Estimated cost calculation.
10. PostgreSQL persistence.
11. Historical retrieval and usage aggregation.

The application separates provider-specific implementation details
from incident management and persistence logic.

External AI requests execute without holding an open database session.

Before persistence, the service reacquires the incident using a
database row lock and checks whether the incident title or description
has changed during analysis.

## Supported Incident Categories

- Authentication
- Authorization
- Database
- Network
- Application
- Integration
- Configuration
- Performance
- Infrastructure
- Security
- Data
- Other
- Unknown

## Structured Analysis

Each successful analysis includes:

- Suggested incident category.
- Recommended priority.
- Recommended severity.
- Incident summary.
- Recommendation justification.
- Self-reported confidence.
- Insufficient-evidence indicator.
- Missing-information recommendations.

Confidence is a model-generated assessment and is not a calibrated
probability of correctness.

When available evidence is insufficient, the response contract
supports unknown classifications and nullable priority recommendations.

## REST API

All endpoints are located under the `/api/v1` prefix.

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /incidents/{incident_id}/analyses | Create an analysis attempt |
| GET | /incidents/{incident_id}/analyses | Retrieve analysis history |
| GET | /incidents/{incident_id}/analyses/latest | Retrieve latest attempt |
| GET | /incidents/{incident_id}/analyses/latest-successful | Retrieve latest successful analysis |
| GET | /incidents/{incident_id}/analyses/{analysis_id} | Retrieve individual analysis |

### Pagination

Analysis history supports:

- offset: Nonnegative integer, default 0.
- limit: Integer between 1 and 100, default 20.
- status: Optional succeeded or failed filter.

Results are ordered by creation time descending, with the analysis
identifier used as a deterministic secondary ordering field.

### HTTP Response Behavior

| Status | Meaning |
| --- | --- |
| 200 | Analysis history or individual analysis retrieved |
| 201 | Analysis attempt successfully persisted |
| 404 | Incident or analysis not found |
| 409 | Incident content changed during analysis |
| 422 | Invalid request parameters |
| 500 | Unexpected internal application failure |

A persisted failed provider attempt returns HTTP 201 because an
analysis attempt resource has been created. Its execution status
indicates failure.

## Persistence

Analysis attempts are stored in the PostgreSQL `ai_analyses` table.

Stored information includes:

- Incident identifier.
- Execution status.
- Structured analysis results.
- Provider and model identifiers.
- Prompt version.
- Provider request identifier when available.
- Token usage.
- Estimated execution cost.
- Recorded execution latency.
- Input character and redaction counts.
- Sanitized failure information.
- Creation timestamp.

Database constraints enforce valid execution states, numeric ranges,
token-count consistency, and relationships between incidents and
analysis records.

Deleting an incident cascades deletion to its associated analyses.

## Security Controls

The AI integration includes:

- Credential-pattern and sensitive-data redaction.
- Input-length validation.
- Configurable prompt character limits.
- Configurable output token limits.
- Structured response validation.
- Instructions treating incident content as untrusted data.
- Sanitization of generated analysis text before persistence.
- Safe provider error translation.
- Incident-scoped historical retrieval.
- Secret-based API key configuration.
- Provider-side storage disabled for analysis requests.

Regex-based sanitization is not a comprehensive data-loss prevention
system. It cannot guarantee detection of every sensitive value.

Prompt injection resistance is not guaranteed.

Disabling provider-side response storage does not establish a
zero-data-retention agreement.

Incident scoping does not replace authentication or authorization.

The application must remain restricted to a trusted local environment
until authentication, authorization, rate limiting, and deployment
security controls are implemented.

## Reliability

The provider abstraction supports configurable request timeouts and
retry limits.

Provider authentication failures, rate limits, connection failures,
timeouts, invalid responses, and other provider errors are translated
into application-specific exceptions.

Expected provider failures can be persisted as failed analysis attempts
without modifying the original incident.

Database write operations include rollback handling.

Historical analyses remain available when subsequent analysis attempts
fail.

Incident content is checked before an analysis is persisted. Full
incident revision tracking and comprehensive concurrent execution
verification remain future improvements.

## Cost Tracking

The application calculates estimated costs using Decimal arithmetic.

Configured model pricing includes:

- Uncached input token price per million tokens.
- Cached input token price per million tokens.
- Output token price per million tokens.

Pricing is applied only when the returned provider and model match
the configured pricing information.

Unknown prices or incomplete required usage metadata produce null
cost estimates rather than misleading zero-cost values.

Invalid cost calculations do not invalidate otherwise successful
analysis results.

Historical stored cost estimates remain unchanged when configured
prices are updated.

Estimates are not authoritative provider billing records and may
exclude charges associated with retries or unsuccessful requests.

Actual provider pricing must be independently verified before use.

## Usage and Performance Metrics

The internal analytics service aggregates:

- Total analysis attempts.
- Successful and failed attempts.
- Success rate.
- Average recorded execution latency.
- Input, output, cached, and total token consumption.
- Known estimated costs.
- Number of analyses with known and unknown costs.
- Sample counts for incomplete usage and latency data.

Aggregation occurs in PostgreSQL rather than loading all analysis
records into application memory.

Metrics support global and incident-specific aggregation.

Global metrics remain internal until appropriate authorization
controls are available.

## Configuration

AI functionality is disabled by default.

The following environment variables control AI behavior:

| Variable | Purpose |
| --- | --- |
| AI_ENABLED | Enable AI functionality |
| AI_PROVIDER | Select the configured AI provider |
| AI_MODEL | Select the requested model |
| OPENAI_API_KEY | Configure the provider credential |
| AI_REQUEST_TIMEOUT | Request timeout |
| AI_MAX_RETRIES | Maximum automatic retries |
| AI_MAX_OUTPUT_TOKENS | Maximum generated tokens |
| AI_MAX_INPUT_CHARS | Maximum prompt character count |
| AI_PRICING_MODEL | Exact model identifier for pricing |
| AI_PRICING_INPUT_USD_PER_MILLION | Input token pricing |
| AI_PRICING_CACHED_INPUT_USD_PER_MILLION | Cached input pricing |
| AI_PRICING_OUTPUT_USD_PER_MILLION | Output token pricing |

Credentials must remain outside source control.

The `.env.example` file documents available configuration without
containing real credentials.

## Automated Verification

Historical Stage 6 local regression results:

- 867 passing automated tests.
- 733 unit, mocked, and SDK transport tests.
- 134 real PostgreSQL integration tests.
- 1,006 covered application statements.
- 100% application statement coverage.
- Regression execution time: 22.28 seconds.

Historical Stage 6 static quality results:

- Ruff linting: passed.
- Ruff formatting: 102 files.
- Strict Mypy validation: 102 source files.
- Python dependency integrity: passed.

Static quality results include the live evaluation runner. Regression
coverage applies to the application package and does not establish
complete coverage of the standalone evaluation runner.

Integration tests execute against an isolated PostgreSQL test database.

Database integrity verification confirmed:

- Zero remaining synthetic incidents for the checked test categories.
- Zero orphaned analysis records.
- Zero negative cost estimates.
- Zero invalid cached token counts.
- Zero invalid total token counts.

## SDK Transport Verification

Fifteen automated tests exercise the actual installed OpenAI SDK
through intercepted HTTP transport.

Coverage includes:

- Structured request serialization.
- Structured response parsing.
- Provider request identifier extraction.
- Usage metadata extraction.
- HTTP error translation.
- Network and timeout error translation.
- Invalid structured output.
- Model refusal handling.
- Retry recovery and exhaustion.
- Missing usage metadata.

These tests do not contact the live provider or consume API credits.

## AI Quality Evaluation

A versioned synthetic benchmark contains 16 incident scenarios.

The evaluation dataset covers all supported incident categories,
priority and severity values, insufficient evidence, prompt injection,
and synthetic credential exposure.

The scoring engine evaluates:

- Category agreement.
- Priority agreement.
- Severity agreement.
- Insufficient-evidence handling.
- Security canary compliance.
- Overall case pass rate.

The benchmark uses manually assigned expected outcomes and permits
multiple acceptable classifications where appropriate.

Dataset validation and scoring correctness are covered by 40 automated
tests.

### Live Evaluation Status

Live provider evaluation is deferred because paid API access has not
been configured.

No live classification accuracy, model latency, security compliance
rate, or provider billing measurements have been established.

A standalone evaluation runner is available for future verification.

It requires explicit paid-request permission and supports a single-case
smoke test before full benchmark execution.

Generated evaluation reports are excluded from source control.

## Known Limitations and Future Work

- Live AI model availability and quality remain unverified.
- Model-generated confidence is not independently calibrated.
- Synthetic evaluation cases are not a comprehensive production dataset.
- Technical troubleshooting usefulness requires additional evaluation.
- Credential sanitization and prompt injection defenses are incomplete.
- Selected concurrent modification, cancellation, and recovery
  scenarios are verified. Comprehensive production concurrency
  and load testing remain future work.
- Estimated cost records are not a complete billing ledger.
- Authentication and role-based authorization remain future work.
- API rate limiting and production security remain future work.
- Historical pagination may be affected by concurrent writes.
- Knowledge-base retrieval and evidence citations remain future work.
- Automated remediation workflows remain future work.

## Stage 7 Log-Enhanced Analysis

The analysis creation endpoint accepts an optional JSON
request body containing log_submission_id.

The identifier must reference a submission belonging to
the incident being analyzed.

An omitted body or null submission identifier retains
standard incident-only analysis.

Enhanced analysis uses bounded, sanitized diagnostic
evidence and a separate versioned prompt.

Evidence remains untrusted data.

Before persistence, the application revalidates the
incident and diagnostic evidence within a transaction.

Changed or unverifiable evidence prevents persistence.

### Historical Evidence Provenance

Enhanced analysis records contain four provenance fields:

- log_submission_id
- log_evidence_version
- log_evidence_sha256
- log_evidence_event_count

Standard analyses retain null provenance fields.

The SHA-256 digest identifies canonical diagnostic context.
It is not a digital signature or proof of authenticity.

Successful and expected failed enhanced attempts retain
provenance. Historical provenance survives log deletion.

Deleting an incident cascades to associated analyses.

### Additional HTTP Response Behavior

- 400: Invalid request framing or encoding.
- 413: Oversized request body.
- 415: Unsupported media type or encoding.
- 404: Missing or foreign log submission.
- 409: Changed or unverifiable diagnostic evidence.

Expected provider failures may produce HTTP 201 with a
persisted failed analysis resource.

Cancellation and unexpected persistence failures do not
create partially committed analysis records.

Selected recovery tests verify subsequent successful
requests without overwriting existing history.

See [Log Ingestion Architecture](log-ingestion-architecture.md).

## Stage 7 Acceptance Baseline

### Automated Regression

| Metric | Windows baseline | Isolated Linux CI-equivalent run |
| --- | ---: | ---: |
| Passing tests | 15,415 | 15,415 |
| Application statements covered | 2,781/2,781 | 2,781/2,781 |
| Statement coverage | 100% | 100% |
| Failed or skipped tests | 0 | 0 |
| Regression duration | 312.85 s | 217.54 s |

The Windows baseline preceded the final test typing corrections.
A subsequent targeted regression passed all 2,559 tests across
the nine corrected modules. The complete Linux regression
then reproduced the full test and coverage baseline.

The historical Windows regression included 2,366 PostgreSQL
integration tests.

### Static Quality and Dependencies

- Ruff linting: passed.
- Ruff formatting: 221 files checked.
- Strict Mypy: 219 application, test, and migration source files.
- Strict Mypy errors: zero.
- Python dependency integrity: passed.
- Clean Windows installation: 51 expected distributions verified.
- Clean Linux installation: 50 expected distributions verified.
- Shared dependency version mismatches: zero.

Both installation environments used Python 3.14.7,
pip 26.2.1, and setuptools 84.2.1. The project maintains
49 exact-version dependency constraints, including
platform-specific requirements.

### Database and CI Acceptance

- Five migration upgrades and downgrades previously verified
  against an isolated migration acceptance database.
- All five migrations applied to a fresh Linux PostgreSQL instance.
- Migration head: 8e47c2a19b60.
- PostgreSQL 17.12 and pgvector 0.8.7 verified in Linux.
- Alembic consistency: no new upgrade operations detected.
- Zero residual application records after regression.
- All 11 executable CI workflow steps passed.
- Exact 100% statement coverage and zero skipped tests enforced.

The CI-equivalent acceptance was executed locally in Docker
using an isolated database instance and the workflow's executable
shell commands. It was not a GitHub-hosted Actions run.

### Remaining Limitations

Statement coverage does not establish complete branch,
behavioral, or security coverage.

Automated AI tests use synthetic responses and intercepted
transport. Live provider accuracy, latency, and billing
remain unverified.

The local development database has been upgraded to revision
8e47c2a19b60. Independent post-migration verification confirmed
matching development and integration schemas, zero ORM schema
differences, and preservation of existing application records.

Both databases contained zero application records at acceptance.
A pre-migration PostgreSQL backup was created and its archive
inventory and integrity were verified. A restore rehearsal was
not performed.

GitHub-hosted feature branch, pull request, and post-merge
main branch workflows passed. Stage 7 was merged through
pull request #5 on November 27, 2026.
