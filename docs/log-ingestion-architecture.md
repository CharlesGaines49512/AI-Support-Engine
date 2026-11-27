# Log Ingestion and Analysis Architecture

## Overview

Stage 7 implements application log ingestion, parsing,
normalization, diagnostic evidence extraction, persistence,
and incident correlation within AI Support Engine.

The system will support enterprise technical support workflows
involving application failures, integration errors, database
connectivity problems, and automation execution failures.

## Objectives

- Accept XML, JSON, and plain-text application logs.
- Validate input formats and enforce resource limits.
- Convert supported logs into normalized structured records.
- Detect and redact sensitive information.
- Identify errors, warnings, and technical evidence.
- Persist sanitized log records in PostgreSQL.
- Associate log records with technical incidents.
- Provide relevant sanitized evidence to AI analysis services.
- Expose log ingestion and retrieval through REST endpoints.

## Non-Goals

- Executing commands contained within logs.
- Automatically modifying production systems.
- Automatically resolving incidents.
- Supporting arbitrary binary files or compressed archives.
- Providing unrestricted remote log collection.
- Requiring paid AI access for deterministic log processing.

## Architecture

Log processing follows a layered architecture:

1. REST API submission.
2. Input validation and format selection.
3. Format-specific parsing.
4. Normalization and sensitive-data sanitization.
5. Error detection and evidence extraction.
6. PostgreSQL persistence.
7. Incident association.
8. Optional AI analysis enrichment.

Parsing and deterministic evidence extraction remain independent
of external AI providers.

## Supported Formats

### XML

Support structured application events and nested error information.

XML processing must reject document type declarations, external
entities, and other unsupported constructs that could introduce
entity expansion or external resource access.

### JSON

Support structured application log objects and arrays of log entries.

JSON processing must enforce size, nesting, entry-count, and
field-length limits.

### Plain Text

Support line-oriented application logs containing timestamps,
severity indicators, exception messages, and diagnostic details.

Unrecognized lines may be represented as unstructured messages
rather than silently discarded.

## Normalized Log Records

A normalized log record may contain:

- Event timestamp when reliably available.
- Normalized severity.
- Original severity label when appropriate.
- Application or service identifier.
- Sanitized event message.
- Sanitized exception information.
- Error code when available.
- Correlation identifier when available.
- Source format.
- Source entry position.
- Associated incident identifier.

Unknown metadata must remain unknown rather than being invented.

## Severity Normalization

Supported normalized severity levels will include:

- TRACE
- DEBUG
- INFO
- WARNING
- ERROR
- CRITICAL
- UNKNOWN

Log severity is distinct from incident severity and incident
priority. Individual error records must not automatically
determine overall business impact.

## Security Requirements

All submitted log content is untrusted.

The ingestion pipeline must:

- Enforce input-size limits before parsing.
- Enforce parser resource and nesting limits.
- Reject unsafe XML constructs.
- Prevent external resource resolution.
- Reject unsupported binary content.
- Sanitize parsed text and metadata before persistence.
- Avoid exposing raw log content through exceptions.
- Avoid logging credentials or sensitive request bodies.
- Prevent log content from being interpreted as AI instructions.
- Preserve incident-scoped access boundaries.

Raw unsanitized logs will not be persisted by default.

Regex-based sensitive-data detection cannot guarantee complete
removal of all private information.

Authentication, authorization, and production rate limiting
remain required before public deployment.

## HTTP Source-Name Encoding

The optional `X-Log-Source-Name` request header accepts
printable ASCII characters only (U+0020 through U+007E).

- Non-ASCII characters and control characters are rejected
  with HTTP 400 before log ingestion.
- Source names exceeding the configured metadata length
  limit are rejected with HTTP 413 when otherwise valid.
- Duplicate source-name headers are rejected with HTTP 400.
- An omitted source-name header remains supported.
- Percent-encoded sequences are treated as literal text.
- Accepted source names remain subject to sensitive-data
  sanitization before persistence.

This restriction avoids ambiguous interpretation of
non-ASCII HTTP header bytes by framework and transport
components.

The restriction applies only to this HTTP header.
UTF-8 log bodies, supported international log metadata,
and internal ingestion-service source names retain
their existing Unicode support.

International source names transmitted through HTTP
headers would require a separately defined encoding
contract.

## Evidence Extraction

Deterministic evidence extraction will identify supported
diagnostic signals, including:

- Error and critical severity events.
- Exception information.
- Database connection failures.
- Authentication and authorization failures.
- Network failures and timeouts.
- Integration response errors.
- Repeated error patterns.

Extracted evidence is advisory and must not be represented as
a verified root cause without sufficient supporting information.

## Persistence

PostgreSQL will store normalized and sanitized log information.

Log ingestion and persistence will use transactional operations
with rollback handling.

Database constraints will protect relationships, supported
formats, and relevant numeric ranges.

## AI Integration

Selected sanitized log evidence may enrich incident analysis.

AI context must remain bounded by configured limits.

Submitted log messages must be treated as untrusted evidence,
not executable instructions.

Existing incident analysis functionality must remain operational
when no associated logs are available.

Live AI evaluation remains deferred until API access is configured.

## Testing Strategy

Testing will include:

- Parser unit tests.
- Normalization and validation tests.
- Sensitive-data redaction tests.
- Malformed input tests.
- Resource-limit tests.
- Unsafe XML input tests.
- Evidence extraction tests.
- Repository and service tests.
- PostgreSQL integration tests.
- REST API tests.
- Full backend regression testing.

All automated tests must run without paid external API access.

## Acceptance Criteria

Stage 7 is complete when:

1. All three supported log formats can be parsed securely.
2. Resource limits are enforced.
3. Parsed logs are normalized consistently.
4. Sensitive information is sanitized before persistence.
5. Technical evidence can be extracted deterministically.
6. Sanitized log records can be associated with incidents.
7. REST endpoints support ingestion and retrieval.
8. AI analysis can incorporate bounded sanitized evidence.
9. Existing backend functionality remains operational.
10. Automated tests and static quality checks pass.
11. Technical documentation accurately describes limitations.
12. GitHub CI passes and the feature branch is merged.

## Historical Baseline

Stage 6 local verification:

- 867 passing automated tests.
- 134 PostgreSQL integration tests.
- 100 percent application statement coverage.
- 1006 covered application statements.

GitHub pull request 4 was merged successfully.

Live AI evaluation remains deferred.

## Implemented Persistence Model

The log_submissions table stores incident association,
source format, sanitized source name, payload size,
entry count, redaction count, and creation time.

The log_entries table stores normalized event content,
submission association, position, and metadata.

Database constraints enforce required fields,
relationships, enum values, and accounting ranges.

Writes are transactional. Failed persistence does not
retain partially committed submissions.

Deleting a submission cascades to its entries.
Deleting an incident cascades to logs and AI analyses.

Historical enhanced analysis provenance survives
deletion of the associated log submission.

## Request and Resource Limits

Supported requests use uncompressed UTF-8 content with
media types matching the selected log format.

| Configuration variable | Purpose |
| --- | --- |
| LOG_MAX_PAYLOAD_BYTES | Maximum payload size |
| LOG_MAX_ENTRIES | Maximum parsed entries |
| LOG_MAX_NESTING_DEPTH | Maximum parser nesting |
| LOG_MAX_MESSAGE_CHARS | Message and exception length |
| LOG_MAX_METADATA_CHARS | Metadata length |
| LOG_MAX_EVIDENCE_ENTRIES | Maximum evidence events |
| LOG_MAX_EVIDENCE_CHARS | Evidence character budget |

### Application Logging Configuration

LOG_LEVEL is an application-wide logging verbosity setting,
rather than an application log ingestion resource limit.
Its configured default is INFO.

Consult application settings and .env.example.

Malformed framing, duplicate singleton headers,
unsupported encodings, unsafe parser constructs,
and invalid input are rejected before persistence.

## Stored Content and Evidence Verification

Sanitization occurs before persistence.

Repository validation provides an additional boundary
against unsafe stored content.

Retrieval and evidence reconstruction validate stored
content before returning it or supplying it to AI.

Unverifiable stored content is rejected.

Recognized credential patterns are redacted.
Unsafe residual credential patterns and unsupported
control characters are rejected.

Unicode support does not imply acceptance of every
possible Unicode sequence.

Diagnostic evidence remains advisory and is not a
confirmed root-cause determination.

## Resource Isolation

Queries are scoped to their incident and submission
identifiers.

Cross-incident and cross-submission access is rejected.

HTTP acceptance testing verified equivalent response
bodies for selected foreign and nonexistent resources.

Rejected requests preserved existing database records
and did not invoke the mocked AI provider.

Incident scoping is not user authentication,
authorization, or tenant isolation.

## Transaction and Recovery Acceptance

Verified integration scenarios include:

- Complete TEXT, JSON, and XML HTTP lifecycles.
- Database constraint enforcement.
- Migration upgrade and downgrade reversibility.
- Historical evidence provenance preservation.
- Log and AI persistence rollback.
- Successful recovery after injected failures.
- Standard and enhanced analysis cancellation recovery.
- Provider timeout history retention and subsequent retry.
- Deletion rollback and recovery.
- Cross-incident resource isolation.
- Independent resource preservation during cascade deletion.

These tests verify selected deterministic scenarios,
not every possible production failure.

Local Linux CI-equivalent regression has passed.
GitHub-hosted feature branch, pull request, and post-merge
main branch workflows passed. Stage 7 was merged through
pull request #5 on November 27, 2026.

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
