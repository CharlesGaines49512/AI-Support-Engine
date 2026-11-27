# AI-Support-Engine

AI Support Engine is an enterprise-style technical support
platform designed for incident management, application log
analysis, and AI-assisted troubleshooting.

[![Backend CI](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/workflows/backend-ci.yml/badge.svg?branch=main)](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/workflows/backend-ci.yml)

## Implemented Capabilities

- PostgreSQL-backed incident management.
- Incident lifecycle validation.
- Provider-independent structured AI analysis.
- Persistent analysis history and estimated processing costs.
- XML, JSON, and plain-text log ingestion.
- Bounded parsing and normalization.
- Sensitive-data sanitization.
- Deterministic diagnostic evidence extraction and ranking.
- Incident-scoped log retrieval and deletion.
- Optional log-enhanced AI analysis.
- Versioned SHA-256 evidence provenance.
- Transaction rollback and failure recovery.
- OpenAPI contracts and readiness checks.

## Technology Stack

Python 3.14.7, FastAPI, Pydantic, SQLAlchemy, PostgreSQL 17,
pgvector, Alembic, OpenAI SDK, Docker Compose, Pytest,
Ruff, Mypy, and GitHub Actions.

For reproducible installation and local testing, follow the
[Backend Development Guide](docs/backend.md).

The repository contains pinned build tools and platform-aware
dependency constraints for the verified development environments.

## Architecture

The application uses a modular monolith with separate API,
service, repository, parsing, security, persistence,
and external integration components.

AI recommendations remain advisory and do not automatically
modify incidents or execute remediation commands.

## Documentation

- [Backend Development Guide](docs/backend.md)
- [System Architecture](docs/architecture.md)
- [Software Requirements](docs/requirements.md)
- [AI Architecture](docs/ai-architecture.md)
- [AI Integration](docs/ai-integration.md)
- [Log Ingestion Architecture](docs/log-ingestion-architecture.md)
- [AI Evaluation Suite](backend/evaluations/README.md)

## Security and Deployment Status

The current implementation is intended for trusted local
development and synthetic demonstration data.

Incident scoping does not replace authentication,
authorization, or tenant isolation.

Sanitization and prompt injection defenses are
defense-in-depth measures, not complete guarantees.

Knowledge retrieval, frontend functionality, authentication,
role-based authorization, and production deployment
security remain future work.

Do not expose the unauthenticated API publicly.

## License

Released under the [MIT License](LICENSE).

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

### Stage 7 Integration

Stage 7 was merged into main on November 27, 2026.

- Pull request: #5.
- Feature commit: `39f739d0b8e175d6770e0f3bc1c8f44d8364a872`.
- Merge commit: `bb0b25ff70934d508f15d58dbb50a690c2e66181`.
- Feature branch GitHub Actions: passed.
- Pull request GitHub Actions: passed.
- Post-merge main branch GitHub Actions: passed.
- Verified regression baseline: 15,415 passing tests.
- Application statement coverage: 2,781/2,781 (100%).
- Failed, errored, or skipped tests in the verified baseline: zero.
- Development and integration migration head: `8e47c2a19b60`.
- Reviewed merged files: 144/144.

Acceptance evidence:

- [Pull request #5](https://github.com/CharlesGaines49512/AI-Support-Engine/pull/5)
- [Feature branch CI](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/runs/46050598988)
- [Pull request CI](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/runs/46051431736)
- [Post-merge CI](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/runs/46051892968)

Live AI provider evaluation, comprehensive dependency vulnerability
scanning, and authentication and authorization remain outside the
completed Stage 7 acceptance scope.
