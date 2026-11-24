# AI-Support-Engine
AI-powered enterprise technical support platform featuring intelligent troubleshooting, application log analysis, knowledge retrieval, and automated incident classification.

[![Backend CI](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/workflows/backend-ci.yml/badge.svg?branch=main)](https://github.com/CharlesGaines49512/AI-Support-Engine/actions/workflows/backend-ci.yml)
## Backend Development

See the [Backend Architecture and Development Guide](docs/backend.md) for setup instructions, API documentation, database migrations, and automated testing.

## AI Integration Milestone

The backend includes a provider-independent AI incident
analysis architecture with structured OpenAI responses,
PostgreSQL persistence, historical analysis retrieval,
input sanitization, estimated cost tracking, and aggregated
usage metrics.

### Verification

- 867 passing automated tests.
- 134 real PostgreSQL integration tests.
- 100% application statement coverage.
- 1,006 covered application statements.
- Strict Mypy validation across 102 Python source files.
- 15 SDK tests using intercepted HTTP transport.
- 16 synthetic incident evaluation scenarios.

Live provider evaluation is deferred until paid API access
is configured. No live model accuracy or billing measurements
are claimed.

### Documentation

- [AI Integration Architecture](docs/ai-architecture.md)
- [AI Integration Implementation](docs/ai-integration.md)
- [AI Evaluation Suite](backend/evaluations/README.md)

