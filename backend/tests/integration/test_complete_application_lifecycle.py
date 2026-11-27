"""End-to-end HTTP and PostgreSQL application lifecycle acceptance."""

import hashlib
import json
from collections.abc import Iterator
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4
from xml.sax.saxutils import escape

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import SecretStr
from sqlalchemy import delete, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.ai_dependencies import get_persistent_ai_analysis_service
from app.api.log_dependencies import (
    get_log_ingestion_service,
    get_log_query_service,
)
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.integrations.ai import AIResponse, AIUsage
from app.main import app
from app.models import AIAnalysis, Incident, LogEntry, LogSubmission
from app.models.ai_enums import AIAnalysisStatus
from app.models.enums import IncidentPriority
from app.prompts.log_enhanced_analysis import (
    LOG_ENHANCED_PROMPT_VERSION,
    LOG_ENHANCED_SYSTEM_PROMPT,
)
from app.schemas.ai_analysis import (
    IncidentAnalysisResult,
    IncidentCategory,
    IncidentSeverity,
)
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService
from app.services.persistent_ai_analysis import PersistentAIAnalysisService

BASE_URL = "/api/v1/incidents"

CANARY = "SYNTHETIC_COMPLETE_LIFECYCLE_SECRET"

EXPECTED_COST = Decimal("0.0054000000")


@pytest.fixture
def factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    with integration_engine.connect() as connection:
        assert (
            connection.execute(text("SELECT current_database()")).scalar_one()
            == "ai_support_engine_migration_test"
        )

        assert (
            connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            == "8e47c2a19b60"
        )

    return sessionmaker(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=False,
    )


@pytest.fixture
def category(
    factory: sessionmaker[Session],
) -> Iterator[str]:
    identifier = f"lifecycle-{uuid4()}"

    try:
        yield identifier
    finally:
        with factory.begin() as session:
            session.execute(delete(Incident).where(Incident.category == identifier))


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        ai_enabled=True,
        ai_model="synthetic-model",
        openai_api_key=SecretStr("synthetic-api-key"),
        ai_pricing_model="synthetic-model",
        ai_pricing_input_usd_per_million=Decimal("2"),
        ai_pricing_cached_input_usd_per_million=Decimal("0.5"),
        ai_pricing_output_usd_per_million=Decimal("8"),
        log_max_entries=100,
        log_max_evidence_entries=20,
        log_max_evidence_chars=8000,
    )


@pytest.fixture
def provider() -> AsyncMock:
    result = AsyncMock()

    result.generate_structured.return_value = AIResponse[IncidentAnalysisResult](
        data=IncidentAnalysisResult(
            suggested_category=IncidentCategory.DATABASE,
            recommended_priority=IncidentPriority.HIGH,
            recommended_severity=IncidentSeverity.HIGH,
            summary="Database connectivity failure.",
            justification="Repeated connection timeouts.",
            confidence=0.9,
            insufficient_evidence=False,
            missing_information=[],
        ),
        provider="openai",
        model="synthetic-model",
        prompt_version=LOG_ENHANCED_PROMPT_VERSION,
        request_id="req_complete_lifecycle",
        usage=AIUsage(
            input_tokens=1000,
            cached_input_tokens=400,
            output_tokens=500,
            total_tokens=1500,
        ),
        latency_ms=250.0,
    )

    return result


@pytest.fixture
def provider_factory(
    provider: AsyncMock,
) -> MagicMock:
    return MagicMock(return_value=provider)


@pytest.fixture
def client(
    factory: sessionmaker[Session],
    settings: Settings,
    provider_factory: MagicMock,
) -> Iterator[TestClient]:
    previous = app.dependency_overrides.copy()

    ingestion = LogIngestionService(factory, settings)
    query = LogQueryService(factory, settings)

    analysis = PersistentAIAnalysisService(
        session_factory=factory,
        settings=settings,
        provider_factory=provider_factory,
    )

    def override_get_db() -> Iterator[Session]:
        with factory() as session:
            try:
                yield session
            except Exception:
                session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    app.dependency_overrides[get_settings] = lambda: settings

    app.dependency_overrides[get_log_ingestion_service] = lambda: ingestion

    app.dependency_overrides[get_log_query_service] = lambda: query

    app.dependency_overrides[get_persistent_ai_analysis_service] = lambda: analysis

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def create_payload(
    source_format: str,
) -> tuple[bytes, str]:
    message = f"Database connection failed; password={CANARY}"

    if source_format == "text":
        return (
            f"ERROR {message}".encode(),
            "text/plain",
        )

    if source_format == "json":
        return (
            json.dumps(
                {
                    "severity": "ERROR",
                    "message": message,
                }
            ).encode(),
            "application/json",
        )

    assert source_format == "xml"

    return (
        (
            f'<entry severity="ERROR"><message>{escape(message)}</message></entry>'
        ).encode(),
        "application/xml",
    )


@pytest.mark.parametrize(
    "source_format",
    ["text", "json", "xml"],
)
def test_complete_http_application_lifecycle(
    client: TestClient,
    factory: sessionmaker[Session],
    category: str,
    provider: AsyncMock,
    provider_factory: MagicMock,
    source_format: str,
) -> None:
    # Create the incident through the public API.
    response = client.post(
        BASE_URL,
        json={
            "title": "Database connectivity incident",
            "description": "Database connection timed out.",
            "priority": "medium",
            "category": category,
        },
    )

    assert response.status_code == 201, response.text

    created_incident = response.json()

    incident_id = UUID(created_incident["id"])

    root = f"{BASE_URL}/{incident_id}"
    logs_url = f"{root}/logs"
    analyses_url = f"{root}/analyses"

    assert created_incident["status"] == "open"

    assert client.get(root).json() == created_incident

    # Ingest synthetic logs containing a credential.
    payload, content_type = create_payload(source_format)

    response = client.post(
        logs_url,
        params={"source_format": source_format},
        content=payload,
        headers={
            "Content-Type": content_type,
            "X-Log-Source-Name": f"password={CANARY}",
        },
    )

    assert response.status_code == 201, response.text
    assert CANARY not in response.text

    submission = response.json()
    submission_id = UUID(submission["submission_id"])

    assert submission["entry_count"] == 1
    assert submission["redaction_count"] == 2

    submission_url = f"{logs_url}/{submission_id}"

    # Verify committed, sanitized PostgreSQL records.
    with factory() as session:
        stored_submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert stored_submission is not None
        assert stored_submission.incident_id == incident_id
        assert stored_submission.source_name == ("password=[REDACTED_SECRET]")

        assert stored_submission.payload_bytes == len(payload)

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission_id)
        ).one()

        entry_id = entry.id

        assert entry.position == 1
        assert "[REDACTED_SECRET]" in entry.message
        assert CANARY not in entry.message

    # Verify HTTP retrieval of the persisted resources.
    for url in (
        logs_url,
        submission_url,
        f"{submission_url}/entries",
        f"{submission_url}/entries/{entry_id}",
        f"{submission_url}/evidence",
    ):
        response = client.get(url)

        assert response.status_code == 200, response.text
        assert CANARY not in response.text

    response = client.get(f"{submission_url}/evidence")

    evidence_document = response.json()

    assert "[REDACTED_SECRET]" in response.text

    events = evidence_document["evidence"]["events"]

    assert len(events) == 1
    assert events[0]["position"] == 1

    provider_factory.assert_not_called()

    # Request enhanced analysis through the public API.
    response = client.post(
        analyses_url,
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 201, response.text
    assert CANARY not in response.text

    analysis = response.json()

    analysis_id = UUID(analysis["id"])

    assert analysis["status"] == "succeeded"
    assert analysis["suggested_category"] == "database"
    assert analysis["recommended_priority"] == "high"
    assert analysis["recommended_severity"] == "high"
    assert analysis["confidence"] == 0.9

    assert analysis["input_tokens"] == 1000
    assert analysis["cached_input_tokens"] == 400
    assert analysis["output_tokens"] == 500
    assert analysis["total_tokens"] == 1500

    assert Decimal(analysis["estimated_cost_usd"]) == EXPECTED_COST

    assert analysis["log_submission_id"] == str(submission_id)
    assert analysis["log_evidence_event_count"] == 1

    provider_factory.assert_called_once()
    provider.generate_structured.assert_awaited_once()
    provider.close.assert_awaited_once()

    call = provider.generate_structured.await_args

    assert call is not None

    request = call.args[0]

    assert request.system_prompt == LOG_ENHANCED_SYSTEM_PROMPT
    assert request.prompt_version == LOG_ENHANCED_PROMPT_VERSION

    assert CANARY not in request.system_prompt
    assert CANARY not in request.user_prompt

    prompt_document = json.loads(request.user_prompt)

    assert prompt_document["trust_level"] == "untrusted"

    context = prompt_document["log_context"]

    assert context["trust_level"] == "untrusted"
    assert context["incident_id"] == str(incident_id)
    assert context["submission_id"] == str(submission_id)

    assert context["evidence"]["source_format"] == source_format

    prompt_events = context["evidence"]["events"]

    assert len(prompt_events) == 1
    assert "[REDACTED_SECRET]" in prompt_events[0]["message"]

    expected_digest = hashlib.sha256(
        json.dumps(
            context,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    assert analysis["log_evidence_sha256"] == expected_digest

    # Verify independently committed analysis metadata.
    with factory() as session:
        stored = session.get(
            AIAnalysis,
            analysis_id,
        )

        assert stored is not None
        assert stored.incident_id == incident_id
        assert stored.status == AIAnalysisStatus.SUCCEEDED
        assert stored.log_submission_id == submission_id
        assert stored.log_evidence_sha256 == expected_digest
        assert stored.log_evidence_event_count == 1
        assert stored.estimated_cost_usd == EXPECTED_COST

    analysis_url = f"{analyses_url}/{analysis_id}"

    for url in (
        analysis_url,
        f"{analyses_url}/latest",
        f"{analyses_url}/latest-successful",
    ):
        response = client.get(url)

        assert response.status_code == 200, response.text
        assert response.json() == analysis

    response = client.get(analyses_url)

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"] == [analysis]

    # AI analysis must not automatically mutate the incident.
    response = client.get(root)

    assert response.status_code == 200
    assert response.json() == created_incident

    # Resolve and close through valid lifecycle transitions.
    response = client.patch(
        root,
        json={"status": "in_progress"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"

    response = client.patch(
        root,
        json={
            "status": "resolved",
            "resolution": "Database connectivity restored.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"

    resolved_at = response.json()["resolved_at"]

    assert resolved_at is not None

    response = client.patch(
        root,
        json={"status": "closed"},
    )

    assert response.status_code == 200

    closed_incident = response.json()

    assert closed_incident["status"] == "closed"
    assert closed_incident["resolved_at"] == resolved_at

    # Delete logs without destroying historical analysis.
    response = client.delete(submission_url)

    assert response.status_code == 204
    assert response.content == b""

    assert client.get(submission_url).status_code == 404

    assert client.get(f"{submission_url}/evidence").status_code == 404

    response = client.get(analysis_url)

    assert response.status_code == 200
    assert response.json() == analysis

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submission_id,
            )
            is None
        )

        assert session.get(LogEntry, entry_id) is None

        stored = session.get(AIAnalysis, analysis_id)

        assert stored is not None
        assert stored.log_submission_id == submission_id
        assert stored.log_evidence_sha256 == expected_digest
        assert stored.estimated_cost_usd == EXPECTED_COST

    assert client.get(root).json() == closed_incident

    # Final incident deletion must cascade to AI history.
    response = client.delete(root)

    assert response.status_code == 204
    assert response.content == b""

    assert client.get(root).status_code == 404
    assert client.get(analysis_url).status_code == 404
    assert client.get(analyses_url).status_code == 404

    with factory() as session:
        assert session.get(Incident, incident_id) is None
        assert session.get(AIAnalysis, analysis_id) is None
        assert session.get(LogSubmission, submission_id) is None
        assert session.get(LogEntry, entry_id) is None

    provider.generate_structured.assert_awaited_once()
    provider.close.assert_awaited_once()


def capture_isolation_snapshot(
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
) -> dict[str, list[dict[str, object]]]:
    statements = {
        "incidents": (
            "SELECT * FROM incidents WHERE id IN (:first, :second) ORDER BY id"
        ),
        "log_submissions": (
            "SELECT * FROM log_submissions "
            "WHERE incident_id IN (:first, :second) "
            "ORDER BY id"
        ),
        "log_entries": (
            "SELECT entry.* FROM log_entries AS entry "
            "JOIN log_submissions AS submission "
            "ON entry.submission_id = submission.id "
            "WHERE submission.incident_id "
            "IN (:first, :second) "
            "ORDER BY entry.id"
        ),
        "ai_analyses": (
            "SELECT * FROM ai_analyses "
            "WHERE incident_id IN (:first, :second) "
            "ORDER BY id"
        ),
    }

    parameters = {
        "first": incident_ids[0],
        "second": incident_ids[1],
    }

    with factory() as session:
        session.execute(
            text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        )

        return {
            name: [
                dict(row)
                for row in session.execute(
                    text(statement),
                    parameters,
                ).mappings()
            ]
            for name, statement in statements.items()
        }


def test_complete_http_resource_isolation(
    client: TestClient,
    factory: sessionmaker[Session],
    category: str,
    provider: AsyncMock,
    provider_factory: MagicMock,
) -> None:
    incident_ids = []

    for label in ("first", "second"):
        response = client.post(
            BASE_URL,
            json={
                "title": f"Synthetic {label} incident",
                "description": "Database connection failed.",
                "priority": "medium",
                "category": category,
            },
        )

        assert response.status_code == 201, response.text

        incident_ids.append(UUID(response.json()["id"]))

    first, second = incident_ids

    assert first != second

    owners = {
        "A1": first,
        "A2": first,
        "B1": second,
    }

    markers = {
        "A1": "ISOLATION_DIAGNOSTIC_ALPHA",
        "A2": "ISOLATION_DIAGNOSTIC_BRAVO",
        "B1": "ISOLATION_DIAGNOSTIC_CHARLIE",
    }

    submissions: dict[str, UUID] = {}
    entries: dict[str, UUID] = {}
    analyses: dict[str, UUID] = {}
    analysis_documents: dict[str, dict[str, object]] = {}

    for label, owner in owners.items():
        root = f"{BASE_URL}/{owner}"

        payload = (
            f"ERROR Database connection failed; {markers[label]}; password={CANARY}"
        ).encode()

        response = client.post(
            f"{root}/logs",
            params={"source_format": "text"},
            content=payload,
            headers={
                "Content-Type": "text/plain",
            },
        )

        assert response.status_code == 201, response.text
        assert CANARY not in response.text

        submission_id = UUID(response.json()["submission_id"])

        submissions[label] = submission_id

        with factory() as session:
            entry = session.scalars(
                select(LogEntry).where(LogEntry.submission_id == submission_id)
            ).one()

            entries[label] = entry.id

            assert markers[label] in entry.message
            assert CANARY not in entry.message
            assert "[REDACTED_SECRET]" in entry.message

        evidence_url = f"{root}/logs/{submission_id}/evidence"

        evidence = client.get(evidence_url)

        assert evidence.status_code == 200, evidence.text
        assert markers[label] in evidence.text
        assert CANARY not in evidence.text

        for other_label, marker in markers.items():
            if other_label != label:
                assert marker not in evidence.text

        response = client.post(
            f"{root}/analyses",
            json={
                "log_submission_id": str(submission_id),
            },
        )

        assert response.status_code == 201, response.text

        document = response.json()

        assert document["status"] == "succeeded"
        assert document["log_submission_id"] == str(submission_id)
        assert document["log_evidence_event_count"] == 1

        assert CANARY not in response.text

        analyses[label] = UUID(document["id"])
        analysis_documents[label] = document

        call = provider.generate_structured.await_args

        assert call is not None

        request = call.args[0]

        assert markers[label] in request.user_prompt
        assert CANARY not in request.user_prompt

        for other_label, marker in markers.items():
            if other_label != label:
                assert marker not in request.user_prompt

    assert len(set(submissions.values())) == 3
    assert len(set(entries.values())) == 3
    assert len(set(analyses.values())) == 3

    assert provider_factory.call_count == 3
    assert provider.generate_structured.await_count == 3
    assert provider.close.await_count == 3

    before = capture_isolation_snapshot(
        factory,
        (first, second),
    )

    assert {table: len(records) for table, records in before.items()} == {
        "incidents": 2,
        "log_submissions": 3,
        "log_entries": 3,
        "ai_analyses": 3,
    }

    provider_factory.reset_mock()
    provider.generate_structured.reset_mock()
    provider.close.reset_mock()

    missing_submission = uuid4()
    missing_entry = uuid4()
    missing_analysis = uuid4()

    def assert_indistinguishable_not_found(
        actual: Response,
        missing: Response,
    ) -> None:
        assert actual.status_code == 404, actual.text
        assert missing.status_code == 404, missing.text
        assert actual.json() == missing.json()

        for response in (actual, missing):
            assert CANARY not in response.text

            for marker in markers.values():
                assert marker not in response.text

    # Cross-incident resource requests in both directions.
    for label, owner in owners.items():
        foreign_owner = second if owner == first else first

        root = f"{BASE_URL}/{foreign_owner}"

        foreign = f"{root}/logs/{submissions[label]}"
        missing = f"{root}/logs/{missing_submission}"

        for suffix in (
            "",
            "/entries",
            f"/entries/{entries[label]}",
            "/evidence",
        ):
            assert_indistinguishable_not_found(
                client.get(f"{foreign}{suffix}"),
                client.get(f"{missing}{suffix}"),
            )

        assert_indistinguishable_not_found(
            client.post(
                f"{root}/analyses",
                json={
                    "log_submission_id": str(submissions[label]),
                },
            ),
            client.post(
                f"{root}/analyses",
                json={
                    "log_submission_id": str(missing_submission),
                },
            ),
        )

        assert_indistinguishable_not_found(
            client.get(f"{root}/analyses/{analyses[label]}"),
            client.get(f"{root}/analyses/{missing_analysis}"),
        )

        assert_indistinguishable_not_found(
            client.delete(foreign),
            client.delete(missing),
        )

    # Every entry must remain scoped to its own submission.
    for target_label, owner in owners.items():
        root = f"{BASE_URL}/{owner}/logs/{submissions[target_label]}/entries"

        for entry_label, entry_id in entries.items():
            if entry_label == target_label:
                continue

            assert_indistinguishable_not_found(
                client.get(f"{root}/{entry_id}"),
                client.get(f"{root}/{missing_entry}"),
            )

    provider_factory.assert_not_called()
    provider.generate_structured.assert_not_awaited()
    provider.close.assert_not_awaited()

    assert (
        capture_isolation_snapshot(
            factory,
            (first, second),
        )
        == before
    )

    # Verify legitimate resource retrieval still succeeds.
    for owner in (first, second):
        expected_labels = {
            label for label, identifier in owners.items() if identifier == owner
        }

        root = f"{BASE_URL}/{owner}"

        response = client.get(f"{root}/logs")

        assert response.status_code == 200, response.text

        document = response.json()

        assert document["total"] == len(expected_labels)

        actual_submission_ids = {UUID(item["id"]) for item in document["items"]}

        assert actual_submission_ids == {
            submissions[label] for label in expected_labels
        }

        response = client.get(f"{root}/analyses")

        assert response.status_code == 200, response.text

        document = response.json()

        assert document["total"] == len(expected_labels)

        assert {UUID(item["id"]) for item in document["items"]} == {
            analyses[label] for label in expected_labels
        }

        for endpoint in (
            "latest",
            "latest-successful",
        ):
            response = client.get(f"{root}/analyses/{endpoint}")

            assert response.status_code == 200

            assert UUID(response.json()["id"]) in {
                analyses[label] for label in expected_labels
            }

        for label in expected_labels:
            response = client.get(f"{root}/analyses/{analyses[label]}")

            assert response.status_code == 200

            assert response.json() == (analysis_documents[label])

            evidence = client.get(f"{root}/logs/{submissions[label]}/evidence")

            assert evidence.status_code == 200

            assert markers[label] in evidence.text
            assert CANARY not in evidence.text

            for other_label, marker in markers.items():
                if other_label != label:
                    assert marker not in evidence.text

    provider_factory.assert_not_called()
    provider.generate_structured.assert_not_awaited()
    provider.close.assert_not_awaited()

    assert (
        capture_isolation_snapshot(
            factory,
            (first, second),
        )
        == before
    )

    # Delete one incident legitimately and preserve the other.
    response = client.delete(f"{BASE_URL}/{first}")

    assert response.status_code == 204
    assert response.content == b""

    after = capture_isolation_snapshot(
        factory,
        (first, second),
    )

    protected_submission = submissions["B1"]
    protected_entry = entries["B1"]
    protected_analysis = analyses["B1"]

    expected = {
        "incidents": [
            record for record in before["incidents"] if record["id"] == second
        ],
        "log_submissions": [
            record
            for record in before["log_submissions"]
            if record["id"] == protected_submission
        ],
        "log_entries": [
            record
            for record in before["log_entries"]
            if record["id"] == protected_entry
        ],
        "ai_analyses": [
            record
            for record in before["ai_analyses"]
            if record["id"] == protected_analysis
        ],
    }

    assert after == expected

    assert all(len(records) == 1 for records in after.values())

    assert client.get(f"{BASE_URL}/{first}").status_code == 404

    assert client.get(f"{BASE_URL}/{second}").status_code == 200

    response = client.get(f"{BASE_URL}/{second}/analyses/{protected_analysis}")

    assert response.status_code == 200
    assert response.json() == analysis_documents["B1"]

    response = client.delete(f"{BASE_URL}/{second}")

    assert response.status_code == 204

    assert capture_isolation_snapshot(
        factory,
        (first, second),
    ) == {
        "incidents": [],
        "log_submissions": [],
        "log_entries": [],
        "ai_analyses": [],
    }

    provider_factory.assert_not_called()
    provider.generate_structured.assert_not_awaited()
    provider.close.assert_not_awaited()
