import json
from collections.abc import Iterator
from unittest.mock import MagicMock
from uuid import UUID, uuid4
from xml.sax.saxutils import escape

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import delete, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.ai_dependencies import get_persistent_ai_analysis_service
from app.api.log_dependencies import (
    get_log_ingestion_service,
    get_log_query_service,
)
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.main import app
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.repositories.ai_analysis import AIAnalysisRepository
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService
from app.services.persistent_ai_analysis import PersistentAIAnalysisService

BASE_URL = "/api/v1/incidents"

CANARY = "SYNTHETIC_HTTP_STORED_SECURITY_CANARY"

ENTRY_FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)

UNSAFE_VALUES = (
    f"password={CANARY}",
    f"api key={CANARY}",
    f"secret key={CANARY}",
    f"Bearer {CANARY}",
    f"password=[REDACTED_SECRET]{CANARY}",
    f"Bearer [REDACTED_TOKEN]{CANARY}",
    f"Bearer [REDACTED_TOKEN={CANARY}]",
    f"postgresql://user:{CANARY}@localhost/db",
)

SAFE_VALUES = (
    "Synthetic diagnostic information.",
    "password=[REDACTED_SECRET]",
    "Bearer [REDACTED_TOKEN]",
    "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
    "[REDACTED_EMAIL]",
    "[REDACTED]",
)

STORED_ERROR = {
    "detail": "Stored application log content could not be verified.",
}

EVIDENCE_ERROR = {
    "detail": "Stored diagnostic evidence could not be verified.",
}

ANALYSIS_ERROR = {
    "detail": "Diagnostic evidence could not be verified.",
}


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_entries": 100,
            "log_max_evidence_entries": 20,
            "log_max_evidence_chars": 8000,
        }
    )


@pytest.fixture
def factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=True,
    )


@pytest.fixture
def incident_ids(
    factory: sessionmaker[Session],
) -> Iterator[tuple[UUID, UUID]]:
    identifiers = (uuid4(), uuid4())

    try:
        with factory.begin() as session:
            session.add_all(
                [
                    Incident(
                        id=identifier,
                        title="Stored security acceptance",
                        description="Synthetic HTTP security integration test.",
                    )
                    for identifier in identifiers
                ]
            )

        yield identifiers

    finally:
        with factory.begin() as session:
            session.execute(delete(Incident).where(Incident.id.in_(identifiers)))


@pytest.fixture
def provider_factory() -> MagicMock:
    return MagicMock(
        side_effect=AssertionError("Unexpected external AI provider creation.")
    )


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
        factory,
        settings,
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


def assert_conflict(
    response: Response,
    expected: dict[str, str],
) -> None:
    assert response.status_code == 409
    assert response.json() == expected
    assert CANARY not in response.text


def assert_no_analysis(
    factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    with factory() as session:
        repository = AIAnalysisRepository(session)

        assert repository.count_by_incident(incident_id) == 0


def submit_text(
    client: TestClient,
    incident_id: UUID,
) -> UUID:
    response = client.post(
        f"{BASE_URL}/{incident_id}/logs",
        params={"source_format": "text"},
        headers={
            "Content-Type": "text/plain",
            "X-Log-Source-Name": "synthetic-service",
        },
        content=(
            b"INFO Workflow started\n"
            b"ERROR Database connection failed\n"
            b"CRITICAL Invalid signature"
        ),
    )

    assert response.status_code == 201, response.text

    return UUID(response.json()["submission_id"])


@pytest.fixture
def submission_id(
    client: TestClient,
    incident_ids: tuple[UUID, UUID],
) -> UUID:
    return submit_text(
        client,
        incident_ids[0],
    )


@pytest.mark.parametrize(
    "source_format",
    ["text", "json", "xml"],
)
@pytest.mark.parametrize(
    ("credential", "marker"),
    [
        (
            f"password={CANARY}",
            "[REDACTED_SECRET]",
        ),
        (
            f"API KEY={CANARY}",
            "[REDACTED_SECRET]",
        ),
        (
            f"secret key={CANARY}",
            "[REDACTED_SECRET]",
        ),
        (
            f"Bearer {CANARY}",
            "[REDACTED_TOKEN]",
        ),
        (
            f"Basic {CANARY}",
            "[REDACTED_TOKEN]",
        ),
        (
            f"postgresql://user:{CANARY}@localhost/db",
            "[REDACTED_CREDENTIALS]",
        ),
    ],
)
def test_http_ingestion_persists_only_redacted_content(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    source_format: str,
    credential: str,
    marker: str,
) -> None:
    incident_id = incident_ids[0]

    message = "Database connection failed; " + credential

    if source_format == "text":
        payload = f"ERROR {message}".encode()
        content_type = "text/plain"

    elif source_format == "json":
        payload = json.dumps(
            {
                "severity": "ERROR",
                "message": message,
            }
        ).encode()

        content_type = "application/json"

    else:
        payload = (
            f'<entry severity="ERROR"><message>{escape(message)}</message></entry>'
        ).encode()

        content_type = "application/xml"

    root = f"{BASE_URL}/{incident_id}/logs"

    response = client.post(
        root,
        params={"source_format": source_format},
        content=payload,
        headers={
            "Content-Type": content_type,
            "X-Log-Source-Name": f"password={CANARY}",
        },
    )

    assert response.status_code == 201, response.text
    assert CANARY not in response.text

    data = response.json()
    submission_id = UUID(data["submission_id"])

    assert data["entry_count"] == 1
    assert data["redaction_count"] == 2

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        assert submission.source_name == ("password=[REDACTED_SECRET]")

        assert submission.redaction_count == 2

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission_id)
        ).one()

        entry_id = entry.id

        assert marker in entry.message
        assert "Database connection failed" in entry.message

        for field in ENTRY_FIELDS:
            assert CANARY not in (getattr(entry, field) or "")

    url = f"{root}/{submission_id}"

    for resource in (
        root,
        url,
        f"{url}/entries",
        f"{url}/entries/{entry_id}",
        f"{url}/evidence",
    ):
        response = client.get(resource)

        assert response.status_code == 200
        assert CANARY not in response.text

    response = client.get(f"{url}/entries/{entry_id}")

    assert marker in response.json()["message"]

    response = client.get(f"{url}/evidence")

    assert marker in response.text


@pytest.mark.parametrize("field", ENTRY_FIELDS)
@pytest.mark.parametrize("value", UNSAFE_VALUES)
@pytest.mark.parametrize("position", [1, 3])
def test_http_unsafe_entry_rejected_across_boundaries(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    field: str,
    value: str,
    position: int,
) -> None:
    incident_id = incident_ids[0]

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == position,
            )
        ).one()

        entry_id = entry.id

        setattr(entry, field, value)

    assert_conflict(
        client.get(f"{url}/entries/{entry_id}"),
        STORED_ERROR,
    )

    assert_conflict(
        client.get(f"{url}/entries"),
        STORED_ERROR,
    )

    assert_conflict(
        client.get(f"{url}/evidence"),
        EVIDENCE_ERROR,
    )

    assert_conflict(
        client.post(
            f"{BASE_URL}/{incident_id}/analyses",
            json={
                "log_submission_id": str(submission_id),
            },
        ),
        ANALYSIS_ERROR,
    )

    provider_factory.assert_not_called()

    assert_no_analysis(factory, incident_id)

    response = client.get(url)

    assert response.status_code == 200
    assert CANARY not in response.text

    with factory() as session:
        retrieved_entry = session.get(LogEntry, entry_id)

        assert retrieved_entry is not None
        assert getattr(retrieved_entry, field) == value


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_http_unsafe_metadata_rejected_across_boundaries(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

    assert_conflict(
        client.get(root),
        STORED_ERROR,
    )

    assert_conflict(
        client.get(url),
        STORED_ERROR,
    )

    assert_conflict(
        client.get(f"{url}/evidence"),
        EVIDENCE_ERROR,
    )

    assert_conflict(
        client.post(
            f"{BASE_URL}/{incident_id}/analyses",
            json={
                "log_submission_id": str(submission_id),
            },
        ),
        ANALYSIS_ERROR,
    )

    provider_factory.assert_not_called()

    assert_no_analysis(factory, incident_id)

    assert_conflict(
        client.get(f"{url}/entries"),
        STORED_ERROR,
    )

    with factory() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 1,
            )
        ).one()

        entry_id = entry.id

    assert_conflict(
        client.get(f"{url}/entries/{entry_id}"),
        STORED_ERROR,
    )

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        assert submission.source_name == value


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_http_corruption_preserves_incident_isolation(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    value: str,
) -> None:
    owner, other = incident_ids

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 1,
            )
        ).one()

        entry_id = entry.id
        entry.message = value

    foreign = f"{BASE_URL}/{other}/logs/{submission_id}"

    for resource in (
        foreign,
        f"{foreign}/entries",
        f"{foreign}/entries/{entry_id}",
        f"{foreign}/evidence",
    ):
        response = client.get(resource)

        assert response.status_code == 404
        assert CANARY not in response.text

    response = client.post(
        f"{BASE_URL}/{other}/analyses",
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 404
    assert CANARY not in response.text

    response = client.delete(foreign)

    assert response.status_code == 404

    provider_factory.assert_not_called()

    assert_no_analysis(factory, owner)
    assert_no_analysis(factory, other)

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        assert submission.source_name == value

        retrieved_entry = session.get(LogEntry, entry_id)

        assert retrieved_entry is not None
        assert retrieved_entry.message == value


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_http_corrupted_submission_remains_deletable(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    safe_id = submit_text(
        client,
        incident_id,
    )

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 3,
            )
        ).one()

        entry.message = value

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    response = client.delete(url)

    assert response.status_code == 204
    assert response.content == b""

    assert client.get(url).status_code == 404

    assert client.get(f"{root}/{safe_id}").status_code == 200

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submission_id,
            )
            is None
        )

        entries = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission_id)
        ).all()

        assert entries == []

        assert (
            session.get(
                LogSubmission,
                safe_id,
            )
            is not None
        )

        assert (
            session.get(
                Incident,
                incident_id,
            )
            is not None
        )


@pytest.mark.parametrize("value", SAFE_VALUES)
def test_http_safe_historical_content_preserved(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    message = f"Database connection failed; {value}"

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id
        entry.message = message

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    response = client.get(root)

    assert response.status_code == 200

    response = client.get(url)

    assert response.status_code == 200
    assert response.json()["source_name"] == value

    response = client.get(f"{url}/entries/{entry_id}")

    assert response.status_code == 200
    assert response.json()["message"] == message

    response = client.get(f"{url}/entries")

    assert response.status_code == 200

    response = client.get(f"{url}/evidence")

    assert response.status_code == 200

    event = next(
        event
        for event in response.json()["evidence"]["events"]
        if event["position"] == 2
    )

    assert event["message"] == message

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        retrieved_entry = session.get(LogEntry, entry_id)

        assert submission is not None
        assert retrieved_entry is not None

        assert submission.source_name == value
        assert retrieved_entry.message == message


UNICODE_HTTP_CANARY = "SYNTHETIC_UNICODE_HTTP_CANARY"


def _unicode_http_fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


UNICODE_HTTP_UNSAFE_VALUES = (
    _unicode_http_fullwidth("password") + "\uff1a" + UNICODE_HTTP_CANARY,
    _unicode_http_fullwidth("api")
    + "_\u00a0"
    + _unicode_http_fullwidth("key")
    + "\ufe66"
    + UNICODE_HTTP_CANARY,
    _unicode_http_fullwidth("access")
    + "\uff3f\u3000"
    + _unicode_http_fullwidth("token")
    + "\ufe55"
    + UNICODE_HTTP_CANARY,
    _unicode_http_fullwidth("Bearer") + "\u3000" + UNICODE_HTTP_CANARY,
    "B\uff41sic\u202f" + UNICODE_HTTP_CANARY,
    "p\u200cassword=" + UNICODE_HTTP_CANARY,
    "B\u200dearer " + UNICODE_HTTP_CANARY,
    _unicode_http_fullwidth("password") + "\uff1d",
    _unicode_http_fullwidth("Bearer") + " [REDACTED_TOKEN]" + UNICODE_HTTP_CANARY,
    _unicode_http_fullwidth("Basic") + " [REDACTED_TOKEN=" + UNICODE_HTTP_CANARY + "]",
    "Diagnostic\u200bcontent",
    "Diagnostic\u202econtent",
    "Diagnostic\u2060content",
    "Diagnostic\ufeffcontent",
)

UNICODE_HTTP_SAFE_VALUES = (
    "\u63a5\u7d9a\u5931\u6557",
    "\u670d\u52a1\u4e0d\u53ef\u7528",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\uff33\uff45\uff52\uff56\uff49\uff43\uff45",
    "caf\u00e9",
    "cafe\u0301",
    _unicode_http_fullwidth("password") + "\uff1a[REDACTED_SECRET]",
    _unicode_http_fullwidth("Bearer") + " [REDACTED_TOKEN]",
)

UNICODE_HTTP_REDACTION_CASES = (
    (
        _unicode_http_fullwidth("password") + "\uff1a" + UNICODE_HTTP_CANARY,
        _unicode_http_fullwidth("password") + "\uff1a[REDACTED_SECRET]",
    ),
    (
        _unicode_http_fullwidth("api")
        + "_\u00a0"
        + _unicode_http_fullwidth("key")
        + "\ufe66"
        + UNICODE_HTTP_CANARY,
        _unicode_http_fullwidth("api")
        + "_\u00a0"
        + _unicode_http_fullwidth("key")
        + "\ufe66[REDACTED_SECRET]",
    ),
    (
        _unicode_http_fullwidth("Bearer") + "\u3000" + UNICODE_HTTP_CANARY,
        _unicode_http_fullwidth("Bearer") + " [REDACTED_TOKEN]",
    ),
    (
        "B\uff41sic\u202f" + UNICODE_HTTP_CANARY,
        "B\uff41sic [REDACTED_TOKEN]",
    ),
)


def assert_unicode_http_conflict(
    response: Response,
    expected: dict[str, str],
) -> None:
    assert_conflict(response, expected)
    assert UNICODE_HTTP_CANARY not in response.text


@pytest.mark.parametrize("field", ENTRY_FIELDS)
@pytest.mark.parametrize("value", UNICODE_HTTP_UNSAFE_VALUES)
@pytest.mark.parametrize("position", (1, 3))
def test_http_unicode_unsafe_entry_rejected(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    field: str,
    value: str,
    position: int,
) -> None:
    incident_id = incident_ids[0]

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == position,
            )
        ).one()

        entry_id = entry.id

        setattr(entry, field, value)

    assert_unicode_http_conflict(
        client.get(f"{url}/entries/{entry_id}"),
        STORED_ERROR,
    )

    assert_unicode_http_conflict(
        client.get(f"{url}/entries"),
        STORED_ERROR,
    )

    assert_unicode_http_conflict(
        client.get(f"{url}/evidence"),
        EVIDENCE_ERROR,
    )

    assert_unicode_http_conflict(
        client.post(
            f"{BASE_URL}/{incident_id}/analyses",
            json={
                "log_submission_id": str(submission_id),
            },
        ),
        ANALYSIS_ERROR,
    )

    provider_factory.assert_not_called()

    assert_no_analysis(factory, incident_id)

    response = client.get(url)

    assert response.status_code == 200
    assert UNICODE_HTTP_CANARY not in response.text

    with factory() as session:
        retrieved_entry = session.get(LogEntry, entry_id)

        assert retrieved_entry is not None
        assert getattr(retrieved_entry, field) == value


@pytest.mark.parametrize("value", UNICODE_HTTP_UNSAFE_VALUES)
def test_http_unicode_unsafe_submission_metadata_rejected(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 1,
            )
        ).one()

        entry_id = entry.id

    for resource in (
        root,
        url,
        f"{url}/entries",
        f"{url}/entries/{entry_id}",
    ):
        assert_unicode_http_conflict(
            client.get(resource),
            STORED_ERROR,
        )

    assert_unicode_http_conflict(
        client.get(f"{url}/evidence"),
        EVIDENCE_ERROR,
    )

    assert_unicode_http_conflict(
        client.post(
            f"{BASE_URL}/{incident_id}/analyses",
            json={
                "log_submission_id": str(submission_id),
            },
        ),
        ANALYSIS_ERROR,
    )

    provider_factory.assert_not_called()

    assert_no_analysis(factory, incident_id)

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None
        assert submission.source_name == value


@pytest.mark.parametrize("value", UNICODE_HTTP_SAFE_VALUES)
def test_http_unicode_safe_historical_content_preserved(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    message = f"Database connection failed; {value}"

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id
        entry.message = message

        for field in (
            "original_severity",
            "service_name",
            "exception",
            "error_code",
            "correlation_id",
        ):
            setattr(entry, field, value)

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    assert client.get(root).status_code == 200

    response = client.get(url)

    assert response.status_code == 200
    assert response.json()["source_name"] == value

    response = client.get(f"{url}/entries/{entry_id}")

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == message

    for field in (
        "original_severity",
        "service_name",
        "exception",
        "error_code",
        "correlation_id",
    ):
        assert data[field] == value

    response = client.get(f"{url}/entries")

    assert response.status_code == 200

    response = client.get(f"{url}/evidence")

    assert response.status_code == 200

    event = next(
        event
        for event in response.json()["evidence"]["events"]
        if event["position"] == 2
    )

    assert event["message"] == message

    provider_factory.assert_not_called()


@pytest.mark.parametrize("value", UNICODE_HTTP_UNSAFE_VALUES)
def test_http_unicode_corruption_preserves_isolation(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    provider_factory: MagicMock,
    value: str,
) -> None:
    owner, other = incident_ids

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 1,
            )
        ).one()

        entry_id = entry.id
        entry.message = value

    foreign = f"{BASE_URL}/{other}/logs/{submission_id}"

    for resource in (
        foreign,
        f"{foreign}/entries",
        f"{foreign}/entries/{entry_id}",
        f"{foreign}/evidence",
    ):
        response = client.get(resource)

        assert response.status_code == 404
        assert UNICODE_HTTP_CANARY not in response.text

    response = client.post(
        f"{BASE_URL}/{other}/analyses",
        json={
            "log_submission_id": str(submission_id),
        },
    )

    assert response.status_code == 404
    assert UNICODE_HTTP_CANARY not in response.text

    assert client.delete(foreign).status_code == 404

    provider_factory.assert_not_called()

    assert_no_analysis(factory, owner)
    assert_no_analysis(factory, other)

    with factory() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        retrieved_entry = session.get(LogEntry, entry_id)

        assert submission is not None
        assert retrieved_entry is not None
        assert submission.source_name == value
        assert retrieved_entry.message == value


@pytest.mark.parametrize("value", UNICODE_HTTP_UNSAFE_VALUES)
def test_http_unicode_corrupted_submission_deletable(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    submission_id: UUID,
    value: str,
) -> None:
    incident_id = incident_ids[0]

    safe_id = submit_text(
        client,
        incident_id,
    )

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 3,
            )
        ).one()

        entry.message = value

    root = f"{BASE_URL}/{incident_id}/logs"
    url = f"{root}/{submission_id}"

    response = client.delete(url)

    assert response.status_code == 204
    assert response.content == b""

    assert client.get(url).status_code == 404
    assert client.get(f"{root}/{safe_id}").status_code == 200

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submission_id,
            )
            is None
        )

        entries = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission_id)
        ).all()

        assert entries == []

        assert (
            session.get(
                LogSubmission,
                safe_id,
            )
            is not None
        )

        assert (
            session.get(
                Incident,
                incident_id,
            )
            is not None
        )


@pytest.mark.parametrize(
    "source_format",
    ("text", "json", "xml"),
)
@pytest.mark.parametrize(
    ("credential", "expected"),
    UNICODE_HTTP_REDACTION_CASES,
)
def test_http_unicode_ingestion_and_retrieval(
    client: TestClient,
    factory: sessionmaker[Session],
    incident_ids: tuple[UUID, UUID],
    provider_factory: MagicMock,
    source_format: str,
    credential: str,
    expected: str,
) -> None:
    incident_id = incident_ids[0]

    message = "Database connection failed; " + credential
    expected_message = "Database connection failed; " + expected

    if source_format == "text":
        payload = f"ERROR {message}".encode()
        content_type = "text/plain"

    elif source_format == "json":
        payload = json.dumps(
            {
                "severity": "ERROR",
                "message": message,
            }
        ).encode()

        content_type = "application/json"

    else:
        payload = (
            f'<entry severity="ERROR"><message>{escape(message)}</message></entry>'
        ).encode()

        content_type = "application/xml"

    root = f"{BASE_URL}/{incident_id}/logs"

    response = client.post(
        root,
        params={"source_format": source_format},
        content=payload,
        headers={
            "Content-Type": content_type,
            "X-Log-Source-Name": ("password=" + UNICODE_HTTP_CANARY),
        },
    )

    assert response.status_code == 201
    assert UNICODE_HTTP_CANARY not in response.text

    data = response.json()

    assert data["entry_count"] == 1
    assert data["redaction_count"] == 2

    stored_id = UUID(data["submission_id"])

    with factory() as session:
        submission = session.get(
            LogSubmission,
            stored_id,
        )

        assert submission is not None

        assert submission.source_name == ("password=[REDACTED_SECRET]")

        assert submission.redaction_count == 2

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == stored_id)
        ).one()

        entry_id = entry.id

        assert entry.message == expected_message

        for field in ENTRY_FIELDS:
            assert UNICODE_HTTP_CANARY not in (getattr(entry, field) or "")

    url = f"{root}/{stored_id}"

    for resource in (
        root,
        url,
        f"{url}/entries",
        f"{url}/entries/{entry_id}",
        f"{url}/evidence",
    ):
        response = client.get(resource)

        assert response.status_code == 200
        assert UNICODE_HTTP_CANARY not in response.text

    response = client.get(f"{url}/entries/{entry_id}")

    assert response.json()["message"] == expected_message

    response = client.get(f"{url}/evidence")

    events = response.json()["evidence"]["events"]

    assert any(event["message"] == expected_message for event in events)

    provider_factory.assert_not_called()
