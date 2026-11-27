from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.log_dependencies import get_log_query_service
from app.core.exceptions import IncidentNotFoundError
from app.logs.exceptions import (
    LogEntryNotFoundError,
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.logs.query_contracts import (
    LogEntryRecord,
    LogPage,
    LogSubmissionRecord,
)
from app.main import app
from app.models.log_enums import LogFormat, LogSeverity
from app.services.log_query import (
    MAX_PAGE_OFFSET,
    LogQueryService,
)


@pytest.fixture
def submission() -> LogSubmissionRecord:
    return LogSubmissionRecord(
        id=uuid4(),
        incident_id=uuid4(),
        source_format=LogFormat.TEXT,
        source_name="application.log",
        payload_bytes=256,
        entry_count=3,
        redaction_count=1,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def entry(
    submission: LogSubmissionRecord,
) -> LogEntryRecord:
    return LogEntryRecord(
        id=uuid4(),
        submission_id=submission.id,
        position=2,
        severity=LogSeverity.ERROR,
        message=("Database connection failed. password=[REDACTED_SECRET]"),
        event_timestamp=datetime.now(UTC),
        original_severity="ERROR",
        service_name="database-service",
        error_code="DB-CONNECTION",
    )


@pytest.fixture
def service(
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
) -> MagicMock:
    mock = MagicMock(spec=LogQueryService)

    mock.get_submission.return_value = submission
    mock.get_entry.return_value = entry

    mock.list_submissions.return_value = LogPage(
        items=(submission,),
        total=1,
        offset=0,
        limit=20,
    )

    mock.list_entries.return_value = LogPage(
        items=(entry,),
        total=1,
        offset=0,
        limit=20,
    )

    return mock


@pytest.fixture
def client(
    service: MagicMock,
) -> Generator[TestClient]:
    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_log_query_service] = lambda: service

    try:
        with TestClient(app) as test_client:
            yield test_client

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)


@pytest.fixture
def endpoint(
    submission: LogSubmissionRecord,
) -> str:
    return f"/api/v1/incidents/{submission.incident_id}/logs"


def test_list_submissions(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
) -> None:
    response = client.get(endpoint)

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["offset"] == 0
    assert data["limit"] == 20
    assert data["has_more"] is False

    item = data["items"][0]

    assert item["id"] == str(submission.id)
    assert item["incident_id"] == str(submission.incident_id)
    assert item["source_format"] == "text"
    assert item["entry_count"] == 3
    assert item["redaction_count"] == 1
    assert "raw_payload" not in item

    service.list_submissions.assert_called_once_with(
        submission.incident_id,
        offset=0,
        limit=20,
    )


def test_get_submission(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
) -> None:
    response = client.get(f"{endpoint}/{submission.id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == str(submission.id)
    assert data["incident_id"] == str(submission.incident_id)
    assert data["source_name"] == "application.log"
    assert data["payload_bytes"] == 256
    assert "raw_payload" not in data

    service.get_submission.assert_called_once_with(
        submission.incident_id,
        submission.id,
    )


def test_list_entries(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
) -> None:
    response = client.get(f"{endpoint}/{submission.id}/entries")

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["offset"] == 0
    assert data["limit"] == 20
    assert data["has_more"] is False

    item = data["items"][0]

    assert item["id"] == str(entry.id)
    assert item["submission_id"] == str(submission.id)
    assert item["severity"] == "error"
    assert item["position"] == 2
    assert item["message"] == entry.message
    assert "[REDACTED_SECRET]" in item["message"]
    assert "raw_payload" not in item

    service.list_entries.assert_called_once_with(
        submission.incident_id,
        submission.id,
        offset=0,
        limit=20,
        severity=None,
    )


def test_get_entry(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
) -> None:
    response = client.get(f"{endpoint}/{submission.id}/entries/{entry.id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == str(entry.id)
    assert data["submission_id"] == str(submission.id)
    assert data["position"] == 2
    assert data["severity"] == "error"
    assert data["message"] == entry.message
    assert data["service_name"] == "database-service"
    assert data["error_code"] == "DB-CONNECTION"
    assert data["correlation_id"] is None
    assert "raw_payload" not in data

    service.get_entry.assert_called_once_with(
        submission.incident_id,
        submission.id,
        entry.id,
    )


@pytest.mark.parametrize(
    "collection",
    ["submissions", "entries"],
)
def test_custom_pagination(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
    collection: str,
) -> None:
    item: LogSubmissionRecord | LogEntryRecord
    arguments: tuple[UUID, ...]
    filters: dict[str, LogSeverity | None]

    if collection == "submissions":
        url = endpoint
        method = service.list_submissions
        item = submission
        arguments = (submission.incident_id,)
        filters = {}
    else:
        url = f"{endpoint}/{submission.id}/entries"
        method = service.list_entries
        item = entry
        arguments = (
            submission.incident_id,
            submission.id,
        )
        filters = {"severity": None}

    method.return_value = LogPage(
        items=(item,),
        total=10,
        offset=2,
        limit=1,
    )

    response = client.get(
        url,
        params={"offset": 2, "limit": 1},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 10
    assert data["offset"] == 2
    assert data["limit"] == 1
    assert data["has_more"] is True

    method.assert_called_once_with(
        *arguments,
        offset=2,
        limit=1,
        **filters,
    )


@pytest.mark.parametrize(
    "collection",
    ["submissions", "entries"],
)
@pytest.mark.parametrize(
    ("offset", "total"),
    [(0, 0), (10, 5), (MAX_PAGE_OFFSET, 5)],
)
def test_empty_collections(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    collection: str,
    offset: int,
    total: int,
) -> None:
    if collection == "submissions":
        url = endpoint
        method = service.list_submissions
    else:
        url = f"{endpoint}/{submission.id}/entries"
        method = service.list_entries

    method.return_value = LogPage(
        items=(),
        total=total,
        offset=offset,
        limit=20,
    )

    response = client.get(
        url,
        params={"offset": offset},
    )

    assert response.status_code == 200

    assert response.json() == {
        "items": [],
        "total": total,
        "offset": offset,
        "limit": 20,
        "has_more": False,
    }


@pytest.mark.parametrize(
    "collection",
    ["submissions", "entries"],
)
def test_maximum_page_size(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
    collection: str,
) -> None:
    item: LogSubmissionRecord | LogEntryRecord

    if collection == "submissions":
        url = endpoint
        method = service.list_submissions
        item = submission
    else:
        url = f"{endpoint}/{submission.id}/entries"
        method = service.list_entries
        item = entry

    method.return_value = LogPage(
        items=(item,),
        total=1,
        offset=0,
        limit=100,
    )

    response = client.get(
        url,
        params={"limit": 100},
    )

    assert response.status_code == 200
    assert response.json()["limit"] == 100


@pytest.mark.parametrize(
    "collection",
    ["submissions", "entries"],
)
@pytest.mark.parametrize(
    ("parameter", "value"),
    [
        ("offset", "-1"),
        ("offset", str(MAX_PAGE_OFFSET + 1)),
        ("offset", "invalid"),
        ("offset", "1.5"),
        ("limit", "0"),
        ("limit", "-1"),
        ("limit", "101"),
        ("limit", "invalid"),
        ("limit", "1.5"),
    ],
)
def test_invalid_pagination_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    collection: str,
    parameter: str,
    value: str,
) -> None:
    if collection == "submissions":
        url = endpoint
    else:
        url = f"{endpoint}/{submission.id}/entries"

    response = client.get(
        url,
        params={parameter: value},
    )

    assert response.status_code == 422

    service.list_submissions.assert_not_called()
    service.list_entries.assert_not_called()


@pytest.mark.parametrize(
    "severity",
    list(LogSeverity),
)
def test_severity_filter(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    severity: LogSeverity,
) -> None:
    service.list_entries.return_value = LogPage[LogEntryRecord](
        items=(),
        total=0,
        offset=0,
        limit=20,
    )

    response = client.get(
        f"{endpoint}/{submission.id}/entries",
        params={"severity": severity.value},
    )

    assert response.status_code == 200

    service.list_entries.assert_called_once_with(
        submission.incident_id,
        submission.id,
        offset=0,
        limit=20,
        severity=severity,
    )


@pytest.mark.parametrize(
    "severity",
    ["invalid", "", "fatal", "ERROR"],
)
def test_invalid_severity_rejected(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    severity: str,
) -> None:
    response = client.get(
        f"{endpoint}/{submission.id}/entries",
        params={"severity": severity},
    )

    assert response.status_code == 422

    service.list_entries.assert_not_called()


@pytest.mark.parametrize(
    "resource",
    [
        "submissions",
        "submission",
        "entries",
        "entry",
    ],
)
def test_missing_incident(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
    resource: str,
) -> None:
    routes = {
        "submissions": (
            endpoint,
            service.list_submissions,
        ),
        "submission": (
            f"{endpoint}/{submission.id}",
            service.get_submission,
        ),
        "entries": (
            f"{endpoint}/{submission.id}/entries",
            service.list_entries,
        ),
        "entry": (
            f"{endpoint}/{submission.id}/entries/{entry.id}",
            service.get_entry,
        ),
    }

    url, method = routes[resource]

    method.side_effect = IncidentNotFoundError(submission.incident_id)

    response = client.get(url)

    assert response.status_code == 404

    method.assert_called_once()


@pytest.mark.parametrize(
    "resource",
    ["submission", "entries", "entry"],
)
def test_missing_or_foreign_submission(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
    resource: str,
) -> None:
    foreign_id = uuid4()

    routes = {
        "submission": (
            f"{endpoint}/{foreign_id}",
            service.get_submission,
        ),
        "entries": (
            f"{endpoint}/{foreign_id}/entries",
            service.list_entries,
        ),
        "entry": (
            f"{endpoint}/{foreign_id}/entries/{entry.id}",
            service.get_entry,
        ),
    }

    url, method = routes[resource]

    error = LogSubmissionNotFoundError()
    error.args = ("SYNTHETIC_SECRET_CANARY",)

    method.side_effect = error

    response = client.get(url)

    assert response.status_code == 404
    assert "SYNTHETIC_SECRET_CANARY" not in response.text

    arguments = method.call_args.args

    assert arguments[0] == submission.incident_id
    assert arguments[1] == foreign_id


def test_missing_entry(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
) -> None:
    missing_id = uuid4()

    error = LogEntryNotFoundError()
    error.args = ("SYNTHETIC_SECRET_CANARY",)

    service.get_entry.side_effect = error

    response = client.get(f"{endpoint}/{submission.id}/entries/{missing_id}")

    assert response.status_code == 404
    assert "SYNTHETIC_SECRET_CANARY" not in response.text

    assert response.json()["detail"] == ("Application log entry was not found.")

    service.get_entry.assert_called_once_with(
        submission.incident_id,
        submission.id,
        missing_id,
    )


@pytest.mark.parametrize(
    "resource",
    [
        "incident",
        "submission",
        "entry_submission",
        "entry",
    ],
)
def test_invalid_resource_identifiers(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission: LogSubmissionRecord,
    resource: str,
) -> None:
    routes = {
        "incident": "/api/v1/incidents/invalid/logs",
        "submission": f"{endpoint}/invalid",
        "entry_submission": f"{endpoint}/invalid/entries",
        "entry": (f"{endpoint}/{submission.id}/entries/invalid"),
    }

    response = client.get(routes[resource])

    assert response.status_code == 422

    service.list_submissions.assert_not_called()
    service.get_submission.assert_not_called()
    service.list_entries.assert_not_called()
    service.get_entry.assert_not_called()


def test_submission_scope_forwarded(
    client: TestClient,
    service: MagicMock,
    submission: LogSubmissionRecord,
) -> None:
    other_incident: UUID = uuid4()

    service.get_submission.side_effect = LogSubmissionNotFoundError()

    response = client.get(f"/api/v1/incidents/{other_incident}/logs/{submission.id}")

    assert response.status_code == 404

    service.get_submission.assert_called_once_with(
        other_incident,
        submission.id,
    )


def test_retrieval_openapi_registration(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json()["paths"]

    prefix = "/api/v1/incidents/{incident_id}/logs"

    for suffix in (
        "",
        "/{submission_id}",
        "/{submission_id}/entries",
        "/{submission_id}/entries/{entry_id}",
    ):
        operation = paths[prefix + suffix]["get"]

        assert operation["tags"] == ["Application Logs"]
        assert "200" in operation["responses"]
        assert "404" in operation["responses"]

    assert "post" in paths[prefix]

    operation = paths[prefix + "/{submission_id}/entries"]["get"]

    parameters = {parameter["name"] for parameter in operation["parameters"]}

    assert {
        "incident_id",
        "submission_id",
        "offset",
        "limit",
        "severity",
    }.issubset(parameters)


@pytest.mark.parametrize(
    ("operation", "suffix"),
    [
        ("list_submissions", ""),
        ("get_submission", "/{submission_id}"),
        ("list_entries", "/{submission_id}/entries"),
        (
            "get_entry",
            "/{submission_id}/entries/{entry_id}",
        ),
    ],
)
def test_stored_content_integrity_error_is_confidential(
    client: TestClient,
    service: MagicMock,
    submission: LogSubmissionRecord,
    entry: LogEntryRecord,
    operation: str,
    suffix: str,
) -> None:
    canary = "SYNTHETIC_STORED_HTTP_SECRET_CANARY"

    error = LogPersistenceIntegrityError()
    error.args = (canary,)

    getattr(service, operation).side_effect = error

    prefix = f"/api/v1/incidents/{submission.incident_id}/logs"

    url = prefix + suffix.format(
        submission_id=submission.id,
        entry_id=entry.id,
    )

    response = client.get(url)

    assert response.status_code == 409

    assert response.json() == {
        "detail": "Stored application log content could not be verified.",
    }

    assert canary not in response.text

    getattr(service, operation).assert_called_once()


@pytest.mark.parametrize(
    "suffix",
    [
        "",
        "/{submission_id}",
        "/{submission_id}/entries",
        "/{submission_id}/entries/{entry_id}",
    ],
)
def test_stored_content_conflict_openapi_registration(
    client: TestClient,
    suffix: str,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    path = "/api/v1/incidents/{incident_id}/logs" + suffix

    operation = response.json()["paths"][path]["get"]

    assert {
        "200",
        "404",
        "409",
        "422",
    }.issubset(operation["responses"])

    assert operation["responses"]["409"]["description"] == (
        "Stored application log content is invalid"
    )
