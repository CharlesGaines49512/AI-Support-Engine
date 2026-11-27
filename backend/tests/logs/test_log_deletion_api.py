from collections.abc import Generator
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.log_dependencies import get_log_query_service
from app.core.exceptions import IncidentNotFoundError
from app.logs.exceptions import LogSubmissionNotFoundError
from app.main import app
from app.services.log_query import LogQueryService


@pytest.fixture
def incident_id() -> UUID:
    return uuid4()


@pytest.fixture
def submission_id() -> UUID:
    return uuid4()


@pytest.fixture
def service() -> MagicMock:
    mock = MagicMock(spec=LogQueryService)
    mock.delete_submission.return_value = None
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
    incident_id: UUID,
    submission_id: UUID,
) -> str:
    return f"/api/v1/incidents/{incident_id}/logs/{submission_id}"


def test_delete_log_submission(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    submission_id: UUID,
) -> None:
    response = client.delete(endpoint)

    assert response.status_code == 204
    assert response.content == b""

    service.delete_submission.assert_called_once_with(
        incident_id,
        submission_id,
    )


def test_deletion_returns_no_content(
    client: TestClient,
    endpoint: str,
) -> None:
    response = client.delete(endpoint)

    assert response.status_code == 204
    assert response.text == ""
    assert "content-type" not in response.headers


def test_deletion_only_invokes_delete_operation(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    response = client.delete(endpoint)

    assert response.status_code == 204

    service.delete_submission.assert_called_once()
    service.get_submission.assert_not_called()
    service.list_submissions.assert_not_called()
    service.get_entry.assert_not_called()
    service.list_entries.assert_not_called()
    service.get_evidence.assert_not_called()


def test_delete_missing_incident(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    submission_id: UUID,
) -> None:
    service.delete_submission.side_effect = IncidentNotFoundError(incident_id)

    response = client.delete(endpoint)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Application log submission was not found.",
    }

    service.delete_submission.assert_called_once_with(
        incident_id,
        submission_id,
    )


def test_delete_missing_submission(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
) -> None:
    service.delete_submission.side_effect = LogSubmissionNotFoundError()

    response = client.delete(endpoint)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Application log submission was not found.",
    }

    service.delete_submission.assert_called_once()


def test_delete_foreign_submission(
    client: TestClient,
    service: MagicMock,
    incident_id: UUID,
    submission_id: UUID,
) -> None:
    foreign_incident_id = uuid4()

    assert foreign_incident_id != incident_id

    service.delete_submission.side_effect = LogSubmissionNotFoundError()

    response = client.delete(
        f"/api/v1/incidents/{foreign_incident_id}/logs/{submission_id}"
    )

    assert response.status_code == 404

    service.delete_submission.assert_called_once_with(
        foreign_incident_id,
        submission_id,
    )


def test_delete_preserves_resource_identifiers(
    client: TestClient,
    service: MagicMock,
) -> None:
    incident_id = uuid4()
    submission_id = uuid4()

    response = client.delete(f"/api/v1/incidents/{incident_id}/logs/{submission_id}")

    assert response.status_code == 204

    arguments = service.delete_submission.call_args.args

    assert arguments == (
        incident_id,
        submission_id,
    )

    assert isinstance(arguments[0], UUID)
    assert isinstance(arguments[1], UUID)


@pytest.mark.parametrize(
    "identifier",
    [
        "incident",
        "submission",
        "both",
    ],
)
def test_invalid_deletion_identifiers(
    client: TestClient,
    service: MagicMock,
    incident_id: UUID,
    submission_id: UUID,
    identifier: str,
) -> None:
    incident = str(incident_id)
    submission = str(submission_id)

    if identifier in ("incident", "both"):
        incident = "invalid-incident"

    if identifier in ("submission", "both"):
        submission = "invalid-submission"

    response = client.delete(f"/api/v1/incidents/{incident}/logs/{submission}")

    assert response.status_code == 422

    service.delete_submission.assert_not_called()


@pytest.mark.parametrize(
    "error_kind",
    [
        "incident",
        "submission",
    ],
)
def test_deletion_errors_are_sanitized(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    error_kind: str,
) -> None:
    error: Exception

    if error_kind == "incident":
        error = IncidentNotFoundError(incident_id)
    else:
        error = LogSubmissionNotFoundError()

    error.args = ("SYNTHETIC_SECRET_CANARY",)

    service.delete_submission.side_effect = error

    response = client.delete(endpoint)

    assert response.status_code == 404
    assert "SYNTHETIC_SECRET_CANARY" not in response.text

    assert response.json() == {
        "detail": "Application log submission was not found.",
    }


def test_missing_and_foreign_submissions_are_indistinguishable(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    submission_id: UUID,
) -> None:
    service.delete_submission.side_effect = LogSubmissionNotFoundError()

    missing = client.delete(endpoint)

    foreign = client.delete(f"/api/v1/incidents/{uuid4()}/logs/{submission_id}")

    assert missing.status_code == 404
    assert foreign.status_code == 404
    assert missing.json() == foreign.json()


def test_repeated_deletion(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
    submission_id: UUID,
) -> None:
    service.delete_submission.side_effect = [
        None,
        LogSubmissionNotFoundError(),
    ]

    first = client.delete(endpoint)
    second = client.delete(endpoint)

    assert first.status_code == 204
    assert first.content == b""

    assert second.status_code == 404

    assert service.delete_submission.call_count == 2

    for invocation in service.delete_submission.call_args_list:
        assert invocation.args == (
            incident_id,
            submission_id,
        )


def test_incident_and_submission_not_found_responses_match(
    client: TestClient,
    service: MagicMock,
    endpoint: str,
    incident_id: UUID,
) -> None:
    service.delete_submission.side_effect = [
        IncidentNotFoundError(incident_id),
        LogSubmissionNotFoundError(),
    ]

    first = client.delete(endpoint)
    second = client.delete(endpoint)

    assert first.status_code == 404
    assert second.status_code == 404
    assert first.json() == second.json()


def test_deletion_openapi_registration(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    document = response.json()

    path = "/api/v1/incidents/{incident_id}/logs/{submission_id}"

    operation = document["paths"][path]["delete"]

    assert operation["tags"] == ["Application Logs"]

    assert {
        "204",
        "404",
        "422",
    }.issubset(operation["responses"])

    assert "content" not in operation["responses"]["204"]
    assert "requestBody" not in operation

    parameters = {parameter["name"] for parameter in operation["parameters"]}

    assert parameters == {
        "incident_id",
        "submission_id",
    }


def test_existing_log_operations_remain_registered(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json()["paths"]

    prefix = "/api/v1/incidents/{incident_id}/logs"

    assert "post" in paths[prefix]
    assert "get" in paths[prefix]

    submission = prefix + "/{submission_id}"

    assert "get" in paths[submission]
    assert "delete" in paths[submission]

    assert "get" in paths[submission + "/entries"]

    assert "get" in paths[submission + "/entries/{entry_id}"]

    assert "get" in paths[submission + "/evidence"]
