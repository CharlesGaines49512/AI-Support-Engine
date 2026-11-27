from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import CheckConstraint, Table, UniqueConstraint

from app.core.base import Base
from app.models import LogEntry, LogSubmission
from app.models.log_enums import LogFormat, LogSeverity


@pytest.mark.parametrize(
    ("model", "table_name"),
    [
        (LogSubmission, "log_submissions"),
        (LogEntry, "log_entries"),
    ],
)
def test_log_model_registration(
    model: type[LogSubmission] | type[LogEntry],
    table_name: str,
) -> None:
    assert model.__tablename__ == table_name
    assert table_name in Base.metadata.tables


@pytest.mark.parametrize(
    "value",
    ["xml", "json", "text"],
)
def test_supported_log_formats(value: str) -> None:
    assert LogFormat(value).value == value


@pytest.mark.parametrize(
    "value",
    [
        "trace",
        "debug",
        "info",
        "warning",
        "error",
        "critical",
        "unknown",
    ],
)
def test_supported_log_severities(value: str) -> None:
    assert LogSeverity(value).value == value


def test_submission_incident_foreign_key() -> None:
    table = cast(Table, LogSubmission.__table__)

    foreign_key = next(iter(table.c.incident_id.foreign_keys))

    assert foreign_key.target_fullname == "incidents.id"
    assert foreign_key.ondelete == "CASCADE"
    assert table.c.incident_id.nullable is False


def test_entry_submission_foreign_key() -> None:
    table = cast(Table, LogEntry.__table__)

    foreign_key = next(iter(table.c.submission_id.foreign_keys))

    assert foreign_key.target_fullname == "log_submissions.id"
    assert foreign_key.ondelete == "CASCADE"
    assert table.c.submission_id.nullable is False


def test_submission_constraints() -> None:
    table = cast(Table, LogSubmission.__table__)

    constraints = {
        str(constraint.name)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert constraints == {
        "ck_log_submissions_payload_bytes_positive",
        "ck_log_submissions_entry_count_positive",
        "ck_log_submissions_redaction_count_nonnegative",
    }


def test_entry_constraints() -> None:
    table = cast(Table, LogEntry.__table__)

    constraints = {
        str(constraint.name)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert constraints == {
        "ck_log_entries_position_positive",
        "ck_log_entries_message_nonempty",
    }


def test_entry_position_uniqueness() -> None:
    table = cast(Table, LogEntry.__table__)

    unique_columns = [
        list(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    ]

    assert [
        "submission_id",
        "position",
    ] in unique_columns


def test_submission_indexes() -> None:
    table = cast(Table, LogSubmission.__table__)

    indexed_columns = [list(index.columns.keys()) for index in table.indexes]

    assert ["incident_id"] in indexed_columns
    assert ["created_at"] in indexed_columns


def test_entry_severity_index() -> None:
    table = cast(Table, LogEntry.__table__)

    indexed_columns = [list(index.columns.keys()) for index in table.indexes]

    assert ["severity"] in indexed_columns


def test_create_submission_model() -> None:
    incident_id = uuid4()

    submission = LogSubmission(
        incident_id=incident_id,
        source_format=LogFormat.XML,
        source_name="synthetic-application",
        payload_bytes=1500,
        entry_count=3,
        redaction_count=1,
    )

    assert submission.incident_id == incident_id
    assert submission.source_format == LogFormat.XML
    assert submission.payload_bytes == 1500
    assert submission.entry_count == 3
    assert submission.redaction_count == 1


def test_create_entry_model() -> None:
    submission_id = uuid4()

    entry = LogEntry(
        submission_id=submission_id,
        position=1,
        severity=LogSeverity.ERROR,
        message="Database connection failed.",
        error_code="DB_CONNECTION_ERROR",
    )

    assert entry.submission_id == submission_id
    assert entry.position == 1
    assert entry.severity == LogSeverity.ERROR
    assert entry.message == "Database connection failed."
    assert entry.error_code == "DB_CONNECTION_ERROR"
    assert entry.event_timestamp is None


@pytest.mark.parametrize(
    "model",
    [LogSubmission, LogEntry],
)
def test_raw_payload_not_stored(
    model: type[LogSubmission] | type[LogEntry],
) -> None:
    table = cast(Table, model.__table__)

    forbidden_columns = {
        "raw_payload",
        "raw_content",
        "raw_log",
        "raw_message",
        "unsanitized_content",
    }

    assert not (forbidden_columns & set(table.columns.keys()))


def test_optional_entry_metadata() -> None:
    table = cast(Table, LogEntry.__table__)

    optional_columns = [
        "event_timestamp",
        "original_severity",
        "service_name",
        "exception",
        "error_code",
        "correlation_id",
    ]

    for name in optional_columns:
        assert table.columns[name].nullable is True

    assert table.c.message.nullable is False
    assert table.c.severity.nullable is False
    assert table.c.position.nullable is False
