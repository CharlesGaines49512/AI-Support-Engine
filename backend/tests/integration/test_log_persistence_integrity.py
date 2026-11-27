from collections.abc import Iterator
from dataclasses import replace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.logs.normalizer import LogNormalizer
from app.logs.sanitized_contracts import SanitizedLog
from app.logs.sanitizer import LogSanitizer
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.models.log_enums import LogFormat, LogSeverity
from app.repositories.application_log import ApplicationLogRepository


@pytest.fixture
def sanitized_log() -> SanitizedLog:
    settings = Settings(_env_file=None)

    payload = (
        b"INFO Workflow started\n"
        b"ERROR Database connection failed\n"
        b"CRITICAL Invalid signature\n"
        b"ERROR Authentication failed "
        b"password=SYNTHETIC_SECRET_CANARY"
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    return LogSanitizer(settings).sanitize(normalized)


@pytest.fixture
def committed_incident_id(
    integration_engine: Engine,
) -> Iterator[UUID]:
    incident_id = uuid4()

    try:
        with Session(integration_engine) as session:
            incident = Incident(
                id=incident_id,
                title="log-persistence-integrity-test",
                description="Synthetic transaction test.",
            )

            session.add(incident)
            session.commit()

        yield incident_id

    finally:
        with Session(integration_engine) as session:
            session.execute(delete(Incident).where(Incident.id == incident_id))

            session.commit()


@pytest.fixture
def incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="Log persistence integrity test",
        description="Synthetic rollback test.",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


def count_submissions(
    session: Session,
    incident_id: UUID,
) -> int:
    statement = (
        select(func.count())
        .select_from(LogSubmission)
        .where(LogSubmission.incident_id == incident_id)
    )

    return session.execute(statement).scalar_one()


def count_raw_entries(
    session: Session,
    submission_id: UUID,
) -> int:
    statement = (
        select(func.count())
        .select_from(LogEntry)
        .where(LogEntry.submission_id == submission_id)
    )

    return session.execute(statement).scalar_one()


def test_committed_submission_visible_in_new_session(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        repository = ApplicationLogRepository(writer)

        submission = repository.create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        writer.commit()

    with Session(integration_engine) as reader:
        repository = ApplicationLogRepository(reader)

        stored = repository.get_by_id(
            committed_incident_id,
            submission_id,
        )

        assert stored is not None
        assert stored.entry_count == 4
        assert stored.payload_bytes == sanitized_log.payload_bytes
        assert stored.redaction_count == sanitized_log.redaction_count

        entries = repository.list_entries(
            committed_incident_id,
            submission_id,
        )

        assert len(entries) == 4

        assert [entry.position for entry in entries] == [1, 2, 3, 4]

        assert [entry.message for entry in entries] == [
            entry.message for entry in sanitized_log.entries
        ]


def test_uncommitted_submission_invisible(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        repository = ApplicationLogRepository(writer)

        submission = repository.create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        assert (
            count_raw_entries(
                writer,
                submission_id,
            )
            == 4
        )

        with Session(integration_engine) as reader:
            assert (
                count_submissions(
                    reader,
                    committed_incident_id,
                )
                == 0
            )

            assert (
                count_raw_entries(
                    reader,
                    submission_id,
                )
                == 0
            )

        writer.rollback()


def test_commit_makes_all_records_visible(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        with Session(integration_engine) as reader:
            assert (
                count_submissions(
                    reader,
                    committed_incident_id,
                )
                == 0
            )

            assert (
                count_raw_entries(
                    reader,
                    submission_id,
                )
                == 0
            )

        writer.commit()

    with Session(integration_engine) as reader:
        assert (
            count_submissions(
                reader,
                committed_incident_id,
            )
            == 1
        )

        assert (
            count_raw_entries(
                reader,
                submission_id,
            )
            == 4
        )


def test_full_transaction_rollback_removes_all_records(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        writer.rollback()

    with Session(integration_engine) as reader:
        assert (
            count_submissions(
                reader,
                committed_incident_id,
            )
            == 0
        )

        assert (
            count_raw_entries(
                reader,
                submission_id,
            )
            == 0
        )

        assert (
            reader.get(
                Incident,
                committed_incident_id,
            )
            is not None
        )


def test_repository_does_not_commit_automatically(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        assert writer.in_transaction()

    # Closing an uncommitted session rolls back its transaction.

    with Session(integration_engine) as reader:
        assert (
            count_submissions(
                reader,
                committed_incident_id,
            )
            == 0
        )

        assert (
            count_raw_entries(
                reader,
                submission_id,
            )
            == 0
        )


def test_invalid_incident_foreign_key(
    integration_session: Session,
    sanitized_log: SanitizedLog,
) -> None:
    nonexistent_incident_id = uuid4()

    repository = ApplicationLogRepository(integration_session)

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            repository.create(
                nonexistent_incident_id,
                sanitized_log,
            )

    assert (
        count_submissions(
            integration_session,
            nonexistent_incident_id,
        )
        == 0
    )


@pytest.mark.parametrize(
    "position",
    [1, 2, 3, 4],
)
def test_failed_event_write_rolls_back_submission(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    position: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident_id = incident.id

    # Intentionally construct an invalid internal record to
    # exercise the database's VARCHAR(2000) constraint.

    entries = list(sanitized_log.entries)

    entries[position - 1] = replace(
        entries[position - 1],
        service_name="x" * 2001,
    )

    invalid_log = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    repository = ApplicationLogRepository(integration_session)

    # Exercise database constraints independently of preflight validation.
    monkeypatch.setattr(
        ApplicationLogRepository,
        "_validate_persistence_text",
        staticmethod(lambda value, limit: None),
    )

    with pytest.raises(DataError):
        with integration_session.begin_nested():
            repository.create(
                incident_id,
                invalid_log,
            )

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 0
    )

    valid = repository.create(
        incident_id,
        sanitized_log,
    )

    assert valid.entry_count == 4

    assert (
        count_raw_entries(
            integration_session,
            valid.id,
        )
        == 4
    )


def test_failed_write_preserves_existing_submission(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    existing = repository.create(
        incident.id,
        sanitized_log,
    )

    incident_id = incident.id
    existing_id = existing.id

    invalid = replace(
        sanitized_log,
        entries=(
            replace(
                sanitized_log.entries[0],
                service_name="x" * 2001,
            ),
        ),
    )

    # Exercise database constraints independently of preflight validation.
    monkeypatch.setattr(
        ApplicationLogRepository,
        "_validate_persistence_text",
        staticmethod(lambda value, limit: None),
    )

    with pytest.raises(DataError):
        with integration_session.begin_nested():
            repository.create(
                incident_id,
                invalid,
            )

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 1
    )

    assert (
        count_raw_entries(
            integration_session,
            existing_id,
        )
        == 4
    )

    assert (
        repository.get_by_id(
            incident_id,
            existing_id,
        )
        is not None
    )


def test_failed_full_transaction_leaves_no_records(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = replace(
        sanitized_log,
        entries=(
            replace(
                sanitized_log.entries[0],
                service_name="x" * 2001,
            ),
        ),
    )

    with Session(integration_engine) as writer:
        repository = ApplicationLogRepository(writer)

        # Exercise database constraints independently of preflight validation.
        monkeypatch.setattr(
            ApplicationLogRepository,
            "_validate_persistence_text",
            staticmethod(lambda value, limit: None),
        )

        with pytest.raises(DataError):
            repository.create(
                committed_incident_id,
                invalid,
            )

        writer.rollback()

    with Session(integration_engine) as reader:
        assert (
            count_submissions(
                reader,
                committed_incident_id,
            )
            == 0
        )

        assert (
            reader.get(
                Incident,
                committed_incident_id,
            )
            is not None
        )


def test_submission_delete_removes_actual_event_rows(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    submission_id = submission.id

    assert (
        count_raw_entries(
            integration_session,
            submission_id,
        )
        == 4
    )

    assert (
        repository.delete(
            incident.id,
            submission_id,
        )
        is True
    )

    # Query LogEntry directly, without joining LogSubmission.
    # A joined query could conceal orphaned event rows.

    assert (
        count_raw_entries(
            integration_session,
            submission_id,
        )
        == 0
    )


def test_incident_delete_cascades_to_all_log_records(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    first = repository.create(
        incident.id,
        sanitized_log,
    )

    second = repository.create(
        incident.id,
        sanitized_log,
    )

    incident_id = incident.id
    submission_ids = (first.id, second.id)

    integration_session.delete(incident)
    integration_session.flush()

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 0
    )

    for submission_id in submission_ids:
        assert (
            count_raw_entries(
                integration_session,
                submission_id,
            )
            == 0
        )


def test_submission_delete_rollback_restores_records(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    incident_id = incident.id
    submission_id = submission.id

    transaction = integration_session.begin_nested()

    assert (
        repository.delete(
            incident_id,
            submission_id,
        )
        is True
    )

    assert (
        count_raw_entries(
            integration_session,
            submission_id,
        )
        == 0
    )

    transaction.rollback()

    assert (
        repository.get_by_id(
            incident_id,
            submission_id,
        )
        is not None
    )

    assert (
        count_raw_entries(
            integration_session,
            submission_id,
        )
        == 4
    )


def test_committed_deletion_visible_in_new_session(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        writer.commit()

    with Session(integration_engine) as writer:
        repository = ApplicationLogRepository(writer)

        assert (
            repository.delete(
                committed_incident_id,
                submission_id,
            )
            is True
        )

        writer.commit()

    with Session(integration_engine) as reader:
        assert (
            count_submissions(
                reader,
                committed_incident_id,
            )
            == 0
        )

        assert (
            count_raw_entries(
                reader,
                submission_id,
            )
            == 0
        )


def test_uncommitted_deletion_invisible_to_reader(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        writer.commit()

    with Session(integration_engine) as writer:
        repository = ApplicationLogRepository(writer)

        assert (
            repository.delete(
                committed_incident_id,
                submission_id,
            )
            is True
        )

        assert (
            count_raw_entries(
                writer,
                submission_id,
            )
            == 0
        )

        with Session(integration_engine) as reader:
            assert (
                count_submissions(
                    reader,
                    committed_incident_id,
                )
                == 1
            )

            assert (
                count_raw_entries(
                    reader,
                    submission_id,
                )
                == 4
            )

        writer.rollback()

    with Session(integration_engine) as reader:
        assert (
            count_raw_entries(
                reader,
                submission_id,
            )
            == 4
        )


def test_incident_cascade_preserves_unrelated_records(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    other = Incident(
        title="Unrelated incident",
        description="Synthetic isolation test.",
    )

    integration_session.add(other)
    integration_session.flush()

    repository = ApplicationLogRepository(integration_session)

    first = repository.create(
        incident.id,
        sanitized_log,
    )

    second = repository.create(
        other.id,
        sanitized_log,
    )

    first_id = first.id
    second_id = second.id
    other_id = other.id

    integration_session.delete(incident)
    integration_session.flush()

    assert (
        count_raw_entries(
            integration_session,
            first_id,
        )
        == 0
    )

    assert (
        count_raw_entries(
            integration_session,
            second_id,
        )
        == 4
    )

    assert (
        count_submissions(
            integration_session,
            other_id,
        )
        == 1
    )


def test_duplicate_event_position_database_constraint(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = ApplicationLogRepository(integration_session).create(
        incident.id,
        sanitized_log,
    )

    submission_id = submission.id

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            duplicate = LogEntry(
                submission_id=submission_id,
                position=1,
                severity=LogSeverity.ERROR,
                message="Duplicate position",
            )

            integration_session.add(duplicate)
            integration_session.flush()

    assert (
        count_raw_entries(
            integration_session,
            submission_id,
        )
        == 4
    )


def test_orphan_event_rejected_by_database(
    integration_session: Session,
) -> None:
    nonexistent_submission_id = uuid4()

    with pytest.raises(IntegrityError):
        with integration_session.begin_nested():
            entry = LogEntry(
                submission_id=nonexistent_submission_id,
                position=1,
                severity=LogSeverity.ERROR,
                message="Synthetic orphan",
            )

            integration_session.add(entry)
            integration_session.flush()

    assert (
        count_raw_entries(
            integration_session,
            nonexistent_submission_id,
        )
        == 0
    )


def test_committed_redaction_survives_session_boundary(
    integration_engine: Engine,
    committed_incident_id: UUID,
    sanitized_log: SanitizedLog,
) -> None:
    canary = "SYNTHETIC_SECRET_CANARY"

    with Session(integration_engine) as writer:
        submission = ApplicationLogRepository(writer).create(
            committed_incident_id,
            sanitized_log,
        )

        submission_id = submission.id

        writer.commit()

    with Session(integration_engine) as reader:
        repository = ApplicationLogRepository(reader)

        stored = repository.get_by_id(
            committed_incident_id,
            submission_id,
        )

        assert stored is not None
        assert stored.redaction_count > 0

        entries = repository.list_entries(
            committed_incident_id,
            submission_id,
        )

        assert len(entries) == 4

        for entry in entries:
            fields = (
                entry.message,
                entry.exception,
                entry.original_severity,
                entry.service_name,
                entry.error_code,
                entry.correlation_id,
            )

            assert all(canary not in (value or "") for value in fields)

        assert "Authentication failed" in entries[3].message


REPOSITORY_SECURITY_CANARY = "SYNTHETIC_REPOSITORY_SECRET_CANARY"

REPOSITORY_SECURITY_FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)

REPOSITORY_UNSAFE_VALUES = (
    f"password={REPOSITORY_SECURITY_CANARY}",
    f"api key={REPOSITORY_SECURITY_CANARY}",
    f"secret key={REPOSITORY_SECURITY_CANARY}",
    f"Bearer {REPOSITORY_SECURITY_CANARY}",
    f"password=[REDACTED_SECRET]{REPOSITORY_SECURITY_CANARY}",
    f"Bearer [REDACTED_TOKEN]{REPOSITORY_SECURITY_CANARY}",
    f"Bearer [REDACTED_TOKEN={REPOSITORY_SECURITY_CANARY}]",
    f"postgresql://user:{REPOSITORY_SECURITY_CANARY}@localhost/db",
)

REPOSITORY_SAFE_VALUES = (
    "Synthetic diagnostic information.",
    "password=[REDACTED_SECRET]",
    "Bearer [REDACTED_TOKEN]",
    "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
    "[REDACTED_EMAIL]",
    "[REDACTED]",
)


@pytest.mark.parametrize("field", REPOSITORY_SECURITY_FIELDS)
@pytest.mark.parametrize("value", REPOSITORY_UNSAFE_VALUES)
@pytest.mark.parametrize("position", [1, 4])
def test_repository_security_rejects_unsafe_entry(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    field: str,
    value: str,
    position: int,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    incident_id = incident.id

    entries = list(sanitized_log.entries)

    entries[position - 1] = replace(
        entries[position - 1], **cast(dict[str, Any], {field: value})
    )

    invalid_log = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    with pytest.raises(ValueError) as error:
        repository.create(
            incident_id,
            invalid_log,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    assert not integration_session.new
    assert not integration_session.dirty

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 0
    )

    valid = repository.create(
        incident_id,
        sanitized_log,
    )

    assert valid.entry_count == sanitized_log.entry_count

    assert (
        count_raw_entries(
            integration_session,
            valid.id,
        )
        == sanitized_log.entry_count
    )


@pytest.mark.parametrize("value", REPOSITORY_UNSAFE_VALUES)
def test_repository_security_rejects_unsafe_source_name(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    value: str,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    incident_id = incident.id

    with pytest.raises(ValueError) as error:
        repository.create(
            incident_id,
            sanitized_log,
            source_name=value,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    assert not integration_session.new
    assert not integration_session.dirty

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 0
    )

    valid = repository.create(
        incident_id,
        sanitized_log,
        source_name="application.log",
    )

    assert valid.source_name == "application.log"


@pytest.mark.parametrize("field", REPOSITORY_SECURITY_FIELDS)
@pytest.mark.parametrize("value", REPOSITORY_SAFE_VALUES)
def test_repository_security_preserves_safe_entry(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    field: str,
    value: str,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    entries = list(sanitized_log.entries)

    entries[1] = replace(entries[1], **cast(dict[str, Any], {field: value}))

    valid_log = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    submission = repository.create(
        incident.id,
        valid_log,
    )

    stored_entries = repository.list_entries(
        incident.id,
        submission.id,
    )

    assert len(stored_entries) == valid_log.entry_count

    assert getattr(stored_entries[1], field) == value

    assert submission.redaction_count == (valid_log.redaction_count)


@pytest.mark.parametrize(
    "value",
    (None, *REPOSITORY_SAFE_VALUES),
)
def test_repository_security_preserves_safe_source_name(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    value: str | None,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    submission = repository.create(
        incident.id,
        sanitized_log,
        source_name=value,
    )

    assert submission.source_name == value

    stored = repository.get_by_id(
        incident.id,
        submission.id,
    )

    assert stored is not None
    assert stored.source_name == value


def test_repository_security_preserves_existing_submission(
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    repository = ApplicationLogRepository(integration_session)

    incident_id = incident.id

    existing = repository.create(
        incident_id,
        sanitized_log,
    )

    existing_id = existing.id

    before = [
        entry.message
        for entry in repository.list_entries(
            incident_id,
            existing_id,
        )
    ]

    entries = list(sanitized_log.entries)

    entries[-1] = replace(
        entries[-1],
        message=f"password={REPOSITORY_SECURITY_CANARY}",
    )

    invalid_log = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    with pytest.raises(ValueError) as error:
        repository.create(
            incident_id,
            invalid_log,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    assert not integration_session.new
    assert not integration_session.dirty

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 1
    )

    assert (
        count_raw_entries(
            integration_session,
            existing_id,
        )
        == sanitized_log.entry_count
    )

    after = [
        entry.message
        for entry in repository.list_entries(
            incident_id,
            existing_id,
        )
    ]

    assert before == after

    another = repository.create(
        incident_id,
        sanitized_log,
    )

    assert another.id != existing_id

    assert (
        count_submissions(
            integration_session,
            incident_id,
        )
        == 2
    )


@pytest.mark.parametrize("field", REPOSITORY_SECURITY_FIELDS)
@pytest.mark.parametrize("value", REPOSITORY_UNSAFE_VALUES)
@pytest.mark.parametrize("position", [1, 4])
def test_repository_security_prevents_session_interactions(
    sanitized_log: SanitizedLog,
    field: str,
    value: str,
    position: int,
) -> None:
    from unittest.mock import MagicMock

    session = MagicMock(spec=Session)
    repository = ApplicationLogRepository(session)

    entries = list(sanitized_log.entries)

    entries[position - 1] = replace(
        entries[position - 1], **cast(dict[str, Any], {field: value})
    )

    invalid = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    with pytest.raises(ValueError) as error:
        repository.create(
            uuid4(),
            invalid,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    session.add.assert_not_called()
    session.add_all.assert_not_called()
    session.flush.assert_not_called()
    session.commit.assert_not_called()
    session.rollback.assert_not_called()
    session.execute.assert_not_called()
    session.refresh.assert_not_called()

    assert session.mock_calls == []


@pytest.mark.parametrize("value", REPOSITORY_UNSAFE_VALUES)
def test_repository_security_source_prevents_session_interactions(
    sanitized_log: SanitizedLog,
    value: str,
) -> None:
    from unittest.mock import MagicMock

    session = MagicMock(spec=Session)
    repository = ApplicationLogRepository(session)

    with pytest.raises(ValueError) as error:
        repository.create(
            uuid4(),
            sanitized_log,
            source_name=value,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    session.add.assert_not_called()
    session.add_all.assert_not_called()
    session.flush.assert_not_called()
    session.commit.assert_not_called()
    session.rollback.assert_not_called()

    assert session.mock_calls == []


@pytest.mark.parametrize("location", ["entry", "source"])
def test_repository_security_rejects_multiple_unsafe_fields(
    sanitized_log: SanitizedLog,
    location: str,
) -> None:
    from unittest.mock import MagicMock

    session = MagicMock(spec=Session)
    repository = ApplicationLogRepository(session)

    entries = list(sanitized_log.entries)
    source_name = None

    if location == "entry":
        entries[-1] = replace(
            entries[-1],
            message=f"password={REPOSITORY_SECURITY_CANARY}",
            exception=f"Bearer {REPOSITORY_SECURITY_CANARY}",
            correlation_id=f"api key={REPOSITORY_SECURITY_CANARY}",
        )
    else:
        source_name = f"password={REPOSITORY_SECURITY_CANARY}"

        entries[-1] = replace(
            entries[-1],
            message=f"secret key={REPOSITORY_SECURITY_CANARY}",
        )

    invalid = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    with pytest.raises(ValueError) as error:
        repository.create(
            uuid4(),
            invalid,
            source_name=source_name,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert REPOSITORY_SECURITY_CANARY not in str(error.value)

    assert session.mock_calls == []


@pytest.mark.parametrize(
    "field",
    [
        "message",
        "original_severity",
        "service_name",
        "exception",
        "error_code",
        "correlation_id",
        "source_name",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        123,
        True,
        b"synthetic-bytes",
        ["synthetic-list"],
        {"synthetic": "mapping"},
    ],
)
def test_repository_security_rejects_invalid_text_types(
    sanitized_log: SanitizedLog,
    field: str,
    value: object,
) -> None:
    from typing import cast
    from unittest.mock import MagicMock

    session = MagicMock(spec=Session)
    repository = ApplicationLogRepository(session)

    entries = list(sanitized_log.entries)

    source_name = None

    if field == "source_name":
        source_name = cast(str, value)
    else:
        entries[-1] = replace(entries[-1], **cast(dict[str, Any], {field: value}))

    invalid_log = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    with pytest.raises(ValueError) as error:
        repository.create(
            uuid4(),
            invalid_log,
            source_name=source_name,
        )

    assert str(error.value) == ("Log persistence requires safe sanitized content.")

    assert session.mock_calls == []
