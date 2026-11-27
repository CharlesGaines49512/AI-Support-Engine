"""Verify PostgreSQL enforcement of database integrity contracts."""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.models import AIAnalysis, Incident, LogEntry, LogSubmission

MODELS = {
    "incidents": Incident,
    "ai_analyses": AIAnalysis,
    "log_submissions": LogSubmission,
    "log_entries": LogEntry,
}

REQUIRED_COLUMNS = {
    "incidents": (
        "id",
        "title",
        "description",
        "status",
        "priority",
        "created_at",
        "updated_at",
    ),
    "ai_analyses": (
        "id",
        "incident_id",
        "status",
        "provider",
        "model",
        "prompt_version",
        "created_at",
    ),
    "log_submissions": (
        "id",
        "incident_id",
        "source_format",
        "payload_bytes",
        "entry_count",
        "redaction_count",
        "created_at",
    ),
    "log_entries": (
        "id",
        "submission_id",
        "position",
        "severity",
        "message",
    ),
}

NULL_CASES = [
    (table, column) for table, columns in REQUIRED_COLUMNS.items() for column in columns
]

ENUM_CASES = [
    ("incidents", "status", "incident_status"),
    ("incidents", "priority", "incident_priority"),
    ("ai_analyses", "status", "ai_analysis_status"),
    ("log_submissions", "source_format", "log_format"),
    ("log_entries", "severity", "log_severity"),
]


@pytest.fixture
def record_ids(
    integration_session: Session,
) -> dict[str, UUID]:
    session = integration_session

    database = session.execute(text("SELECT current_database()")).scalar_one()

    assert database == "ai_support_engine_migration_test"

    revision = session.execute(
        text("SELECT version_num FROM alembic_version")
    ).scalar_one()

    assert revision == "8e47c2a19b60"

    ids = {table: uuid4() for table in MODELS}

    session.execute(
        text(
            """
            INSERT INTO incidents (
                id, title, description
            )
            VALUES (
                :id,
                'Synthetic constraint acceptance',
                'Database enforcement test fixture.'
            )
            """
        ),
        {"id": ids["incidents"]},
    )

    session.execute(
        text(
            """
            INSERT INTO ai_analyses (
                id, incident_id, status,
                provider, model, prompt_version,
                error_code, error_message
            )
            VALUES (
                :id, :incident_id, 'failed',
                'openai', 'synthetic-model',
                'constraint-test-v1',
                'synthetic_failure',
                'Synthetic test failure.'
            )
            """
        ),
        {
            "id": ids["ai_analyses"],
            "incident_id": ids["incidents"],
        },
    )

    session.execute(
        text(
            """
            INSERT INTO log_submissions (
                id, incident_id, source_format,
                payload_bytes, entry_count,
                redaction_count
            )
            VALUES (
                :id, :incident_id, 'text',
                100, 1, 0
            )
            """
        ),
        {
            "id": ids["log_submissions"],
            "incident_id": ids["incidents"],
        },
    )

    session.execute(
        text(
            """
            INSERT INTO log_entries (
                id, submission_id, position,
                severity, message
            )
            VALUES (
                :id, :submission_id, 1,
                'error',
                'Synthetic constraint acceptance event.'
            )
            """
        ),
        {
            "id": ids["log_entries"],
            "submission_id": ids["log_submissions"],
        },
    )

    return ids


def assert_original_record_exists(
    session: Session,
    table: str,
    identifier: UUID,
) -> None:
    model = MODELS[table]

    database_table = model.__table__
    count = session.execute(
        select(func.count())
        .select_from(database_table)
        .where(database_table.c.id == identifier)
    ).scalar_one()

    assert count == 1


@pytest.mark.parametrize("table", list(MODELS))
def test_database_rejects_duplicate_primary_key(
    integration_session: Session,
    record_ids: dict[str, UUID],
    table: str,
) -> None:
    model = MODELS[table]

    columns = [column.name for column in model.__table__.columns]

    source_columns = [
        "position + 1" if table == "log_entries" and column == "position" else column
        for column in columns
    ]

    statement = text(
        f"INSERT INTO public.{table} "
        f"({', '.join(columns)}) "
        f"SELECT {', '.join(source_columns)} "
        f"FROM public.{table} "
        "WHERE id = :id"
    )

    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            integration_session.execute(
                statement,
                {"id": record_ids[table]},
            )

    original = captured.value.orig

    assert getattr(original, "sqlstate", None) == "23505"

    diagnostic = getattr(original, "diag", None)

    assert getattr(diagnostic, "constraint_name", None) == (f"pk_{table}")

    assert_original_record_exists(
        integration_session,
        table,
        record_ids[table],
    )


@pytest.mark.parametrize(
    ("table", "column"),
    NULL_CASES,
)
def test_database_rejects_null_required_column(
    integration_session: Session,
    record_ids: dict[str, UUID],
    table: str,
    column: str,
) -> None:
    assert column in REQUIRED_COLUMNS[table]

    statement = text(f"UPDATE public.{table} SET {column} = NULL WHERE id = :id")

    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            integration_session.execute(
                statement,
                {"id": record_ids[table]},
            )

    original = captured.value.orig

    assert getattr(original, "sqlstate", None) == "23502"

    diagnostic = getattr(original, "diag", None)

    assert getattr(diagnostic, "table_name", None) == table
    assert getattr(diagnostic, "column_name", None) == column

    assert_original_record_exists(
        integration_session,
        table,
        record_ids[table],
    )

    restored = integration_session.execute(
        text(f"SELECT {column} FROM public.{table} WHERE id = :id"),
        {"id": record_ids[table]},
    ).scalar_one()

    assert restored is not None


@pytest.mark.parametrize(
    ("table", "column", "enum_type"),
    ENUM_CASES,
)
def test_database_rejects_invalid_enum_value(
    integration_session: Session,
    record_ids: dict[str, UUID],
    table: str,
    column: str,
    enum_type: str,
) -> None:
    assert (table, column, enum_type) in ENUM_CASES

    statement = text(
        f"UPDATE public.{table} "
        f"SET {column} = CAST(:value AS {enum_type}) "
        "WHERE id = :id"
    )

    previous = integration_session.execute(
        text(f"SELECT {column} FROM public.{table} WHERE id = :id"),
        {"id": record_ids[table]},
    ).scalar_one()

    with pytest.raises(DataError) as captured:
        with integration_session.begin_nested():
            integration_session.execute(
                statement,
                {
                    "id": record_ids[table],
                    "value": "unsupported_synthetic_enum_value",
                },
            )

    original = captured.value.orig

    assert getattr(original, "sqlstate", None) == "22P02"

    assert_original_record_exists(
        integration_session,
        table,
        record_ids[table],
    )

    restored = integration_session.execute(
        text(f"SELECT {column} FROM public.{table} WHERE id = :id"),
        {"id": record_ids[table]},
    ).scalar_one()

    assert restored == previous


def capture_record(
    session: Session,
    table: str,
    identifier: UUID,
) -> dict[str, object] | None:
    assert table in MODELS

    result = (
        session.execute(
            text(f"SELECT * FROM public.{table} WHERE id = :id"),
            {"id": identifier},
        )
        .mappings()
        .one_or_none()
    )

    return None if result is None else dict(result)


def capture_graph(
    session: Session,
    identifiers: dict[str, UUID],
) -> dict[str, dict[str, object] | None]:
    return {
        table: capture_record(
            session,
            table,
            identifier,
        )
        for table, identifier in identifiers.items()
    }


@pytest.fixture
def independent_record_ids(
    integration_session: Session,
    record_ids: dict[str, UUID],
) -> dict[str, UUID]:
    identifiers = {table: uuid4() for table in MODELS}

    for table in (
        "incidents",
        "ai_analyses",
        "log_submissions",
        "log_entries",
    ):
        model = MODELS[table]

        columns = [column.name for column in model.__table__.columns]

        replacements = {
            "id": ":new_id",
        }

        parameters = {
            "new_id": identifiers[table],
            "old_id": record_ids[table],
        }

        if table in {
            "ai_analyses",
            "log_submissions",
        }:
            replacements["incident_id"] = ":new_incident"

            parameters["new_incident"] = identifiers["incidents"]

        if table == "log_entries":
            replacements["submission_id"] = ":new_submission"

            parameters["new_submission"] = identifiers["log_submissions"]

        selected = [replacements.get(column, column) for column in columns]

        result = integration_session.execute(
            text(
                f"INSERT INTO public.{table} "
                f"({', '.join(columns)}) "
                f"SELECT {', '.join(selected)} "
                f"FROM public.{table} "
                "WHERE id = :old_id"
            ),
            parameters,
        )

        assert isinstance(result, CursorResult)
        assert result.rowcount == 1

    return identifiers


def test_complete_incident_cascade_preserves_independent_graph(
    integration_session: Session,
    record_ids: dict[str, UUID],
    independent_record_ids: dict[str, UUID],
) -> None:
    session = integration_session

    protected = capture_graph(
        session,
        independent_record_ids,
    )

    assert all(record is not None for record in protected.values())

    result = session.execute(
        text("DELETE FROM incidents WHERE id = :id"),
        {"id": record_ids["incidents"]},
    )

    assert isinstance(result, CursorResult)
    assert result.rowcount == 1

    removed = capture_graph(
        session,
        record_ids,
    )

    assert all(record is None for record in removed.values())

    assert (
        capture_graph(
            session,
            independent_record_ids,
        )
        == protected
    )


def test_selective_submission_deletion_preserves_other_records(
    integration_session: Session,
    record_ids: dict[str, UUID],
    independent_record_ids: dict[str, UUID],
) -> None:
    session = integration_session

    session.execute(
        text(
            "UPDATE log_submissions "
            "SET incident_id = :incident_id "
            "WHERE id = :submission_id"
        ),
        {
            "incident_id": record_ids["incidents"],
            "submission_id": independent_record_ids["log_submissions"],
        },
    )

    original = capture_graph(session, record_ids)

    protected = capture_graph(
        session,
        independent_record_ids,
    )

    result = session.execute(
        text("DELETE FROM log_submissions WHERE id = :id"),
        {"id": record_ids["log_submissions"]},
    )

    assert isinstance(result, CursorResult)
    assert result.rowcount == 1

    remaining = capture_graph(
        session,
        record_ids,
    )

    assert remaining["incidents"] == original["incidents"]
    assert remaining["ai_analyses"] == original["ai_analyses"]
    assert remaining["log_submissions"] is None
    assert remaining["log_entries"] is None

    assert (
        capture_graph(
            session,
            independent_record_ids,
        )
        == protected
    )


def test_submission_deletion_preserves_historical_provenance(
    integration_session: Session,
    record_ids: dict[str, UUID],
    independent_record_ids: dict[str, UUID],
) -> None:
    session = integration_session

    session.execute(
        text(
            """
            UPDATE ai_analyses
            SET
                log_submission_id = :submission_id,
                log_evidence_version = :version,
                log_evidence_sha256 = :digest,
                log_evidence_event_count = 1
            WHERE id = :analysis_id
            """
        ),
        {
            "submission_id": record_ids["log_submissions"],
            "version": "synthetic-provenance-v1",
            "digest": "a" * 64,
            "analysis_id": record_ids["ai_analyses"],
        },
    )

    analysis_before = capture_record(
        session,
        "ai_analyses",
        record_ids["ai_analyses"],
    )

    assert analysis_before is not None

    assert analysis_before["log_submission_id"] == (record_ids["log_submissions"])

    assert analysis_before["log_evidence_sha256"] == "a" * 64

    protected = capture_graph(
        session,
        independent_record_ids,
    )

    result = session.execute(
        text("DELETE FROM log_submissions WHERE id = :id"),
        {"id": record_ids["log_submissions"]},
    )

    assert isinstance(result, CursorResult)
    assert result.rowcount == 1

    assert (
        capture_record(
            session,
            "log_submissions",
            record_ids["log_submissions"],
        )
        is None
    )

    assert (
        capture_record(
            session,
            "log_entries",
            record_ids["log_entries"],
        )
        is None
    )

    assert (
        capture_record(
            session,
            "ai_analyses",
            record_ids["ai_analyses"],
        )
        == analysis_before
    )

    assert_original_record_exists(
        session,
        "incidents",
        record_ids["incidents"],
    )

    assert (
        capture_graph(
            session,
            independent_record_ids,
        )
        == protected
    )


def test_cascading_deletion_rollback_restores_complete_graph(
    integration_session: Session,
    record_ids: dict[str, UUID],
    independent_record_ids: dict[str, UUID],
) -> None:
    session = integration_session

    original = capture_graph(session, record_ids)

    protected = capture_graph(
        session,
        independent_record_ids,
    )

    assert all(record is not None for record in original.values())

    with pytest.raises(
        RuntimeError,
        match="synthetic cascade rollback",
    ):
        with session.begin_nested():
            result = session.execute(
                text("DELETE FROM incidents WHERE id = :id"),
                {"id": record_ids["incidents"]},
            )

            assert isinstance(result, CursorResult)
            assert result.rowcount == 1

            assert all(
                record is None
                for record in capture_graph(
                    session,
                    record_ids,
                ).values()
            )

            assert (
                capture_graph(
                    session,
                    independent_record_ids,
                )
                == protected
            )

            raise RuntimeError("synthetic cascade rollback")

    assert (
        capture_graph(
            session,
            record_ids,
        )
        == original
    )

    assert (
        capture_graph(
            session,
            independent_record_ids,
        )
        == protected
    )
