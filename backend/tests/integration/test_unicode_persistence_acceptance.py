import json
from collections.abc import Iterator
from uuid import UUID, uuid4
from xml.sax.saxutils import escape

import pytest
from sqlalchemy import delete, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.models.log_enums import LogFormat
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    UnsafeLogContentError,
)
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_UNICODE_POSTGRESQL_CANARY"

ENCODINGS = (
    (LogFormat.TEXT, False),
    (LogFormat.JSON, False),
    (LogFormat.JSON, True),
    (LogFormat.XML, False),
    (LogFormat.XML, True),
)

STRUCTURED_ENCODINGS = (
    (LogFormat.JSON, False),
    (LogFormat.JSON, True),
    (LogFormat.XML, False),
    (LogFormat.XML, True),
)

FIELDS = (
    ("severity", "original_severity"),
    ("service_name", "service_name"),
    ("exception", "exception"),
    ("error_code", "error_code"),
    ("correlation_id", "correlation_id"),
)

ENTRY_FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


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
def incident_id(
    factory: sessionmaker[Session],
) -> Iterator[UUID]:
    identifier = uuid4()

    try:
        with factory.begin() as session:
            session.add(
                Incident(
                    id=identifier,
                    title="Unicode persistence acceptance",
                    description="Synthetic Unicode security test.",
                )
            )

        yield identifier

    finally:
        with factory.begin() as session:
            session.execute(delete(Incident).where(Incident.id == identifier))


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


PREFIXES = (
    fullwidth("password") + "\uff1a",
    fullwidth("api") + "_\u00a0" + fullwidth("key") + "\ufe66",
    fullwidth("access") + "\uff3f\u3000" + fullwidth("token") + "\ufe55",
    fullwidth("client_secret") + "\uff1d",
    "secret-\u2003_key=",
    fullwidth("refresh_token") + ":",
)

REDACTION_CASES = tuple(
    (
        prefix + CANARY,
        prefix + "[REDACTED_SECRET]",
    )
    for prefix in PREFIXES
) + tuple(
    (
        scheme + "\u3000" + CANARY,
        scheme + " [REDACTED_TOKEN]",
    )
    for scheme in (
        fullwidth("Bearer"),
        fullwidth("Basic"),
        "B\uff45arer",
        "B\uff41sic",
    )
)

PRESERVATION_CASES = (
    "\u63a5\u7d9a\u5931\u6557",
    "\u670d\u52a1\u4e0d\u53ef\u7528",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\uff33\uff45\uff52\uff56\uff49\uff43\uff45",
    "caf\u00e9",
    "cafe\u0301",
)

UNSAFE_CASES = (
    PREFIXES[0][0] + "\u200c" + PREFIXES[0][1:] + CANARY,
    PREFIXES[1][0] + "\u200d" + PREFIXES[1][1:] + CANARY,
    PREFIXES[2],
    PREFIXES[3],
    fullwidth("Bearer") + " [REDACTED_TOKEN]" + CANARY,
    fullwidth("Basic") + " [REDACTED_TOKEN=" + CANARY + "]",
)

CONTROL_CASES = (
    "\u200b",
    "\u202e",
    "\u2060",
    "\ufeff",
)


def xml_value(value: str, escaped: bool) -> str:
    if not escaped:
        return escape(value)

    return "".join(
        f"&#x{ord(character):x};" if ord(character) > 127 else escape(character)
        for character in value
    )


def make_payload(
    source_format: LogFormat,
    escaped: bool,
    fields: dict[str, str],
) -> bytes:
    if source_format == LogFormat.JSON:
        return json.dumps(
            fields,
            ensure_ascii=escaped,
        ).encode()

    if source_format == LogFormat.XML:
        children = "".join(
            f"<{name}>" + xml_value(value, escaped) + f"</{name}>"
            for name, value in fields.items()
        )

        return f"<entry>{children}</entry>".encode()

    assert set(fields) == {"severity", "message"}

    return (fields["severity"] + " " + fields["message"]).encode()


def assert_no_persistence(
    factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    with factory() as session:
        submissions = session.scalars(
            select(LogSubmission).where(LogSubmission.incident_id == incident_id)
        ).all()

        entries = session.scalars(
            select(LogEntry)
            .join(
                LogSubmission,
                LogEntry.submission_id == LogSubmission.id,
            )
            .where(LogSubmission.incident_id == incident_id)
        ).all()

        assert submissions == []
        assert entries == []


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
def test_unicode_credential_round_trip(
    factory: sessionmaker[Session],
    incident_id: UUID,
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    credential: str,
    expected: str,
) -> None:
    message = "Database connection failed; " + credential
    expected_message = "Database connection failed; " + expected

    payload = make_payload(
        source_format,
        escaped,
        {
            "severity": "ERROR",
            "message": message,
        },
    )

    result = LogIngestionService(
        factory,
        settings,
    ).ingest(
        incident_id,
        payload,
        source_format,
        source_name=credential,
    )

    assert result.incident_id == incident_id
    assert result.source_format == source_format
    assert result.payload_bytes == len(payload)
    assert result.entry_count == 1
    assert result.redaction_count == 2
    assert result.source_name == expected
    assert result.was_redacted is True

    assert CANARY not in repr(result)
    assert CANARY not in result.evidence.to_json()

    assert any(event.message == expected_message for event in result.evidence.events)

    with factory() as session:
        submission = session.get(
            LogSubmission,
            result.submission_id,
        )

        assert submission is not None
        assert submission.incident_id == incident_id
        assert submission.source_name == expected
        assert submission.source_format == source_format
        assert submission.payload_bytes == len(payload)
        assert submission.entry_count == 1
        assert submission.redaction_count == 2

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission.id)
        ).one()

        assert entry.position == 1
        assert entry.message == expected_message

        for field in ENTRY_FIELDS:
            assert CANARY not in (getattr(entry, field) or "")


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize(
    ("input_field", "output_field"),
    FIELDS,
)
@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
def test_unicode_metadata_round_trip(
    factory: sessionmaker[Session],
    incident_id: UUID,
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    input_field: str,
    output_field: str,
    credential: str,
    expected: str,
) -> None:
    fields = {
        "severity": "ERROR",
        "message": "Database connection failed.",
    }

    fields[input_field] = credential

    payload = make_payload(
        source_format,
        escaped,
        fields,
    )

    result = LogIngestionService(
        factory,
        settings,
    ).ingest(
        incident_id,
        payload,
        source_format,
        source_name=credential,
    )

    assert result.entry_count == 1
    assert result.redaction_count == 2
    assert result.source_name == expected

    assert CANARY not in repr(result)
    assert CANARY not in result.evidence.to_json()

    with factory() as session:
        submission = session.get(
            LogSubmission,
            result.submission_id,
        )

        assert submission is not None
        assert submission.redaction_count == 2
        assert submission.source_name == expected

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission.id)
        ).one()

        assert getattr(entry, output_field) == expected
        assert entry.message == "Database connection failed."

        for field in ENTRY_FIELDS:
            assert CANARY not in (getattr(entry, field) or "")


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "value",
    PRESERVATION_CASES,
)
def test_international_unicode_round_trip(
    factory: sessionmaker[Session],
    incident_id: UUID,
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    value: str,
) -> None:
    message = f"Database connection failed; {value}"

    fields = {
        "severity": "ERROR",
        "message": message,
    }

    if source_format != LogFormat.TEXT:
        fields.update(
            {
                "service_name": value,
                "exception": value,
                "error_code": value,
                "correlation_id": value,
            }
        )

    payload = make_payload(
        source_format,
        escaped,
        fields,
    )

    result = LogIngestionService(
        factory,
        settings,
    ).ingest(
        incident_id,
        payload,
        source_format,
        source_name=value,
    )

    assert result.entry_count == 1
    assert result.redaction_count == 0
    assert result.was_redacted is False
    assert result.source_name == value

    assert any(event.message == message for event in result.evidence.events)

    with factory() as session:
        submission = session.get(
            LogSubmission,
            result.submission_id,
        )

        assert submission is not None
        assert submission.source_name == value
        assert submission.redaction_count == 0

        entry = session.scalars(
            select(LogEntry).where(LogEntry.submission_id == submission.id)
        ).one()

        assert entry.message == message
        assert entry.original_severity == "ERROR"

        if source_format != LogFormat.TEXT:
            for field in (
                "service_name",
                "exception",
                "error_code",
                "correlation_id",
            ):
                assert getattr(entry, field) == value


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "location",
    ("message", "source_name"),
)
@pytest.mark.parametrize("value", UNSAFE_CASES)
def test_unsafe_unicode_not_persisted(
    factory: sessionmaker[Session],
    incident_id: UUID,
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    location: str,
    value: str,
) -> None:
    fields = {
        "severity": "ERROR",
        "message": "Database connection failed.",
    }

    source_name = "synthetic-service"

    if location == "message":
        fields["message"] = value
    else:
        source_name = value

    payload = make_payload(
        source_format,
        escaped,
        fields,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        LogIngestionService(
            factory,
            settings,
        ).ingest(
            incident_id,
            payload,
            source_format,
            source_name=source_name,
        )

    assert CANARY not in str(captured.value)

    assert_no_persistence(
        factory,
        incident_id,
    )


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "location",
    ("message", "source_name"),
)
@pytest.mark.parametrize("control", CONTROL_CASES)
def test_unicode_controls_not_persisted(
    factory: sessionmaker[Session],
    incident_id: UUID,
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    location: str,
    control: str,
) -> None:
    value = "Service" + control + "unavailable"

    fields = {
        "severity": "ERROR",
        "message": "Database connection failed.",
    }

    source_name = "synthetic-service"

    if location == "message":
        fields["message"] = value
    else:
        source_name = value

    payload = make_payload(
        source_format,
        escaped,
        fields,
    )

    with pytest.raises(InvalidLogEncodingError) as captured:
        LogIngestionService(
            factory,
            settings,
        ).ingest(
            incident_id,
            payload,
            source_format,
            source_name=source_name,
        )

    assert value not in str(captured.value)

    assert_no_persistence(
        factory,
        incident_id,
    )
