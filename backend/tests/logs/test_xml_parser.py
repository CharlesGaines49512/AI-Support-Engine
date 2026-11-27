import pytest

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.contracts import LogParser
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.parsers.xml_parser import XMLLogParser


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 1024,
            "log_max_entries": 3,
            "log_max_nesting_depth": 5,
            "log_max_message_chars": 100,
            "log_max_metadata_chars": 32,
        }
    )


def test_parser_protocol() -> None:
    assert isinstance(XMLLogParser(), LogParser)


def test_complete_xml_entry(settings: Settings) -> None:
    payload = b"""
    <logs>
        <entry severity="ERROR" service_name="ticketing">
            <timestamp>2026-11-24T15:30:00Z</timestamp>
            <message>Ticketing failed.</message>
            <exception>Connection timeout</exception>
            <error_code>TK-ERR</error_code>
            <correlation_id>TXN-10482</correlation_id>
        </entry>
    </logs>
    """

    result = XMLLogParser().parse(payload, settings)

    assert result.source_format == LogFormat.XML
    assert result.payload_bytes == len(payload)
    assert len(result.entries) == 1

    entry = result.entries[0]

    assert entry.position == 1
    assert entry.message == "Ticketing failed."
    assert entry.timestamp == "2026-11-24T15:30:00Z"
    assert entry.severity == "ERROR"
    assert entry.service_name == "ticketing"
    assert entry.exception == "Connection timeout"
    assert entry.error_code == "TK-ERR"
    assert entry.correlation_id == "TXN-10482"


@pytest.mark.parametrize("root", ["logs", "events"])
@pytest.mark.parametrize("tag", ["entry", "event", "log"])
def test_container_formats(
    settings: Settings,
    root: str,
    tag: str,
) -> None:
    payload = (
        f"<{root}><{tag}><message>Application ready.</message></{tag}></{root}>"
    ).encode()

    result = XMLLogParser().parse(payload, settings)

    assert len(result.entries) == 1
    assert result.entries[0].message == "Application ready."


@pytest.mark.parametrize("tag", ["entry", "event", "log"])
def test_single_entry_formats(
    settings: Settings,
    tag: str,
) -> None:
    payload = (f"<{tag}><message>Ready</message></{tag}>").encode()

    result = XMLLogParser().parse(payload, settings)

    assert result.entries[0].message == "Ready"
    assert result.entries[0].position == 1


def test_multiple_entries(settings: Settings) -> None:
    payload = b"""
    <logs>
        <entry message="First"/>
        <entry message="Second"/>
        <entry message="Third"/>
    </logs>
    """

    result = XMLLogParser().parse(payload, settings)

    assert [entry.position for entry in result.entries] == [1, 2, 3]

    assert [entry.message for entry in result.entries] == ["First", "Second", "Third"]


def test_attribute_fields(settings: Settings) -> None:
    payload = b'<entry message="Ready" severity="INFO" service_name="automation"/>'

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "Ready"
    assert entry.severity == "INFO"
    assert entry.service_name == "automation"


def test_child_fields(settings: Settings) -> None:
    payload = b"""
    <entry>
        <message>Ready</message>
        <severity>INFO</severity>
        <service_name>automation</service_name>
    </entry>
    """

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "Ready"
    assert entry.severity == "INFO"
    assert entry.service_name == "automation"


def test_missing_optional_metadata(
    settings: Settings,
) -> None:
    entry = (
        XMLLogParser()
        .parse(
            b'<entry message="Ready"/>',
            settings,
        )
        .entries[0]
    )

    assert entry.timestamp is None
    assert entry.severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_empty_optional_metadata(
    settings: Settings,
) -> None:
    payload = b"""
    <entry>
        <message>Ready</message>
        <timestamp/>
        <severity>   </severity>
        <service_name/>
        <exception/>
        <error_code/>
        <correlation_id/>
    </entry>
    """

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.timestamp is None
    assert entry.severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_unicode_message(settings: Settings) -> None:
    payload = ("<entry><message>Caf\u00e9 error</message></entry>").encode()

    result = XMLLogParser().parse(payload, settings)

    assert result.entries[0].message == "Caf\u00e9 error"


def test_utf8_bom(settings: Settings) -> None:
    payload = b'\xef\xbb\xbf<entry message="Ready"/>'

    result = XMLLogParser().parse(payload, settings)

    assert result.entries[0].message == "Ready"
    assert result.payload_bytes == len(payload)


@pytest.mark.parametrize(
    "declaration",
    [
        b'<?xml version="1.0"?>',
        b'<?xml version="1.0" encoding="UTF-8"?>',
        b'<?xml version="1.0" encoding="utf-8"?>',
    ],
)
def test_valid_xml_declaration(
    settings: Settings,
    declaration: bytes,
) -> None:
    result = XMLLogParser().parse(
        declaration + b'<entry message="Ready"/>',
        settings,
    )

    assert result.entries[0].message == "Ready"


def test_unsupported_xml_encoding(
    settings: Settings,
) -> None:
    payload = b'<?xml version="1.0" encoding="ISO-8859-1"?><entry message="Ready"/>'

    with pytest.raises(InvalidLogEncodingError):
        XMLLogParser().parse(payload, settings)


def test_unsupported_xml_version(
    settings: Settings,
) -> None:
    payload = b'<?xml version="1.1"?><entry message="Ready"/>'

    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


def test_xml_entities(settings: Settings) -> None:
    payload = b"<entry><message>A &amp; B &lt; C</message></entry>"

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "A & B < C"


def test_cdata_message(settings: Settings) -> None:
    payload = b"<entry><message><![CDATA[Error < 10]]></message></entry>"

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "Error < 10"


def test_whitespace_normalization(
    settings: Settings,
) -> None:
    payload = b"<entry><message>  Ready  </message><severity> INFO </severity></entry>"

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "Ready"
    assert entry.severity == "INFO"


@pytest.mark.parametrize(
    "payload",
    [
        b"<entry>",
        b"<entry></log>",
        b"<entry/><entry/>",
        b"<entry><message>&undefined;</message></entry>",
        b"Not an XML document",
    ],
)
def test_malformed_xml(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"<unsupported/>",
        b'<logs application="test"/>',
        b"<logs><unsupported/></logs>",
        b'<entry message="Ready" unsupported="value"/>',
        b"<entry>Unexpected text<message>Ready</message></entry>",
        b"<entry><unsupported>Ready</unsupported></entry>",
        b'<entry message="First"><message>Second</message></entry>',
        b"<entry><message>First</message><message>Second</message></entry>",
        b"<entry><message><nested>Ready</nested></message></entry>",
        b'<entry><message type="text">Ready</message></entry>',
        b"<entry><message>Ready</message>Unexpected text</entry>",
        b"<entry/>",
        b"<entry><message>   </message></entry>",
        b'<logs>Unexpected text<entry message="Ready"/></logs>',
        b'<logs><entry message="Ready"/>Unexpected text</logs>',
    ],
)
def test_unsupported_xml_structure(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"<logs/>",
        b"<events/>",
    ],
)
def test_empty_containers(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        XMLLogParser().parse(payload, settings)


def test_dtd_rejected(settings: Settings) -> None:
    payload = b'<!DOCTYPE entry><entry message="Ready"/>'

    with pytest.raises(UnsafeLogContentError):
        XMLLogParser().parse(payload, settings)


def test_entry_limit(settings: Settings) -> None:
    payload = b"<logs>" + b'<entry message="Ready"/>' * 4 + b"</logs>"

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


def test_nesting_limit(settings: Settings) -> None:
    limited = settings.model_copy(update={"log_max_nesting_depth": 2})

    payload = b"<logs><entry><message>Ready</message></entry></logs>"

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, limited)


def test_payload_size_limit(settings: Settings) -> None:
    payload = b"x" * 1025

    with pytest.raises(LogPayloadTooLargeError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize("field", ["message", "exception"])
def test_message_field_limits(
    settings: Settings,
    field: str,
) -> None:
    payload = (f"<entry><{field}>" + "x" * 101 + f"</{field}></entry>").encode()

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "field",
    [
        "timestamp",
        "severity",
        "service_name",
        "error_code",
        "correlation_id",
    ],
)
def test_metadata_field_limits(
    settings: Settings,
    field: str,
) -> None:
    payload = (
        f'<entry message="Ready"><{field}>' + "x" * 33 + f"</{field}></entry>"
    ).encode()

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


def test_exact_field_limits(
    settings: Settings,
) -> None:
    message = "m" * 100
    service = "s" * 32

    payload = (f'<entry message="{message}" service_name="{service}"/>').encode()

    entry = (
        XMLLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == message
    assert entry.service_name == service


def test_encoded_control_character(
    settings: Settings,
) -> None:
    payload = b"<entry><message>Ready&#127;</message></entry>"

    with pytest.raises(InvalidLogEncodingError):
        XMLLogParser().parse(payload, settings)


def test_error_does_not_expose_raw_payload(
    settings: Settings,
) -> None:
    payload = b"<entry>SYNTHETIC_SECRET_CANARY"

    with pytest.raises(MalformedLogError) as captured:
        XMLLogParser().parse(payload, settings)

    assert "SYNTHETIC_SECRET_CANARY" not in str(captured.value)

    assert captured.value.__suppress_context__ is True
