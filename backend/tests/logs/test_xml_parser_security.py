from pathlib import Path

import pytest

from app.core.config import Settings
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.parsers.xml_parser import (
    XMLLogParser,
    _reject_external_entity,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 4096,
            "log_max_entries": 5,
            "log_max_nesting_depth": 8,
            "log_max_message_chars": 100,
            "log_max_metadata_chars": 32,
        }
    )


@pytest.mark.parametrize(
    "payload",
    [
        (b'<!DOCTYPE entry SYSTEM "file:///synthetic.xml"><entry message="Ready"/>'),
        (
            b'<!DOCTYPE entry SYSTEM "https://example.invalid/log.dtd">'
            b'<entry message="Ready"/>'
        ),
        (
            b'<!DOCTYPE entry PUBLIC "-//Synthetic//DTD Log//EN" '
            b'"https://example.invalid/log.dtd">'
            b'<entry message="Ready"/>'
        ),
        (
            b'<!DOCTYPE entry [<!ENTITY sample "synthetic">]>'
            b"<entry><message>&sample;</message></entry>"
        ),
        (
            b"<!DOCTYPE entry ["
            b'<!ENTITY sample SYSTEM "file:///synthetic.txt">'
            b"]>"
            b"<entry><message>&sample;</message></entry>"
        ),
        (
            b"<!DOCTYPE entry ["
            b'<!ENTITY % sample SYSTEM "https://example.invalid/">'
            b"%sample;"
            b"]>"
            b'<entry message="Ready"/>'
        ),
    ],
)
def test_unsafe_document_declarations(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        XMLLogParser().parse(payload, settings)


def test_external_entity_cannot_return_local_file_contents(
    settings: Settings,
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "synthetic-secret.txt"
    canary = "SYNTHETIC_XML_FILE_SECRET"

    secret_file.write_text(
        canary,
        encoding="utf-8",
    )

    payload = (
        "<!DOCTYPE entry ["
        f'<!ENTITY external SYSTEM "{secret_file.as_uri()}">'
        "]>"
        "<entry><message>&external;</message></entry>"
    ).encode()

    with pytest.raises(UnsafeLogContentError) as captured:
        XMLLogParser().parse(payload, settings)

    assert canary not in str(captured.value)
    assert str(secret_file) not in str(captured.value)


def test_external_entity_handler_rejects_request() -> None:
    with pytest.raises(UnsafeLogContentError):
        _reject_external_entity(
            None,
            None,
            "https://example.invalid/",
            None,
        )


def test_nested_entity_declarations_rejected(
    settings: Settings,
) -> None:
    payload = b"""
    <!DOCTYPE entry [
        <!ENTITY first "synthetic">
        <!ENTITY second "&first;&first;">
        <!ENTITY third "&second;&second;">
    ]>
    <entry>
        <message>&third;</message>
    </entry>
    """

    with pytest.raises(UnsafeLogContentError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        (
            b'<?xml-stylesheet type="text/xsl" '
            b'href="https://example.invalid/style.xsl"?>'
            b'<entry message="Ready"/>'
        ),
        (b"<entry><?execute synthetic?><message>Ready</message></entry>"),
        (b'<entry message="Ready"/><?custom synthetic?>'),
    ],
)
def test_processing_instructions_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b'<entry xmlns="urn:synthetic" message="Ready"/>',
        (b'<x:entry xmlns:x="urn:synthetic"><x:message>Ready</x:message></x:entry>'),
        (b'<entry xmlns:x="urn:synthetic" message="Ready"/>'),
        (b'<entry><message xmlns="urn:synthetic">Ready</message></entry>'),
    ],
)
def test_namespace_declarations_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


def test_deeply_nested_document_rejected(
    settings: Settings,
) -> None:
    payload = (
        b"<entry><message>"
        + b"<nested>" * 100
        + b"Ready"
        + b"</nested>" * 100
        + b"</message></entry>"
    )

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


def test_excessive_entries_rejected(
    settings: Settings,
) -> None:
    payload = b"<logs>" + b'<entry message="Ready"/>' * 50 + b"</logs>"

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


def test_exact_entry_limit(
    settings: Settings,
) -> None:
    payload = b"<logs>" + b'<entry message="Ready"/>' * 5 + b"</logs>"

    result = XMLLogParser().parse(payload, settings)

    assert len(result.entries) == 5


def test_oversized_document_rejected_before_parsing(
    settings: Settings,
) -> None:
    payload = b"<!DOCTYPE entry>" + b"x" * 4096

    with pytest.raises(LogPayloadTooLargeError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "field",
    [
        "severity",
        "timestamp",
        "service_name",
        "error_code",
        "correlation_id",
    ],
)
def test_oversized_metadata_attributes(
    settings: Settings,
    field: str,
) -> None:
    value = "x" * 33

    payload = (f'<entry message="Ready" {field}="{value}"/>').encode()

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "field",
    ["message", "exception"],
)
def test_oversized_message_attributes(
    settings: Settings,
    field: str,
) -> None:
    value = "x" * 101

    message = "" if field == "message" else 'message="Ready" '

    payload = (f'<entry {message}{field}="{value}"/>').encode()

    with pytest.raises(LogResourceLimitError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b'<entry message="Ready&#127;"/>',
        b'<entry message="Ready&#133;"/>',
        b'<entry message="Ready&#159;"/>',
        b'<entry message="Ready" severity="INFO&#127;"/>',
    ],
)
def test_encoded_attribute_controls_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogEncodingError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b'<entry message="Ready&#0;"/>',
        b'<entry message="Ready&#1;"/>',
        b'<entry message="Ready&#xD800;"/>',
    ],
)
def test_invalid_xml_character_references(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        (b'<entry message="Ready" message="Duplicate"/>'),
        (
            b'<entry message="Ready">'
            b"<severity>INFO</severity>"
            b"<severity>ERROR</severity>"
            b"</entry>"
        ),
        (b'<entry message="Ready"><entry message="Nested"/></entry>'),
    ],
)
def test_ambiguous_xml_structures_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        XMLLogParser().parse(payload, settings)


def test_security_error_does_not_expose_canary(
    settings: Settings,
) -> None:
    payload = (
        b"<!DOCTYPE entry SYSTEM "
        b'"https://example.invalid/SYNTHETIC_SECRET">'
        b'<entry message="Ready"/>'
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        XMLLogParser().parse(payload, settings)

    assert "SYNTHETIC_SECRET" not in str(captured.value)


def test_literal_doctype_inside_cdata(
    settings: Settings,
) -> None:
    payload = (
        b"<entry><message>"
        b"<![CDATA[Received <!DOCTYPE synthetic> as text]]>"
        b"</message></entry>"
    )

    result = XMLLogParser().parse(payload, settings)

    assert result.entries[0].message == ("Received <!DOCTYPE synthetic> as text")


def test_xml_comment_does_not_create_entry(
    settings: Settings,
) -> None:
    payload = (
        b'<logs><!-- <entry message="Ignored"/> --><entry message="Ready"/></logs>'
    )

    result = XMLLogParser().parse(payload, settings)

    assert len(result.entries) == 1
    assert result.entries[0].message == "Ready"


def test_legitimate_character_references_preserved(
    settings: Settings,
) -> None:
    payload = b"<entry><message>A &amp; B &#65; &#x42; &lt; C</message></entry>"

    result = XMLLogParser().parse(payload, settings)

    assert result.entries[0].message == "A & B A B < C"


def test_parser_reusable_after_security_rejection(
    settings: Settings,
) -> None:
    parser = XMLLogParser()

    with pytest.raises(UnsafeLogContentError):
        parser.parse(
            b'<!DOCTYPE entry><entry message="Ready"/>',
            settings,
        )

    result = parser.parse(
        b'<entry message="Ready"/>',
        settings,
    )

    assert result.entries[0].message == "Ready"
    assert result.entries[0].position == 1
