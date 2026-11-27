from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.contracts import ParsedLog, ParsedLogEntry
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.parsers.validation import (
    decode_log_payload,
    validate_entry_count,
    validate_nesting_depth,
)

CONTAINER_TAGS = frozenset({"logs", "events"})
ENTRY_TAGS = frozenset({"entry", "event", "log"})

SUPPORTED_FIELDS = frozenset(
    {
        "timestamp",
        "severity",
        "service_name",
        "message",
        "exception",
        "error_code",
        "correlation_id",
    }
)


def _reject_doctype(*args: object) -> None:
    raise UnsafeLogContentError("XML document type declarations are not supported.")


def _reject_external_entity(*args: object) -> int:
    raise UnsafeLogContentError("XML external entities are not supported.")


def _reject_processing_instruction(*args: object) -> None:
    raise UnsafeLogContentError("XML processing instructions are not supported.")


def _reject_namespace(*args: object) -> None:
    raise MalformedLogError("XML namespaces are not supported.")


def _validate_xml_declaration(
    version: str,
    encoding: str | None,
    standalone: int,
) -> None:
    if version != "1.0":
        raise MalformedLogError("Only XML version 1.0 is supported.")

    if encoding is not None and encoding.lower() != "utf-8":
        raise InvalidLogEncodingError("XML encoding must be UTF-8.")


def _validate_field(
    name: str,
    value: str,
    settings: Settings,
) -> str:
    if any(
        (ord(character) < 32 and character not in "\t\r\n")
        or 127 <= ord(character) <= 159
        for character in value
    ):
        raise InvalidLogEncodingError(
            "XML field contains unsupported control characters."
        )

    value = value.strip()

    limit = (
        settings.log_max_message_chars
        if name in {"message", "exception"}
        else settings.log_max_metadata_chars
    )

    if len(value) > limit:
        raise LogResourceLimitError("XML field exceeds the configured length limit.")

    return value


def _extract_entry(
    element: Element,
    position: int,
    settings: Settings,
) -> ParsedLogEntry:
    fields: dict[str, str] = {}

    for name, value in element.attrib.items():
        if name not in SUPPORTED_FIELDS:
            raise MalformedLogError("XML entry contains an unsupported attribute.")

        fields[name] = _validate_field(
            name,
            value,
            settings,
        )

    if element.text and element.text.strip():
        raise MalformedLogError("XML entry contains unexpected text.")

    for child in element:
        name = child.tag

        if name not in SUPPORTED_FIELDS:
            raise MalformedLogError("XML entry contains an unsupported field.")

        if name in fields:
            raise MalformedLogError("XML entry contains a duplicate field.")

        if len(child) or child.attrib:
            raise MalformedLogError("XML fields must contain plain text.")

        if child.tail and child.tail.strip():
            raise MalformedLogError("XML entry contains unexpected text.")

        fields[name] = _validate_field(
            name,
            child.text or "",
            settings,
        )

    message = fields.get("message", "")

    if not message:
        raise MalformedLogError("XML log entry requires a nonempty message.")

    return ParsedLogEntry(
        position=position,
        message=message,
        timestamp=fields.get("timestamp") or None,
        severity=fields.get("severity") or None,
        service_name=fields.get("service_name") or None,
        exception=fields.get("exception") or None,
        error_code=fields.get("error_code") or None,
        correlation_id=fields.get("correlation_id") or None,
    )


class XMLLogParser:
    """Parse supported XML application log documents."""

    def parse(
        self,
        payload: bytes,
        settings: Settings,
    ) -> ParsedLog:
        content = decode_log_payload(payload, settings)

        builder = TreeBuilder()
        parser = expat.ParserCreate(
            encoding="UTF-8",
            namespace_separator="}",
        )

        depth = 0
        entry_count = 0
        root_tag = ""

        def start(
            name: str,
            attributes: dict[str, str],
        ) -> None:
            nonlocal depth, entry_count, root_tag

            depth += 1
            validate_nesting_depth(depth, settings)

            if depth == 1:
                root_tag = name

                if name not in CONTAINER_TAGS | ENTRY_TAGS:
                    raise MalformedLogError("Unsupported XML document root.")

                if name in CONTAINER_TAGS and attributes:
                    raise MalformedLogError("XML container attributes are unsupported.")

            is_entry = (depth == 1 and name in ENTRY_TAGS) or (
                depth == 2 and root_tag in CONTAINER_TAGS
            )

            if is_entry:
                if name not in ENTRY_TAGS:
                    raise MalformedLogError(
                        "XML container contains an unsupported element."
                    )

                entry_count += 1
                validate_entry_count(entry_count, settings)

            builder.start(name, attributes)

        def end(name: str) -> None:
            nonlocal depth

            builder.end(name)
            depth -= 1

        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.CharacterDataHandler = builder.data
        parser.StartDoctypeDeclHandler = _reject_doctype
        parser.ExternalEntityRefHandler = _reject_external_entity
        parser.ProcessingInstructionHandler = _reject_processing_instruction
        parser.StartNamespaceDeclHandler = _reject_namespace
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        parser.XmlDeclHandler = _validate_xml_declaration

        try:
            parser.Parse(content, True)
        except expat.ExpatError:
            raise MalformedLogError("XML log document is malformed.") from None

        validate_entry_count(entry_count, settings)

        root = builder.close()

        if root.tag in CONTAINER_TAGS:
            if root.text and root.text.strip():
                raise MalformedLogError("XML container contains unexpected text.")

            for element in root:
                if element.tail and element.tail.strip():
                    raise MalformedLogError("XML container contains unexpected text.")

            elements = list(root)
        else:
            elements = [root]

        entries = tuple(
            _extract_entry(element, position, settings)
            for position, element in enumerate(
                elements,
                start=1,
            )
        )

        return ParsedLog(
            source_format=LogFormat.XML,
            payload_bytes=len(payload),
            entries=entries,
        )
