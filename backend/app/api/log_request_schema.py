"""OpenAPI documentation for structured log requests."""

from typing import Any

JSON_LOG_ENTRY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["message"],
    "additionalProperties": False,
    "properties": {
        "message": {
            "type": "string",
            "minLength": 1,
            "description": ("Nonempty log message after trimming whitespace."),
        },
        "timestamp": {"type": ["string", "null"]},
        "severity": {"type": ["string", "null"]},
        "service_name": {"type": ["string", "null"]},
        "exception": {"type": ["string", "null"]},
        "error_code": {"type": ["string", "null"]},
        "correlation_id": {"type": ["string", "null"]},
    },
}

JSON_LOG_ENTRY_ARRAY_SCHEMA: dict[str, Any] = {
    "type": "array",
    "minItems": 1,
    "items": JSON_LOG_ENTRY_SCHEMA,
}

JSON_LOG_REQUEST_SCHEMA: dict[str, Any] = {
    "description": (
        "A single log entry, an array of entries, "
        "or an object containing exactly one supported "
        "collection field. Configured resource limits "
        "and additional content validation apply."
    ),
    "oneOf": [
        JSON_LOG_ENTRY_SCHEMA,
        JSON_LOG_ENTRY_ARRAY_SCHEMA,
        *[
            {
                "type": "object",
                "required": [field],
                "additionalProperties": False,
                "properties": {
                    field: JSON_LOG_ENTRY_ARRAY_SCHEMA,
                },
            }
            for field in ("entries", "logs", "events")
        ],
    ],
}
