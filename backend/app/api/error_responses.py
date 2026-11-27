"""Shared OpenAPI error response declarations."""

from typing import Any

VALIDATION_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    422: {
        "description": "Request validation failed",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "required": ["detail"],
                    "additionalProperties": False,
                    "properties": {
                        "detail": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 1,
                            "items": {
                                "type": "object",
                                "required": ["loc", "msg", "type"],
                                "additionalProperties": False,
                                "properties": {
                                    "loc": {
                                        "type": "array",
                                        "maxItems": 0,
                                    },
                                    "msg": {
                                        "type": "string",
                                        "const": "Request validation failed.",
                                    },
                                    "type": {
                                        "type": "string",
                                        "const": "request_validation_error",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def http_error_response(
    description: str,
) -> dict[str, Any]:
    """Describe a standard HTTP exception response."""
    return {
        "description": description,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "required": ["detail"],
                    "additionalProperties": False,
                    "properties": {
                        "detail": {"type": "string"},
                    },
                },
            },
        },
    }
