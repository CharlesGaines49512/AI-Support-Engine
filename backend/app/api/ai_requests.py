import json
from collections.abc import Callable, Coroutine
from typing import Any, Never

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.types import Message

MAX_AI_REQUEST_BYTES = 4096


def validate_ai_request_headers(
    request: Request,
) -> int | None:
    """Reject ambiguous or unsupported AI request headers."""

    for header in (
        "content-length",
        "content-type",
        "content-encoding",
        "transfer-encoding",
    ):
        if len(request.headers.getlist(header)) > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate request header.",
            )

    length = request.headers.get("content-length")
    transfer = request.headers.get("transfer-encoding")

    if transfer is not None:
        if length is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Conflicting request framing.",
            )

        if transfer.strip().lower() != "chunked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported transfer encoding.",
            )

    encoding = request.headers.get(
        "content-encoding",
        "identity",
    )

    if encoding.strip().lower() != "identity":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Compressed AI requests are not supported.",
        )

    content_type = request.headers.get("content-type")

    if content_type is not None:
        parts = content_type.split(";")
        media_type = parts[0].strip().lower()

        if media_type != "application/json":
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="AI requests require JSON content.",
            )

        if len(parts) > 2:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Invalid AI request charset declaration.",
            )

        for parameter in parts[1:]:
            name, separator, value = parameter.partition("=")

            if (
                not separator
                or name.strip().lower() != "charset"
                or value.strip().lower()
                not in (
                    "utf-8",
                    '"utf-8"',
                )
            ):
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Only UTF-8 JSON content is supported.",
                )

    if length is None:
        return None

    if not length.isascii() or not length.isdecimal():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid content length.",
        )

    normalized = length.lstrip("0") or "0"

    if (
        len(normalized) > len(str(MAX_AI_REQUEST_BYTES))
        or int(normalized) > MAX_AI_REQUEST_BYTES
    ):
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="AI request exceeds the configured size limit.",
        )

    return int(normalized)


MAX_AI_JSON_DEPTH = 32


def _reject_json_constant(_value: str) -> Never:
    raise ValueError("Unsupported JSON constant.")


def _unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")

        result[key] = value

    return result


def _validate_json_depth(content: str) -> None:
    depth = 0
    in_string = False
    escaped = False

    for character in content:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False

            continue

        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1

            if depth > MAX_AI_JSON_DEPTH:
                raise ValueError("JSON nesting limit exceeded.")

        elif character in "}]":
            depth -= 1

            if depth < 0:
                raise ValueError("Invalid JSON structure.")


def validate_ai_json_payload(payload: bytes) -> None:
    """Validate untrusted JSON before framework deserialization."""

    if not payload:
        return

    try:
        content = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI request contains invalid UTF-8 content.",
        ) from None

    if "\x00" in content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI request contains unsupported content.",
        )

    if "\ufeff" in content or (
        payload.startswith(b"\xef\xbb\xbf") and not content.strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI request contains an invalid byte order mark.",
        )

    try:
        _validate_json_depth(content)

        json.loads(
            content,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )

    except json.JSONDecodeError:
        raise RequestValidationError([]) from None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI request contains invalid JSON content.",
        ) from None


async def read_ai_request_body(
    request: Request,
) -> bytes:
    """Read and validate a bounded AI analysis request."""

    declared_length = validate_ai_request_headers(request)
    payload = bytearray()

    try:
        async for chunk in request.stream():
            if len(payload) + len(chunk) > MAX_AI_REQUEST_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="AI request exceeds the configured size limit.",
                )

            payload.extend(chunk)

    except ClientDisconnect:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI request was interrupted.",
        ) from None

    if declared_length is not None and declared_length != len(payload):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content length does not match the request body.",
        )

    validate_ai_json_payload(bytes(payload))

    return bytes(payload)


class BoundedAIRequestRoute(APIRoute):
    """Enforce AI request limits before automatic JSON parsing."""

    def get_route_handler(
        self,
    ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original_handler = super().get_route_handler()

        if self.methods is None or "POST" not in self.methods:
            return original_handler

        async def bounded_handler(
            request: Request,
        ) -> Response:
            body = await read_ai_request_body(request)

            delivered = False

            async def receive() -> Message:
                nonlocal delivered

                if delivered:
                    return await request.receive()

                delivered = True

                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            scope = request.scope

            if body and "content-type" not in request.headers:
                scope = dict(request.scope)
                scope["headers"] = [
                    *request.scope["headers"],
                    (b"content-type", b"application/json"),
                ]

            bounded_request = Request(
                scope,
                receive,
            )

            return await original_handler(bounded_request)

        return bounded_handler
