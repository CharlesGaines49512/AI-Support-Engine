from fastapi import HTTPException, Request, status
from starlette.requests import ClientDisconnect

from app.models.log_enums import LogFormat

SUPPORTED_MEDIA_TYPES = {
    LogFormat.XML: frozenset({"application/xml", "text/xml"}),
    LogFormat.JSON: frozenset({"application/json"}),
    LogFormat.TEXT: frozenset({"text/plain"}),
}


async def read_log_payload(
    request: Request,
    source_format: LogFormat,
    max_bytes: int,
) -> bytes:
    """Read a bounded, uncompressed UTF-8 log request."""

    for header in (
        "content-length",
        "content-type",
        "content-encoding",
        "transfer-encoding",
        "x-log-source-name",
    ):
        if len(request.headers.getlist(header)) > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate request header.",
            )

    transfer_encoding = request.headers.get("transfer-encoding")

    if transfer_encoding is not None:
        if request.headers.get("content-length") is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Conflicting request framing.",
            )

        if transfer_encoding.strip().lower() != "chunked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported transfer encoding.",
            )

    content_encoding = (
        request.headers.get(
            "content-encoding",
            "identity",
        )
        .strip()
        .lower()
    )

    if content_encoding != "identity":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Compressed log requests are not supported.",
        )

    content_type = request.headers.get(
        "content-type",
        "",
    )

    parts = content_type.split(";")

    media_type = parts[0].strip().lower()

    if media_type not in SUPPORTED_MEDIA_TYPES[source_format]:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content type does not match the log format.",
        )

    if len(parts) > 2:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only one UTF-8 charset declaration is supported.",
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
                detail="Only UTF-8 log content is supported.",
            )

    normalized_length = "0"

    content_length = request.headers.get("content-length")

    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid content length.",
            )

        normalized_length = content_length.lstrip("0") or "0"

        if (
            len(normalized_length) > len(str(max_bytes))
            or int(normalized_length) > max_bytes
        ):
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Log payload exceeds the configured size limit.",
            )

    payload = bytearray()

    try:
        async for chunk in request.stream():
            if len(payload) + len(chunk) > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="Log payload exceeds the configured size limit.",
                )

            payload.extend(chunk)

    except ClientDisconnect:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log upload was interrupted.",
        ) from None

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log payload must not be empty.",
        )

    if content_length is not None and int(normalized_length) != len(payload):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content length does not match the request body.",
        )

    return bytes(payload)
