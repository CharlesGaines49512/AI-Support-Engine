import asyncio

import pytest
from fastapi import HTTPException, Request
from starlette.types import Message

from app.api.log_requests import read_log_payload
from app.models.log_enums import LogFormat


def make_request(
    headers: list[tuple[bytes, bytes]],
    payload: bytes = b"test",
) -> Request:
    messages: list[Message] = [
        {
            "type": "http.request",
            "body": payload,
            "more_body": False,
        }
    ]

    async def receive() -> Message:
        return messages.pop(0)

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logs",
            "headers": headers,
        },
        receive,
    )


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (b"content-length", b"4"),
        (b"content-type", b"text/plain"),
        (b"content-encoding", b"identity"),
        (b"transfer-encoding", b"chunked"),
        (b"x-log-source-name", b"application.log"),
    ],
)
def test_duplicate_singleton_headers_rejected(
    header: bytes,
    value: bytes,
) -> None:
    headers = [
        (b"content-type", b"text/plain"),
    ]

    if header == b"content-type":
        headers.clear()

    headers.extend(
        [
            (header, value),
            (header, value),
        ]
    )

    request = make_request(headers)

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400
    assert error.value.detail == "Duplicate request header."


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (b"4", b"8"),
        (b"4", b"0"),
        (b"4", b"invalid"),
    ],
)
def test_conflicting_content_lengths_rejected(
    first: bytes,
    second: bytes,
) -> None:
    request = make_request(
        [
            (b"content-type", b"text/plain"),
            (b"content-length", first),
            (b"content-length", second),
        ]
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "encoding",
    [
        b"chunked",
        b"identity",
        b"gzip",
    ],
)
def test_conflicting_request_framing_rejected(
    encoding: bytes,
) -> None:
    request = make_request(
        [
            (b"content-type", b"text/plain"),
            (b"content-length", b"4"),
            (b"transfer-encoding", encoding),
        ]
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400
    assert error.value.detail == "Conflicting request framing."


@pytest.mark.parametrize(
    "encoding",
    [
        b"gzip",
        b"identity",
        b"",
        b"gzip, chunked",
        b"chunked, chunked",
    ],
)
def test_unsupported_transfer_encoding_rejected(
    encoding: bytes,
) -> None:
    request = make_request(
        [
            (b"content-type", b"text/plain"),
            (b"transfer-encoding", encoding),
        ]
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400
    assert error.value.detail == "Unsupported transfer encoding."


@pytest.mark.parametrize(
    "content_type",
    [
        b"text/plain; charset=utf-8; charset=utf-8",
        b"text/plain; charset=utf-8; charset=ascii",
        b'text/plain; charset="utf-8',
        b'text/plain; charset=utf-8"',
        b'text/plain; charset=""utf-8""',
        b"text/plain; charset=utf-8;",
        b"text/plain; charset=",
        b"text/plain; charset",
    ],
)
def test_ambiguous_charset_rejected(
    content_type: bytes,
) -> None:
    request = make_request([(b"content-type", content_type)])

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 415


@pytest.mark.parametrize(
    "length",
    [
        b"0",
        b"1",
        b"3",
        b"5",
        b"0005",
        b"1024",
    ],
)
def test_content_length_mismatch_rejected(
    length: bytes,
) -> None:
    request = make_request(
        [
            (b"content-type", b"text/plain"),
            (b"content-length", length),
        ]
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )

    assert error.value.status_code == 400
    assert error.value.detail == ("Content length does not match the request body.")


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"4")],
        [(b"content-length", b"0004")],
        [(b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"CHUNKED")],
        [],
    ],
)
def test_valid_request_framing_preserved(
    headers: list[tuple[bytes, bytes]],
) -> None:
    request = make_request([(b"content-type", b"text/plain")] + headers)

    assert (
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )
        == b"test"
    )


@pytest.mark.parametrize(
    "content_type",
    [
        b"text/plain",
        b"text/plain; charset=utf-8",
        b'text/plain; charset="UTF-8"',
        b"text/plain; CHARSET = UTF-8",
    ],
)
def test_valid_charset_preserved(
    content_type: bytes,
) -> None:
    request = make_request([(b"content-type", content_type)])

    assert (
        asyncio.run(
            read_log_payload(
                request,
                LogFormat.TEXT,
                1024,
            )
        )
        == b"test"
    )
