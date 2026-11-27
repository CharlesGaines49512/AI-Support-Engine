from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


async def handle_request_validation_error(
    _request: Request,
    _error: Exception,
) -> JSONResponse:
    """Return validation failures without exposing untrusted request data."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "detail": [
                {
                    "loc": [],
                    "msg": "Request validation failed.",
                    "type": "request_validation_error",
                }
            ]
        },
    )


def register_error_handlers(app: FastAPI) -> None:
    """Register application-wide safe HTTP validation handling."""
    app.add_exception_handler(
        RequestValidationError,
        handle_request_validation_error,
    )
