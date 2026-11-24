from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from app.api.v1.ai_analyses import router as ai_analysis_router
from app.api.v1.incidents import router as incident_router
from app.core.config import get_settings
from app.core.database import check_database_health

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-powered enterprise technical support platform",
    debug=settings.debug,
)


@app.get("/")
def root() -> dict[str, str]:
    """Return application information."""
    return {
        "application": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Check whether the application is running."""
    return {"status": "healthy"}


@app.get("/ready")
def readiness() -> JSONResponse:
    """Check whether the application is ready to serve requests."""
    if check_database_health():
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ready",
                "database": "healthy",
            },
        )

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "not_ready",
            "database": "unavailable",
        },
    )


app.include_router(incident_router, prefix=get_settings().api_v1_prefix)

app.include_router(ai_analysis_router, prefix=settings.api_v1_prefix)
