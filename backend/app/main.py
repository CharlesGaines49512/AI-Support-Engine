from fastapi import FastAPI

app = FastAPI(
    title="AI Support Engine",
    description="AI-powered enterprise technical support platform",
    version="0.1.0",
)


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    """Return basic application information."""
    return {
        "application": "AI Support Engine",
        "version": "0.1.0",
    }


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Confirm that the application is running."""
    return {
        "status": "healthy",
    }
