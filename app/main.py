"""FastAPI application entry point.

Run with:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.api.routes import router

_DASHBOARD_FILE = Path(__file__).resolve().parents[1] / "frontend" / "index.html"

app = FastAPI(
    title="Autonomous IT Incident Recovery System",
    description=(
        "Detects simulated IT incidents, decides whether recovery is safe, "
        "executes a simulated recovery action, independently verifies the "
        "result, and records a complete audit trail."
    ),
    version="0.1.0",
)


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the bundled incident recovery dashboard."""
    return FileResponse(_DASHBOARD_FILE, media_type="text/html")


# -- Mount API routes (supports both /... and /api/...) ----------------------

# Canonical API routes documented in OpenAPI schema
app.include_router(router, prefix="/api")

# Root alias routes for backwards-compatibility (excluded from OpenAPI schema to prevent duplicate operation IDs)
app.include_router(router, include_in_schema=False)
