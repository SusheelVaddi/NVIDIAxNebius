"""FastAPI application entry point.

Run with:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="Autonomous IT Incident Recovery System",
    description=(
        "Detects simulated IT incidents, decides whether recovery is safe, "
        "executes a simulated recovery action, independently verifies the "
        "result, and records a complete audit trail."
    ),
    version="0.1.0",
)

# -- Mount API routes (supports both /... and /api/...) ----------------------

app.include_router(router)
app.include_router(router, prefix="/api")
