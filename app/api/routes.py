"""REST API endpoints for the Incident Recovery System.

All endpoints are grouped under a single ``router`` that is mounted
by the FastAPI application in ``app.main``.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.audit import audit_logger
from app.infrastructure import infra
from app.models import (
    AuditRecord,
    IncidentSeverity,
    ServiceInfo,
)
from app.orchestrator import detect_and_recover

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response helpers
# ---------------------------------------------------------------------------

class IncidentRequest(BaseModel):
    """Body for the POST /incidents endpoint."""
    service_name: str
    severity: IncidentSeverity
    description: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/services", response_model=List[ServiceInfo])
def list_services():
    """Return the current state of every simulated service."""
    return infra.list_services()


@router.get("/services/{name}", response_model=ServiceInfo)
def get_service(name: str):
    """Return a single service by name."""
    svc = infra.get_service(name)
    if svc is None:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    return svc


@router.post("/incidents", response_model=AuditRecord)
def create_incident(body: IncidentRequest):
    """Inject a simulated incident and run the full recovery pipeline.

    Returns the resulting audit record.
    """
    try:
        record = detect_and_recover(
            service_name=body.service_name,
            severity=body.severity,
            description=body.description,
            infra=infra,
            audit=audit_logger,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return record


@router.get("/audit", response_model=List[AuditRecord])
def list_audit_records():
    """Return every audit record (most-recent last)."""
    return audit_logger.read_all()


@router.post("/reset")
def reset_infrastructure():
    """Reset all services to healthy defaults and clear the audit log."""
    infra.reset()
    audit_logger.clear()
    return {"status": "reset"}
