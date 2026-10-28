"""REST API endpoints for the Autonomous Incident Recovery System.

Exposes the incident-recovery workflow through FastAPI.
Delegates all business logic to the orchestrator layer.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.audit import audit_logger
from app.infrastructure import infra
from app.models import (
    AuditEvent,
    AuditRecord,
    Incident,
    IncidentSeverity,
    RecoveryRequest,
    RecoveryResponse,
    ServiceInfo,
)
from app.orchestrator import Orchestrator, detect_and_recover

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency provider
# ---------------------------------------------------------------------------

def get_orchestrator() -> Orchestrator:
    """Provide an Orchestrator instance configured with system singletons."""
    return Orchestrator(infra=infra, audit_logger=audit_logger)


# ---------------------------------------------------------------------------
# Legacy request helper
# ---------------------------------------------------------------------------

class IncidentRequest(BaseModel):
    """Body for the legacy POST /incidents endpoint."""
    service_name: str
    severity: IncidentSeverity
    description: str = ""


# ---------------------------------------------------------------------------
# Health check endpoint
# ---------------------------------------------------------------------------

@router.get("/health")
def health_check():
    """Liveness probe returning application health status."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Recovery Workflow Endpoints
# ---------------------------------------------------------------------------

@router.post("/incidents/recover", response_model=RecoveryResponse)
def recover_incident(
    req: RecoveryRequest,
    orchestrator: Orchestrator = Depends(get_orchestrator),
):
    """Trigger the autonomous incident recovery workflow via the Orchestrator.

    Takes:
    - incident ID
    - incident type
    - affected service
    - proposed recovery action
    - current simulated system state

    Returns:
    - incident ID
    - policy decision
    - recovery result
    - verification result
    - final status
    - audit events
    """
    # Synchronize simulated infrastructure with current system state if known
    if req.current_system_state:
        infra.update_service_state(req.current_system_state)

    # Determine severity based on incident_type or default to HIGH
    severity_val = req.incident_type.lower()
    try:
        severity = IncidentSeverity(severity_val)
    except ValueError:
        severity = IncidentSeverity.HIGH

    incident = Incident(
        id=req.incident_id,
        service_name=req.affected_service,
        severity=severity,
        title=f"{req.incident_type} on {req.affected_service}",
        description=f"Incident '{req.incident_id}' of type '{req.incident_type}' affecting {req.affected_service}.",
    )

    action = req.proposed_recovery_action
    if not action.incident_id or action.incident_id != req.incident_id:
        action = action.model_copy(update={"incident_id": req.incident_id})

    # Delegate full lifecycle to orchestrator (no business logic in routes)
    resp = orchestrator.handle_incident(incident, proposed_action=action)

    return RecoveryResponse(
        incident_id=resp.incident.id,
        policy_decision=resp.policy_decision,
        recovery_result=resp.recovery_result,
        verification_result=resp.verification_result,
        final_status=resp.pipeline_status,
        audit_events=resp.audit_events,
    )


@router.get("/incidents/{incident_id}/audit", response_model=List[AuditEvent])
def get_incident_audit(incident_id: str):
    """Retrieve the sequential audit log trail for a specific incident."""
    events = audit_logger.get_events_for_incident(incident_id)
    if not events:
        raise HTTPException(
            status_code=404,
            detail=f"No audit events found for incident '{incident_id}'.",
        )
    return events


# ---------------------------------------------------------------------------
# Additional Infrastructure & Audit Queries
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
    """Inject a simulated incident and run the full recovery pipeline."""
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
