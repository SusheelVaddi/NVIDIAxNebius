"""REST API endpoints for the Autonomous Incident Recovery System.

Exposes the incident-recovery workflow through FastAPI.
Delegates all business logic to the orchestrator layer.
"""

from __future__ import annotations

import hmac
import os
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app.audit import audit_logger
from app.config import get_nebius_api_key
from app.infrastructure import infra
from app.models import (
    AuditEvent,
    AuditIntegrityReport,
    AuditEventType,
    AuditRecord,
    Incident,
    IncidentResponse,
    IncidentSeverity,
    IncidentStatus,
    PipelineStatus,
    RecoveryRequest,
    RecoveryResponse,
    ServiceInfo,
)
from app.orchestrator import Orchestrator, detect_and_recover
from app.recovery import DeterministicMockPlanner, NebiusPlanner

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency provider
# ---------------------------------------------------------------------------

def get_orchestrator() -> Orchestrator:
    """Provide an Orchestrator instance configured with system singletons."""
    api_key = get_nebius_api_key()
    planner = NebiusPlanner(api_key=api_key) if api_key else DeterministicMockPlanner()
    return Orchestrator(infra=infra, audit_logger=audit_logger, planner=planner)


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


def _records_from_events(events: List[AuditEvent]) -> List[AuditRecord]:
    """Reconstruct listable pipeline summaries from legacy event-only audit logs."""
    grouped: dict[str, List[AuditEvent]] = {}
    for event in events:
        grouped.setdefault(event.incident_id, []).append(event)

    records: List[AuditRecord] = []
    for incident_events in grouped.values():
        event_by_type = {event.event_type: event for event in incident_events}
        received = event_by_type.get(AuditEventType.INCIDENT_RECEIVED.value)
        completed = event_by_type.get(AuditEventType.PIPELINE_COMPLETED.value)
        if received is None or completed is None:
            continue

        incident_data = received.details.get("incident")
        status_data = completed.details.get("pipeline_status")
        if not isinstance(incident_data, dict) or status_data not in {
            status.value for status in PipelineStatus
        }:
            continue
        incident_data = dict(incident_data)
        incident_data["status"] = completed.details.get(
            "incident_status", IncidentStatus.FAILED.value
        )

        state_event = event_by_type.get(AuditEventType.STATE_LOADED.value)
        action_event = event_by_type.get(AuditEventType.ACTION_PROPOSED.value)
        policy_event = event_by_type.get(AuditEventType.POLICY_EVALUATED.value)
        recovery_event = event_by_type.get(AuditEventType.RECOVERY_EXECUTED.value)
        verification_event = event_by_type.get(AuditEventType.VERIFICATION_COMPLETED.value)

        records.append(AuditRecord(
            incident=incident_data,
            system_state_before=(
                state_event.details.get("system_state_before") if state_event else None
            ),
            recovery_action=(
                action_event.details.get("recovery_action") if action_event else None
            ),
            policy_decision=(
                policy_event.details.get("policy_decision") if policy_event else None
            ),
            recovery_result=(
                recovery_event.details.get("recovery_result") if recovery_event else None
            ),
            verification_result=(
                verification_event.details.get("verification_result")
                if verification_event else None
            ),
            audit_events=incident_events,
            pipeline_status=status_data,
            started_at=incident_events[0].timestamp,
            completed_at=completed.timestamp,
        ))
    return records


@router.get("/audit", response_model=List[AuditRecord])
def list_audit_records():
    """Return every audit record (most-recent last)."""
    entries = audit_logger.read_all()
    records = [
        AuditRecord.model_validate(record.model_dump())
        for record in entries
        if isinstance(record, (AuditRecord, IncidentResponse))
    ]
    if records:
        return records
    return _records_from_events(
        [entry for entry in entries if isinstance(entry, AuditEvent)]
    )


def verify_admin_auth(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> None:
    """Verify administrator authorization for sensitive administrative endpoints.

    If ADMIN_RESET_TOKEN is set in the environment, requests must supply a matching
    token via the 'X-Admin-Token' header or 'Authorization: Bearer <token>'.
    """
    expected_token = os.getenv("ADMIN_RESET_TOKEN", "").strip()
    if not expected_token:
        # In open development/testing mode without ADMIN_RESET_TOKEN configured, permit access
        return

    provided_token = None
    if x_admin_token:
        provided_token = x_admin_token.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            provided_token = parts[1]
        elif len(parts) == 1:
            provided_token = parts[0]

    if not provided_token or not secrets.compare_digest(provided_token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing admin token for reset.",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ResetRequest(BaseModel):
    """Optional request body for POST /reset."""
    clear_audit: bool = False


@router.post("/reset")
def reset_infrastructure(
    body: Optional[ResetRequest] = None,
    clear_audit: bool = False,
    _: None = Depends(verify_admin_auth),
):
    """Reset all services to healthy defaults.
    
    Audit history is preserved by default to maintain traceability.
    Audit history is only cleared if explicitly requested via clear_audit=True.
    """
    infra.reset()
    should_clear = clear_audit or (body.clear_audit if body is not None else False)
    if should_clear:
        audit_logger.clear()
    return {"status": "reset", "audit_cleared": should_clear}


@router.get("/audit/verify", response_model=AuditIntegrityReport)
def verify_audit_trail():
    """Verify cryptographic hash chain integrity and chronological order of all audit events."""
    return audit_logger.verify_integrity()
