"""Convenience pipeline helpers for orchestrating incident recovery."""

from __future__ import annotations

from typing import Optional

from app.audit import AuditLogger
from app.infrastructure import InfrastructureSimulator
from app.models import Incident, IncidentResponse, RecoveryAction
from app.orchestrator.orchestrator import Orchestrator
from src.schemas import IncidentPayload


def run_pipeline(
    incident: Incident,
    infra: InfrastructureSimulator,
    audit: AuditLogger,
    proposed_action: Optional[RecoveryAction] = None,
) -> IncidentResponse:
    """Execute the recovery pipeline for *incident* using Orchestrator."""
    orchestrator = Orchestrator(infra=infra, audit_logger=audit)
    return orchestrator.handle_incident(incident, proposed_action=proposed_action)


def run_pipeline_from_payload(
    payload: IncidentPayload,
    infra: InfrastructureSimulator,
    audit: AuditLogger,
    proposed_action: Optional[RecoveryAction] = None,
) -> IncidentResponse:
    """Adapt a monitoring IncidentPayload into app.models.Incident and run the recovery pipeline."""
    incident = Incident.from_monitoring_payload(payload)
    return run_pipeline(incident, infra, audit, proposed_action=proposed_action)


def detect_and_recover(
    service_name: str,
    severity,
    infra: InfrastructureSimulator,
    audit: AuditLogger,
    description: str = "",
    proposed_action: Optional[RecoveryAction] = None,
) -> IncidentResponse:
    """Inject a simulated incident on *service_name* and run the orchestration pipeline."""
    incident = infra.inject_incident(service_name, severity, description)
    return run_pipeline(incident, infra, audit, proposed_action=proposed_action)


__all__ = [
    "Orchestrator",
    "run_pipeline",
    "run_pipeline_from_payload",
    "detect_and_recover",
]
