"""Incident recovery orchestration pipeline.

Coordinates the full lifecycle:
    receive incident → load state → propose action → policy gate
    → execute if approved → independent verification → audit trail
    → IncidentResponse

Exports:
- Orchestrator: class implementing the full 8-step orchestration flow
- run_pipeline: helper taking Incident, InfrastructureSimulator, AuditLogger
- detect_and_recover: convenience wrapper injecting an incident and running orchestration
"""

from __future__ import annotations

from typing import Optional

from app.audit import AuditLogger
from app.infrastructure import InfrastructureSimulator
from app.models import (
    Incident,
    IncidentResponse,
    IncidentSeverity,
    RecoveryAction,
)
from app.orchestrator.orchestrator import Orchestrator


def run_pipeline(
    incident: Incident,
    infra: InfrastructureSimulator,
    audit: AuditLogger,
    proposed_action: Optional[RecoveryAction] = None,
) -> IncidentResponse:
    """Execute the recovery pipeline for *incident* using Orchestrator."""
    orchestrator = Orchestrator(infra=infra, audit_logger=audit)
    return orchestrator.handle_incident(incident, proposed_action=proposed_action)


def detect_and_recover(
    service_name: str,
    severity: IncidentSeverity,
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
    "detect_and_recover",
]
