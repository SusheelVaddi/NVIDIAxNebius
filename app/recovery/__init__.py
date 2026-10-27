"""Simulated recovery actions and executor.

Exports:
- SimulatedRecoveryExecutor: class executing recovery actions on in-memory infrastructure
- pick_action: helper to recommend an action for an incident
- execute: legacy functional execution wrapper
"""

from __future__ import annotations

from typing import Union

from app.infrastructure import InfrastructureSimulator
from app.models import (
    Incident,
    IncidentSeverity,
    RecoveryAction,
    RecoveryActionType,
    RecoveryResult,
)
from app.recovery.executor import SimulatedRecoveryExecutor


def pick_action(incident: Incident) -> RecoveryActionType:
    """Choose a recommended recovery action based on incident severity / title."""
    desc = (incident.description + " " + incident.title).lower()
    if "queue" in desc:
        return RecoveryActionType.CLEAR_QUEUE
    if incident.severity == IncidentSeverity.CRITICAL:
        return RecoveryActionType.FAILOVER
    if incident.severity == IncidentSeverity.HIGH:
        return RecoveryActionType.SCALE_UP
    return RecoveryActionType.RESTART_SERVICE


def execute(
    target: Union[Incident, RecoveryAction],
    infra: InfrastructureSimulator,
) -> RecoveryResult:
    """Execute recovery action against simulated infrastructure.

    Accepts either a ``RecoveryAction`` or a legacy ``Incident``.
    """
    executor = SimulatedRecoveryExecutor()
    if isinstance(target, Incident):
        action_type = pick_action(target)
        action = RecoveryAction(
            incident_id=target.id,
            action_type=action_type,
            target_service=target.service_name,
        )
    else:
        action = target

    return executor.execute(action, infra)


__all__ = [
    "SimulatedRecoveryExecutor",
    "pick_action",
    "execute",
]
