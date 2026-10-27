"""Policy decision engine and deterministic gate.

Exports:
- DeterministicPolicyGate: deterministic gate evaluating recovery actions
- evaluate: legacy/simple policy evaluator
"""

from __future__ import annotations

from app.models import (
    DecisionVerdict,
    Incident,
    IncidentSeverity,
    PolicyDecision,
    RecoveryAction,
    RecoveryActionType,
    ServiceInfo,
    ServiceStatus,
)
from app.policy.gate import (
    DEFAULT_ALLOWED_ACTIONS,
    DEFAULT_REQUIRED_PARAMETERS,
    DeterministicPolicyGate,
)

PROTECTED_SERVICES: set[str] = {"database"}
AUTO_APPROVE_MAX_SEVERITY: IncidentSeverity = IncidentSeverity.HIGH


def evaluate(incident: Incident, service: ServiceInfo) -> PolicyDecision:
    """Legacy helper: Return a policy decision for the given incident.

    Maintained for backwards-compatibility with earlier sprint tests.
    """
    if service.status == ServiceStatus.HEALTHY:
        return PolicyDecision(
            incident_id=incident.id,
            verdict=DecisionVerdict.DENY,
            reason="Service is already healthy.",
        )

    if incident.service_name in PROTECTED_SERVICES and incident.severity == IncidentSeverity.CRITICAL:
        return PolicyDecision(
            incident_id=incident.id,
            verdict=DecisionVerdict.MANUAL_REVIEW,
            reason="Protected service with critical severity requires manual review.",
        )

    severity_order = list(IncidentSeverity)
    if severity_order.index(incident.severity) <= severity_order.index(AUTO_APPROVE_MAX_SEVERITY):
        return PolicyDecision(
            incident_id=incident.id,
            verdict=DecisionVerdict.APPROVE,
            reason="Severity within auto-approve threshold.",
        )

    return PolicyDecision(
        incident_id=incident.id,
        verdict=DecisionVerdict.MANUAL_REVIEW,
        reason="Severity exceeds auto-approve threshold.",
    )


__all__ = [
    "DeterministicPolicyGate",
    "DEFAULT_ALLOWED_ACTIONS",
    "DEFAULT_REQUIRED_PARAMETERS",
    "evaluate",
    "PROTECTED_SERVICES",
    "AUTO_APPROVE_MAX_SEVERITY",
]
