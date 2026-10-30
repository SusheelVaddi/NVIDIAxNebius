"""Deterministic policy gate for recovery actions.

Evaluates proposed recovery actions against a set of deterministic, explainable rules.
Rejects unsafe, unknown, or out-of-bounds actions without execution.
"""

from __future__ import annotations

from typing import Dict, Optional, Set, Union

from app.models import (
    DecisionVerdict,
    PolicyDecision,
    RecoveryAction,
    RecoveryActionType,
    SystemState,
)

DEFAULT_ALLOWED_ACTIONS: Set[str] = {
    RecoveryActionType.RESTART_SERVICE.value,
    RecoveryActionType.CLEAR_QUEUE.value,
    RecoveryActionType.SCALE_SERVICE.value,
    RecoveryActionType.SCALE_UP.value,
    RecoveryActionType.FAILOVER.value,
}

DEFAULT_REQUIRED_PARAMETERS: Dict[str, Set[str]] = {
    RecoveryActionType.SCALE_SERVICE.value: {"target_instances"},
}

DEFAULT_PROTECTED_SERVICES: Set[str] = {"database"}


class DeterministicPolicyGate:
    """Deterministic and explainable policy gate.

    An action is approved ONLY when:
    1. The action type is explicitly allowed.
    2. The target service exists.
    3. The action is marked safe for simulation.
    4. Required parameters are present.
    5. The action does not exceed configured retry or risk limits.
    """

    def __init__(
        self,
        allowed_actions: Optional[Set[Union[RecoveryActionType, str]]] = None,
        max_risk_limit: int = 5,
        max_retry_limit: int = 3,
        required_parameters: Optional[Dict[str, Set[str]]] = None,
        protected_services: Optional[Set[str]] = None,
    ) -> None:
        if allowed_actions is not None:
            self.allowed_actions = {
                a.value if hasattr(a, "value") else str(a) for a in allowed_actions
            }
        else:
            self.allowed_actions = set(DEFAULT_ALLOWED_ACTIONS)

        self.max_risk_limit = max_risk_limit
        self.max_retry_limit = max_retry_limit
        self.required_parameters = (
            required_parameters if required_parameters is not None else dict(DEFAULT_REQUIRED_PARAMETERS)
        )
        self.protected_services = (
            protected_services if protected_services is not None else set(DEFAULT_PROTECTED_SERVICES)
        )

    def evaluate(
        self,
        action: RecoveryAction,
        state: Optional[SystemState],
    ) -> PolicyDecision:
        """Evaluate a recovery action against policy rules.

        Returns a PolicyDecision with verdict and explainable rationale.
        """
        action_type_str = (
            action.action_type.value
            if hasattr(action.action_type, "value")
            else str(action.action_type)
        )

        # 1. Action type explicitly allowed
        if action_type_str not in self.allowed_actions:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Action type '{action_type_str}' is not explicitly allowed. "
                    f"Allowed actions: {sorted(list(self.allowed_actions))}."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # 2. Target service exists
        if state is None:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Target service '{action.target_service}' does not exist in system state. "
                    f"Cannot perform recovery on an unknown service."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # Protected service critical safety check
        severity = action.parameters.get("severity")
        if severity is None:
            severity = action.parameters.get("incident_severity")
        if severity is None:
            severity = action.parameters.get("incidentSeverity")
        if action.target_service in self.protected_services and str(severity).lower() == "critical":
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.MANUAL_REVIEW,
                reason=(
                    f"Target service '{action.target_service}' is protected and incident severity "
                    f"is critical. Automated recovery requires manual review."
                ),
                decided_by="DeterministicPolicyGate",
            )
        if action.target_service in self.protected_services and severity is None:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.MANUAL_REVIEW,
                reason=(
                    f"Target service '{action.target_service}' is protected and missing incident severity "
                    f"requires manual review before automated recovery."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # 3. Action marked safe for simulation
        if not action.safe_for_simulation:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Action '{action_type_str}' is marked unsafe for simulation "
                    f"(safe_for_simulation=False). Unsafe actions are rejected."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # 4. Required parameters present
        expected_params = self.required_parameters.get(action_type_str, set())
        missing_params = expected_params - set(action.parameters.keys())
        if missing_params:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Action '{action_type_str}' is missing required parameter(s): "
                    f"{sorted(list(missing_params))}."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # 5. Risk and retry limits
        if action.risk_level > self.max_risk_limit:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Action risk level {action.risk_level} exceeds max allowed risk limit "
                    f"({self.max_risk_limit})."
                ),
                decided_by="DeterministicPolicyGate",
            )

        if action.retry_count >= self.max_retry_limit:
            return PolicyDecision(
                incident_id=action.incident_id,
                verdict=DecisionVerdict.DENY,
                reason=(
                    f"Action retry count {action.retry_count} reaches or exceeds max retry limit "
                    f"({self.max_retry_limit})."
                ),
                decided_by="DeterministicPolicyGate",
            )

        # All deterministic checks passed
        return PolicyDecision(
            incident_id=action.incident_id,
            verdict=DecisionVerdict.APPROVE,
            reason=(
                f"Action '{action_type_str}' on '{action.target_service}' approved: "
                f"action type allowed, service exists, safe for simulation, "
                f"required parameters present, and risk/retry limits satisfied."
            ),
            decided_by="DeterministicPolicyGate",
        )
