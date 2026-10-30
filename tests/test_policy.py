"""Tests for the policy decision engine."""

from app.models import (
    Incident,
    IncidentSeverity,
    PolicyDecision,
    ServiceInfo,
    ServiceStatus,
)
from app.policy import evaluate


def _make_service(name: str, status: ServiceStatus) -> ServiceInfo:
    return ServiceInfo(name=name, status=status, cpu_percent=50, memory_percent=50, error_rate=0.5)


def test_healthy_service_is_denied():
    inc = Incident(service_name="web", severity=IncidentSeverity.HIGH, description="x")
    svc = _make_service("web", ServiceStatus.HEALTHY)
    assert evaluate(inc, svc) == PolicyDecision.DENY


def test_low_severity_approved():
    inc = Incident(service_name="web", severity=IncidentSeverity.LOW, description="x")
    svc = _make_service("web", ServiceStatus.DEGRADED)
    assert evaluate(inc, svc) == PolicyDecision.APPROVE


def test_high_severity_approved():
    inc = Incident(service_name="web", severity=IncidentSeverity.HIGH, description="x")
    svc = _make_service("web", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.APPROVE


def test_critical_protected_service_manual_review():
    inc = Incident(service_name="database", severity=IncidentSeverity.CRITICAL, description="x")
    svc = _make_service("database", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.MANUAL_REVIEW


def test_critical_protected_service_manual_review_must_use_incident_severity_parameter():
    from app.models import RecoveryAction, RecoveryActionType
    from app.policy.gate import DeterministicPolicyGate

    action = RecoveryAction(
        incident_id="inc-123",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="database",
        parameters={},
        safe_for_simulation=True,
        risk_level=1,
        retry_count=0,
    )
    state = _make_service("database", ServiceStatus.DOWN)

    decision = DeterministicPolicyGate().evaluate(action, state)
    assert decision.verdict == "manual_review"
    assert "manual review" in decision.reason.lower()


def test_critical_non_protected_service_manual_review():
    """CRITICAL exceeds AUTO_APPROVE_MAX_SEVERITY (HIGH) → MANUAL_REVIEW."""
    inc = Incident(service_name="web", severity=IncidentSeverity.CRITICAL, description="x")
    svc = _make_service("web", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.MANUAL_REVIEW


# ==============================================================================
# Production DeterministicPolicyGate Tests
# ==============================================================================

from unittest.mock import MagicMock
from app.models import DecisionVerdict, RecoveryAction, RecoveryActionType, PipelineStatus, IncidentStatus, ServiceInfo, ServiceStatus
from app.policy.gate import DeterministicPolicyGate
from app.orchestrator import Orchestrator
from app.infrastructure import InfrastructureSimulator
from app.recovery import SimulatedRecoveryExecutor


def test_production_policy_gate_approves_valid_recovery_on_degraded_service():
    gate = DeterministicPolicyGate()
    action = RecoveryAction(
        incident_id="inc-pol-01",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        parameters={"severity": "low"},
        safe_for_simulation=True,
    )
    state = _make_service("web-frontend", ServiceStatus.DEGRADED)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.APPROVE
    assert decision.is_approved is True
    assert "approved" in decision.reason.lower()


def test_production_policy_gate_denies_disallowed_action():
    gate = DeterministicPolicyGate(allowed_actions={RecoveryActionType.RESTART_SERVICE})
    action = RecoveryAction(
        incident_id="inc-pol-02",
        action_type=RecoveryActionType.FAILOVER,
        target_service="web-frontend",
        safe_for_simulation=True,
    )
    state = _make_service("web-frontend", ServiceStatus.DOWN)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert decision.is_approved is False
    assert "not explicitly allowed" in decision.reason


def test_production_policy_gate_denies_unsafe_simulation_action():
    gate = DeterministicPolicyGate()
    action = RecoveryAction(
        incident_id="inc-pol-03",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        safe_for_simulation=False,
    )
    state = _make_service("web-frontend", ServiceStatus.DOWN)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "unsafe for simulation" in decision.reason.lower()


def test_production_policy_gate_denies_target_service_mismatch():
    gate = DeterministicPolicyGate()
    action = RecoveryAction(
        incident_id="inc-pol-04",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="auth-service",
        safe_for_simulation=True,
    )
    state = _make_service("web-frontend", ServiceStatus.DOWN)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "target service mismatch" in decision.reason.lower()


def test_production_policy_gate_denies_unknown_target_service():
    gate = DeterministicPolicyGate()
    action = RecoveryAction(
        incident_id="inc-pol-05",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="nonexistent-svc",
        safe_for_simulation=True,
    )
    decision = gate.evaluate(action, None)
    assert decision.verdict == DecisionVerdict.DENY
    assert "does not exist in system state" in decision.reason.lower()


def test_production_policy_gate_denies_excessive_risk_or_retry():
    gate = DeterministicPolicyGate(max_risk_limit=3, max_retry_limit=2)
    high_risk_action = RecoveryAction(
        incident_id="inc-pol-06",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        risk_level=5,
        safe_for_simulation=True,
    )
    state = _make_service("web-frontend", ServiceStatus.DOWN)
    assert gate.evaluate(high_risk_action, state).verdict == DecisionVerdict.DENY

    high_retry_action = RecoveryAction(
        incident_id="inc-pol-07",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        retry_count=3,
        safe_for_simulation=True,
    )
    assert gate.evaluate(high_retry_action, state).verdict == DecisionVerdict.DENY


def test_policy_rejection_strictly_prevents_executor_invocation():
    infra = InfrastructureSimulator()
    infra.inject_incident("database", IncidentSeverity.CRITICAL)
    mock_executor = MagicMock(spec=SimulatedRecoveryExecutor)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(protected_services={"database"}),
        executor=mock_executor,
    )
    incident = Incident(
        id="inc-pol-exec-01",
        service_name="database",
        severity=IncidentSeverity.CRITICAL,
        title="Database Down",
        description="Critical failure on database",
    )
    response = orchestrator.handle_incident(incident)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    mock_executor.execute.assert_not_called()


# ==============================================================================
# Scaling Policy Safety & Replica Limit Enforcement Tests
# ==============================================================================

def test_policy_gate_denies_scaling_above_maximum():
    """Verify that requests scaling beyond max_instances are rejected by the policy gate."""
    gate = DeterministicPolicyGate(min_instances=1, max_instances=10)
    action = RecoveryAction(
        incident_id="inc-scale-high",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 50},
        safe_for_simulation=True,
    )
    state = _make_service("payment-service", ServiceStatus.DEGRADED)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "exceeds maximum allowed limit" in decision.reason


def test_policy_gate_denies_scaling_below_minimum():
    """Verify that requests scaling below min_instances are rejected by the policy gate."""
    gate = DeterministicPolicyGate(min_instances=1, max_instances=10)
    action = RecoveryAction(
        incident_id="inc-scale-low",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 0},
        safe_for_simulation=True,
    )
    state = _make_service("payment-service", ServiceStatus.DEGRADED)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "below minimum allowed limit" in decision.reason


def test_policy_gate_denies_scaling_invalid_requested_count():
    """Verify that non-integer or malformed requested counts are rejected."""
    gate = DeterministicPolicyGate(min_instances=1, max_instances=10)
    action = RecoveryAction(
        incident_id="inc-scale-invalid-req",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": "not_a_number"},
        safe_for_simulation=True,
    )
    state = _make_service("payment-service", ServiceStatus.DEGRADED)
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "not a valid integer" in decision.reason


def test_policy_gate_denies_scaling_invalid_current_count():
    """Verify that out-of-bounds or corrupted current replica counts cause rejection."""
    gate = DeterministicPolicyGate(min_instances=1, max_instances=10)
    action = RecoveryAction(
        incident_id="inc-scale-invalid-cur",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 4},
        safe_for_simulation=True,
    )
    # State with current instances = 15 (> max_instances 10)
    state = ServiceInfo(
        name="payment-service",
        status=ServiceStatus.DEGRADED,
        cpu_percent=50,
        memory_percent=50,
        error_rate=0.2,
        instances=15,
    )
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.DENY
    assert "out of bounds" in decision.reason


def test_policy_gate_approves_safe_scaling():
    """Verify that scaling within min/max bounds on valid current state is approved."""
    gate = DeterministicPolicyGate(min_instances=1, max_instances=10)
    action = RecoveryAction(
        incident_id="inc-scale-safe",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 5},
        safe_for_simulation=True,
    )
    state = ServiceInfo(
        name="payment-service",
        status=ServiceStatus.DEGRADED,
        cpu_percent=80,
        memory_percent=70,
        error_rate=0.3,
        instances=2,
    )
    decision = gate.evaluate(action, state)
    assert decision.verdict == DecisionVerdict.APPROVE
    assert decision.is_approved is True
    assert "approved" in decision.reason


def test_unsafe_scaling_strictly_prevents_executor_invocation():
    """Verify that policy gate denial for excessive scaling prevents executor execution."""
    infra = InfrastructureSimulator()
    infra.register_service("payment-service", status=ServiceStatus.DEGRADED, instances=2)
    mock_executor = MagicMock(spec=SimulatedRecoveryExecutor)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(max_instances=10),
        executor=mock_executor,
    )

    excessive_action = RecoveryAction(
        incident_id="inc-scale-exec-deny",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 50},
        safe_for_simulation=True,
    )
    incident = Incident(
        id="inc-scale-exec-deny",
        service_name="payment-service",
        severity=IncidentSeverity.HIGH,
        title="Traffic Spike",
        description="Massive spike requiring scale",
    )

    response = orchestrator.handle_incident(incident, proposed_action=excessive_action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    mock_executor.execute.assert_not_called()
