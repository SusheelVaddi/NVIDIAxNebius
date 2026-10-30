"""Unit tests for the Member 3 Orchestration Layer.

Tests cover:
- approved action
- rejected unsafe action
- unknown service
- missing parameters
- executor failure
- verification failure
- audit events being written in the correct order
- clearing a simulated queue
- scaling within limits
"""

from pathlib import Path
import pytest

from app.audit import AuditLogger
from app.infrastructure import InfrastructureSimulator
from app.models import (
    AuditEventType,
    DecisionVerdict,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    PipelineStatus,
    RecoveryAction,
    RecoveryActionType,
    ServiceStatus,
    VerificationOutcome,
)
from app.orchestrator import Orchestrator
from app.policy import DeterministicPolicyGate
from app.recovery import SimulatedRecoveryExecutor
from app.verification import IndependentVerifier


@pytest.fixture()
def infra():
    """Fresh infrastructure simulator."""
    return InfrastructureSimulator()


@pytest.fixture()
def audit(tmp_path: Path):
    """Isolated audit logger using temporary file."""
    log_path = tmp_path / "test_orchestration_audit.jsonl"
    logger = AuditLogger(path=log_path)
    yield logger
    logger.clear()


@pytest.fixture()
def orchestrator(infra, audit):
    """Configured Orchestrator instance."""
    gate = DeterministicPolicyGate(
        max_risk_limit=5,
        max_retry_limit=3,
        required_parameters={
            RecoveryActionType.SCALE_SERVICE.value: {"target_instances"},
        },
    )
    executor = SimulatedRecoveryExecutor(max_scale_limit=10)
    verifier = IndependentVerifier()
    return Orchestrator(
        infra=infra,
        policy_gate=gate,
        executor=executor,
        verifier=verifier,
        audit_logger=audit,
    )


# ---------------------------------------------------------------------------
# 1. Approved action
# ---------------------------------------------------------------------------

def test_approved_action(orchestrator, infra, audit):
    """An approved action proceeds through policy, execution, and verification to success."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.HIGH)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        safe_for_simulation=True,
        risk_level=2,
        retry_count=0,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.incident.status == IncidentStatus.VERIFIED
    assert response.policy_decision.verdict == DecisionVerdict.APPROVE
    assert response.recovery_result is not None
    assert response.recovery_result.success is True
    assert response.verification_result is not None
    assert response.verification_result.outcome == VerificationOutcome.PASS
    assert infra.get_service("web-frontend").status == ServiceStatus.HEALTHY


# ---------------------------------------------------------------------------
# 2. Rejected unsafe action
# ---------------------------------------------------------------------------

def test_rejected_unsafe_action(orchestrator, infra, audit):
    """An action marked safe_for_simulation=False is rejected without execution."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.HIGH)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        safe_for_simulation=False,  # Unsafe!
        risk_level=1,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "unsafe" in response.policy_decision.reason.lower()
    # Executor must not have been executed
    assert response.recovery_result is None
    assert response.verification_result is None
    # Service remains down
    assert infra.get_service("web-frontend").status == ServiceStatus.DOWN


# ---------------------------------------------------------------------------
# 3. Unknown service
# ---------------------------------------------------------------------------

def test_unknown_service(orchestrator, infra, audit):
    """An action targeting a non-existent service is rejected without execution."""
    incident = Incident(
        service_name="nonexistent-ghost-service",
        severity=IncidentSeverity.MEDIUM,
        title="Incident on nonexistent service",
    )
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="nonexistent-ghost-service",
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "does not exist" in response.policy_decision.reason
    assert response.recovery_result is None


# ---------------------------------------------------------------------------
# 4. Missing parameters
# ---------------------------------------------------------------------------

def test_missing_parameters(orchestrator, infra, audit):
    """An action missing required parameters is rejected without execution."""
    incident = infra.inject_incident("api-gateway", IncidentSeverity.HIGH)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="api-gateway",
        parameters={},  # Missing 'target_instances'
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "missing required parameter" in response.policy_decision.reason.lower()
    assert "target_instances" in response.policy_decision.reason
    assert response.recovery_result is None


# ---------------------------------------------------------------------------
# 5. Executor failure
# ---------------------------------------------------------------------------

def test_executor_failure_exceeding_scale_limit(orchestrator, infra, audit):
    """When the executor fails (e.g. scaling limit exceeded), failure is recorded and verification skipped."""
    # Configure policy gate with higher ceiling to specifically test executor defense-in-depth failure
    orchestrator.policy_gate.max_instances = 100
    incident = infra.inject_incident("api-gateway", IncidentSeverity.HIGH)
    # Target instances exceeds executor limit of 10
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="api-gateway",
        parameters={"target_instances": 50},
        safe_for_simulation=True,
        risk_level=3,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_FAILED
    assert response.incident.status == IncidentStatus.FAILED
    assert response.policy_decision.verdict == DecisionVerdict.APPROVE
    assert response.recovery_result is not None
    assert response.recovery_result.success is False
    assert "exceeds" in response.recovery_result.message.lower()
    assert response.verification_result is None


# ---------------------------------------------------------------------------
# 6. Verification failure
# ---------------------------------------------------------------------------

def test_verification_failure_when_state_remains_unhealthy(orchestrator, infra, audit):
    """Independent verifier detects unhealthy state after recovery and does not trust executor blindly."""
    incident = infra.inject_incident("auth-service", IncidentSeverity.HIGH)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="auth-service",
        safe_for_simulation=True,
    )

    class FaultyExecutor(SimulatedRecoveryExecutor):
        def execute(self, act, sim):
            from app.models import RecoveryResult
            return RecoveryResult(
                action_id=act.id,
                incident_id=act.incident_id,
                action_type=act.action_type,
                target_service=act.target_service,
                success=True,
                message="Falsely claimed success without fixing service",
            )

    orchestrator.executor = FaultyExecutor()
    # Explicitly ensure service remains DOWN
    infra.fail_service("auth-service", status=ServiceStatus.DOWN, error_rate=0.8)

    response = orchestrator.handle_incident(incident, proposed_action=action)

    # Verifier independently checked state and caught the failure!
    assert response.pipeline_status == PipelineStatus.VERIFICATION_FAILED
    assert response.incident.status == IncidentStatus.FAILED
    assert response.recovery_result is not None
    assert response.recovery_result.success is True  # Executor falsely claimed success
    assert response.verification_result is not None
    assert response.verification_result.outcome == VerificationOutcome.FAIL
    assert "verification failed" in response.verification_result.details.lower()


# ---------------------------------------------------------------------------
# 7. Audit events written in correct order with all required fields
# ---------------------------------------------------------------------------

def test_audit_events_order_and_structure(orchestrator, infra, audit):
    """Every step writes an audit event in exact sequence with all 8 mandatory fields."""
    incident = infra.inject_incident("cache-layer", IncidentSeverity.LOW)
    response = orchestrator.handle_incident(incident)

    events = audit.get_events_for_incident(incident.id)
    assert len(events) == 7

    expected_event_types = [
        AuditEventType.INCIDENT_RECEIVED.value,
        AuditEventType.STATE_LOADED.value,
        AuditEventType.ACTION_PROPOSED.value,
        AuditEventType.POLICY_EVALUATED.value,
        AuditEventType.RECOVERY_EXECUTED.value,
        AuditEventType.VERIFICATION_COMPLETED.value,
        AuditEventType.PIPELINE_COMPLETED.value,
    ]

    actual_event_types = [e.event_type for e in events]
    assert actual_event_types == expected_event_types

    # Verify each event includes all 8 required fields:
    # 1. event ID (id)
    # 2. incident ID (incident_id)
    # 3. timestamp (timestamp)
    # 4. component name (component_name)
    # 5. event type (event_type)
    # 6. action or decision details (details)
    # 7. success or failure (success)
    # 8. human-readable explanation (explanation)
    for event in events:
        assert isinstance(event.id, str) and len(event.id) > 0
        assert event.incident_id == incident.id
        assert event.timestamp is not None
        assert isinstance(event.component_name, str) and len(event.component_name) > 0
        assert isinstance(event.event_type, str) and len(event.event_type) > 0
        assert isinstance(event.details, dict)
        assert isinstance(event.success, bool)
        assert isinstance(event.explanation, str) and len(event.explanation) > 0

    # Verify chronological timestamp ordering
    for i in range(len(events) - 1):
        assert events[i].timestamp <= events[i + 1].timestamp


# ---------------------------------------------------------------------------
# Additional feature tests: queue clearing and scaling within limits
# ---------------------------------------------------------------------------

def test_queue_clearing_action(orchestrator, infra, audit):
    """Simulated recovery executor clears a backed up queue and verifier confirms queue_size is 0."""
    infra.set_queue_size("api-gateway", size=500)
    assert infra.get_service("api-gateway").queue_size == 500

    incident = Incident(
        service_name="api-gateway",
        severity=IncidentSeverity.MEDIUM,
        title="High queue backlog on api-gateway",
        description="Queue backlog size reached 500 requests",
    )
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.CLEAR_QUEUE,
        target_service="api-gateway",
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_result.success is True
    assert response.verification_result.outcome == VerificationOutcome.PASS
    assert infra.get_service("api-gateway").queue_size == 0


def test_scaling_within_configured_limit(orchestrator, infra, audit):
    """Simulated recovery executor scales a service within limit and verifier confirms replica count."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.HIGH)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="web-frontend",
        parameters={"target_instances": 4},
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_result.success is True
    assert infra.get_service("web-frontend").instances == 4
    assert response.verification_result.outcome == VerificationOutcome.PASS


def test_policy_gate_rejects_exceeded_risk_limit(orchestrator, infra, audit):
    """Policy gate rejects an action if risk level exceeds configured limit."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        risk_level=9,  # max limit is 5
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "risk level 9 exceeds" in response.policy_decision.reason.lower()


def test_policy_gate_rejects_exceeded_retry_limit(orchestrator, infra, audit):
    """Policy gate rejects an action if retry limit is reached."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        retry_count=3,  # max retry limit is 3
        safe_for_simulation=True,
    )

    response = orchestrator.handle_incident(incident, proposed_action=action)

    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "retry count 3 reaches or exceeds" in response.policy_decision.reason.lower()
