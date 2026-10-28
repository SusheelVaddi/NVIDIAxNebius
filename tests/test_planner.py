"""Unit tests for AI Recovery Planners and Orchestrator integration.

Tests cover:
- AI recommendation approved by the policy gate
- AI recommendation rejected by the policy gate
- malformed AI output
- planner timeout
- planner failure with deterministic fallback
- complete successful recovery flow
- DeterministicMockPlanner rule-based proposals
- Authority isolation constraints
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
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
    RecoveryActionType,
    ServiceStatus,
    SystemState,
)
from app.orchestrator import Orchestrator
from app.policy import DeterministicPolicyGate
from app.recovery import (
    AIPlanProposal,
    DeterministicMockPlanner,
    NebiusPlanner,
    RecoveryPlanner,
    SimulatedRecoveryExecutor,
)
from app.verification import IndependentVerifier


@pytest.fixture()
def mock_planner():
    return DeterministicMockPlanner()


@pytest.fixture()
def sample_incident():
    return Incident(
        id="inc-test-01",
        service_name="web-frontend",
        severity=IncidentSeverity.HIGH,
        title="High error rate on web-frontend",
        description="Error rate spiked above 50%",
    )


@pytest.fixture()
def sample_state():
    return SystemState(
        service_name="web-frontend",
        status=ServiceStatus.DEGRADED,
        cpu_percent=45.0,
        memory_percent=55.0,
        error_rate=0.5,
        queue_size=0,
        instances=2,
    )


# ---------------------------------------------------------------------------
# 1. DeterministicMockPlanner Rules
# ---------------------------------------------------------------------------

def test_mock_planner_queue_backlog(mock_planner):
    inc = Incident(service_name="api-gateway", severity=IncidentSeverity.MEDIUM, title="Queue backlog high")
    state = SystemState(service_name="api-gateway", status=ServiceStatus.DEGRADED, cpu_percent=20, memory_percent=30, error_rate=0.1, queue_size=150)

    action = mock_planner.plan(inc, state)
    assert action.action_type == RecoveryActionType.CLEAR_QUEUE
    assert action.target_service == "api-gateway"
    assert action.safe_for_simulation is True


def test_mock_planner_scale_service_on_high_cpu(mock_planner):
    inc = Incident(service_name="api-gateway", severity=IncidentSeverity.HIGH, title="CPU overload")
    state = SystemState(service_name="api-gateway", status=ServiceStatus.DEGRADED, cpu_percent=85.0, memory_percent=50, error_rate=0.2, instances=2)

    action = mock_planner.plan(inc, state)
    assert action.action_type == RecoveryActionType.SCALE_SERVICE
    assert action.parameters.get("target_instances") == 3


def test_mock_planner_critical_severity_failover(mock_planner):
    inc = Incident(service_name="web-frontend", severity=IncidentSeverity.CRITICAL, title="Node crashed")
    state = SystemState(service_name="web-frontend", status=ServiceStatus.DOWN, cpu_percent=0, memory_percent=0, error_rate=1.0)

    action = mock_planner.plan(inc, state)
    assert action.action_type == RecoveryActionType.FAILOVER


def test_mock_planner_default_restart(mock_planner, sample_incident, sample_state):
    sample_incident.severity = IncidentSeverity.LOW
    sample_incident.title = "Minor glitch"
    sample_incident.description = "Intermittent timeout"
    sample_state.cpu_percent = 25.0

    action = mock_planner.plan(sample_incident, sample_state)
    assert action.action_type == RecoveryActionType.RESTART_SERVICE


# ---------------------------------------------------------------------------
# 2. AI Recommendation Approved by the Policy Gate
# ---------------------------------------------------------------------------

def test_ai_recommendation_approved_by_policy_gate(tmp_path):
    """When an AI model recommends a valid and safe action, the policy gate approves it and execution proceeds."""
    ai_content = json.dumps({
        "action_type": "restart_service",
        "target_service": "web-frontend",
        "parameters": {},
        "reasoning": "Restarting degraded frontend pod based on NVIDIA Nemotron recommendation.",
        "confidence": 0.95,
    })

    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {"choices": [{"message": {"content": ai_content}}]}

    infra = InfrastructureSimulator()
    infra.inject_incident("web-frontend", IncidentSeverity.HIGH)
    audit = AuditLogger(path=tmp_path / "test_approved.jsonl")

    planner = NebiusPlanner(
        api_key="valid-token-key",
        model="nvidia/llama-3.1-nemotron-70b-instruct",
    )

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        planner=planner,
    )

    incident = Incident(service_name="web-frontend", severity=IncidentSeverity.HIGH, title="Frontend degraded")

    with patch("httpx.Client.post", return_value=mock_res):
        response = orchestrator.handle_incident(incident)

        # Policy gate approved the AI recommendation
        assert response.policy_decision.verdict == DecisionVerdict.APPROVE
        assert response.pipeline_status == PipelineStatus.SUCCESS
        assert response.recovery_result is not None
        assert response.recovery_result.success is True
        assert response.verification_result.outcome.value == "pass"
        assert infra.get_service("web-frontend").status == ServiceStatus.HEALTHY


# ---------------------------------------------------------------------------
# 3. AI Recommendation Rejected by the Policy Gate
# ---------------------------------------------------------------------------

def test_ai_recommendation_rejected_by_policy_gate(tmp_path):
    """The policy gate remains the final authority: an unsafe AI recommendation is strictly rejected and never executed."""
    # AI hallucinated an unsafe action targeting a protected service or exceeding risk
    ai_content = json.dumps({
        "action_type": "restart_service",
        "target_service": "database",  # Protected service
        "parameters": {"severity": "critical"},
        "reasoning": "AI recommends restarting database during critical incident.",
        "confidence": 0.99,
    })

    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {"choices": [{"message": {"content": ai_content}}]}

    infra = InfrastructureSimulator()
    infra.inject_incident("database", IncidentSeverity.CRITICAL)
    audit = AuditLogger(path=tmp_path / "test_rejected.jsonl")

    planner = NebiusPlanner(api_key="valid-token-key")
    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        planner=planner,
    )

    incident = Incident(service_name="database", severity=IncidentSeverity.CRITICAL, title="Critical DB outage")

    with patch("httpx.Client.post", return_value=mock_res):
        response = orchestrator.handle_incident(incident)

        # Policy gate rejected AI recommendation: must NEVER execute
        assert response.policy_decision.verdict == DecisionVerdict.MANUAL_REVIEW
        assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
        assert response.incident.status == IncidentStatus.REJECTED
        assert response.recovery_result is None
        assert response.verification_result is None
        # Database service was NOT restarted; remains DOWN
        assert infra.get_service("database").status == ServiceStatus.DOWN


def test_ai_recommendation_rejected_unsafe_flag(tmp_path):
    """If AI output fails safe_for_simulation check, policy gate strictly denies execution."""
    planner = NebiusPlanner(api_key="valid-token-key")

    # Custom plan that produces safe_for_simulation=False
    def plan_unsafe(inc, state):
        act = DeterministicMockPlanner().plan(inc, state)
        act.safe_for_simulation = False
        return act

    planner.plan = plan_unsafe

    infra = InfrastructureSimulator()
    infra.inject_incident("web-frontend", IncidentSeverity.HIGH)
    audit = AuditLogger(path=tmp_path / "test_unsafe_flag.jsonl")

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        planner=planner,
    )

    incident = Incident(service_name="web-frontend", severity=IncidentSeverity.HIGH, title="Degraded")
    response = orchestrator.handle_incident(incident)

    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert "unsafe" in response.policy_decision.reason.lower()
    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.recovery_result is None


# ---------------------------------------------------------------------------
# 4. Malformed AI Output
# ---------------------------------------------------------------------------

def test_malformed_ai_output(sample_incident, sample_state):
    """When the model returns malformed JSON or missing fields, planner validates and falls back safely."""
    mock_res = MagicMock()
    mock_res.status_code = 200
    # Malformed JSON (unclosed braces)
    mock_res.json.return_value = {
        "choices": [{"message": {"content": '{"action_type": "restart_service", "target_service": "web-frontend"'}}]
    }

    planner = NebiusPlanner(api_key="valid-key")

    with patch("httpx.Client.post", return_value=mock_res):
        action = planner.plan(sample_incident, sample_state)

        # Safely fell back to deterministic mock planner
        assert action is not None
        assert action.target_service == sample_incident.service_name
        assert action.action_type in list(RecoveryActionType)
        assert action.safe_for_simulation is True


def test_malformed_ai_schema_validation_failure(sample_incident, sample_state):
    """When model returns JSON that violates the strict AIPlanProposal schema (e.g. confidence > 1.0), it falls back."""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "action_type": "restart_service",
                        "target_service": "web-frontend",
                        "parameters": {},
                        "reasoning": "Test",
                        "confidence": 1.5,  # Invalid: must be <= 1.0
                    })
                }
            }
        ]
    }

    planner = NebiusPlanner(api_key="valid-key")

    with patch("httpx.Client.post", return_value=mock_res):
        action = planner.plan(sample_incident, sample_state)

        # Validation failed and fell back
        assert action is not None
        assert action.target_service == sample_incident.service_name


# ---------------------------------------------------------------------------
# 5. Planner Timeout
# ---------------------------------------------------------------------------

def test_planner_timeout(sample_incident, sample_state):
    """When the Nebius API call times out, planner catches TimeoutException and uses deterministic fallback."""
    planner = NebiusPlanner(api_key="valid-key", timeout=1.0)

    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Connection timed out")):
        action = planner.plan(sample_incident, sample_state)

        # Recovered via fallback planner
        assert action is not None
        assert action.target_service == sample_incident.service_name
        assert action.action_type == RecoveryActionType.SCALE_UP


# ---------------------------------------------------------------------------
# 6. Planner Failure with Deterministic Fallback
# ---------------------------------------------------------------------------

def test_planner_failure_with_deterministic_fallback(sample_incident, sample_state):
    """When the Nebius API returns HTTP 500/503 error, planner falls back deterministically."""
    mock_res = MagicMock()
    mock_res.status_code = 503
    mock_res.raise_for_status.side_effect = httpx.HTTPStatusError("Service Unavailable", request=None, response=mock_res)

    planner = NebiusPlanner(api_key="valid-key")

    with patch("httpx.Client.post", return_value=mock_res):
        action = planner.plan(sample_incident, sample_state)

        assert action is not None
        assert action.target_service == sample_incident.service_name
        assert action.safe_for_simulation is True


# ---------------------------------------------------------------------------
# 7. Complete Successful Recovery Flow
# ---------------------------------------------------------------------------

def test_complete_successful_recovery_flow(tmp_path):
    """Verifies all 9 steps of the complete recovery lifecycle with AI recommendation in audit log."""
    ai_content = json.dumps({
        "action_type": "clear_queue",
        "target_service": "api-gateway",
        "parameters": {},
        "reasoning": "Clearing backed up queue on api-gateway using NVIDIA Nemotron 70B.",
        "confidence": 0.97,
    })

    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {"choices": [{"message": {"content": ai_content}}]}

    infra = InfrastructureSimulator()
    infra.set_queue_size("api-gateway", 400)
    assert infra.get_service("api-gateway").queue_size == 400

    audit = AuditLogger(path=tmp_path / "test_complete_9_steps.jsonl")
    planner = NebiusPlanner(
        api_key="test-key",
        model="nvidia/llama-3.1-nemotron-70b-instruct",
    )

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        planner=planner,
    )

    incident = Incident(
        id="inc-complete-09",
        service_name="api-gateway",
        severity=IncidentSeverity.MEDIUM,
        title="Queue backlog spike",
        description="Queue exceeded threshold",
    )

    with patch("httpx.Client.post", return_value=mock_res):
        # 1. Receive incident, 2. Load state, 3. Ask planner, 4. Record recommendation,
        # 5. Send to gate, 6. Execute approved, 7. Verify, 8. Record results, 9. Return response
        response = orchestrator.handle_incident(incident)

        # Step 9 verification: Complete IncidentResponse returned
        assert response.pipeline_status == PipelineStatus.SUCCESS
        assert response.incident.status == IncidentStatus.VERIFIED
        assert response.policy_decision.verdict == DecisionVerdict.APPROVE
        assert response.recovery_result.success is True
        assert response.verification_result.outcome.value == "pass"
        assert infra.get_service("api-gateway").queue_size == 0

        # Verify audit log trail captures all steps in exact order
        events = audit.get_events_for_incident("inc-complete-09")
        assert len(events) == 7

        event_types = [e.event_type for e in events]
        assert event_types == [
            AuditEventType.INCIDENT_RECEIVED.value,
            AuditEventType.STATE_LOADED.value,
            AuditEventType.ACTION_PROPOSED.value,
            AuditEventType.POLICY_EVALUATED.value,
            AuditEventType.RECOVERY_EXECUTED.value,
            AuditEventType.VERIFICATION_COMPLETED.value,
            AuditEventType.PIPELINE_COMPLETED.value,
        ]

        # Verify Step 4: AI recommendation recorded in audit log with planner attribution
        rec_event = events[2]
        assert rec_event.component_name == "RecoveryPlanner"
        assert "api-gateway" in rec_event.explanation
        assert rec_event.details["planner"] == "NebiusPlanner"
        assert rec_event.details["recovery_action"]["parameters"]["ai_confidence"] == 0.97
        assert "NVIDIA Nemotron" in rec_event.details["recovery_action"]["parameters"]["ai_reasoning"]

        # Verify Step 5: Policy gate evaluation event
        gate_event = events[3]
        assert gate_event.component_name == "DeterministicPolicyGate"
        assert gate_event.success is True

        # Verify Step 6: Simulated executor event
        exec_event = events[4]
        assert exec_event.component_name == "SimulatedRecoveryExecutor"
        assert exec_event.success is True

        # Verify Step 7 & 8: Independent verification and completion events
        verif_event = events[5]
        assert verif_event.component_name == "IndependentVerifier"
        assert verif_event.success is True

        comp_event = events[6]
        assert comp_event.component_name == "Orchestrator"
        assert comp_event.success is True


# ---------------------------------------------------------------------------
# 8. Authority Isolation Constraints
# ---------------------------------------------------------------------------

def test_ai_planner_cannot_execute_or_verify(sample_incident, sample_state):
    """Enforce authority isolation: RecoveryPlanner subclasses only suggest actions."""
    planner = NebiusPlanner(api_key="dummy")

    assert issubclass(NebiusPlanner, RecoveryPlanner)
    assert issubclass(DeterministicMockPlanner, RecoveryPlanner)

    # Must NOT possess execution or verification capabilities
    assert not hasattr(planner, "execute")
    assert not hasattr(planner, "verify")
    assert not hasattr(planner, "record_event")
    assert not hasattr(planner, "approve")
