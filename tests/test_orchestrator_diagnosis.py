"""Integration tests for AI diagnosis integration within the Orchestrator.

Verifies:
1. A successful AI diagnosis proposes a recovery action.
2. The deterministic policy gate vetoes an AI-recommended action when unsafe or not allowed.
3. A diagnosis/client error falls back to the existing heuristic recovery behavior.
4. An unexpected programming error is not silently swallowed.
5. An explicitly supplied proposed_action bypasses AI diagnosis.
6. Audit metadata is recorded correctly and the audit event count/order remains unchanged.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.audit import AuditLogger
from app.diagnosis import (
    DiagnosisError,
    DiagnosisResult,
    IncidentDiagnoser,
    NemotronAPIError,
    NemotronAuthError,
    NemotronClient,
    NemotronConnectionError,
    NemotronTimeoutError,
)
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
    SystemState,
)
from app.orchestrator import Orchestrator
from app.policy import DeterministicPolicyGate
from app.recovery import SimulatedRecoveryExecutor
from app.verification import IndependentVerifier


@pytest.fixture()
def infra():
    """Fresh infrastructure simulator."""
    sim = InfrastructureSimulator()
    return sim


@pytest.fixture()
def audit(tmp_path: Path):
    """Isolated audit logger using temporary file."""
    log_path = tmp_path / "test_orchestrator_diagnosis_audit.jsonl"
    logger = AuditLogger(path=log_path)
    yield logger
    logger.clear()


@pytest.fixture()
def base_policy_gate():
    """Configured DeterministicPolicyGate instance."""
    return DeterministicPolicyGate(
        max_risk_limit=5,
        max_retry_limit=3,
        required_parameters={
            RecoveryActionType.SCALE_SERVICE.value: {"target_instances"},
        },
        protected_services={"database"},
    )


@pytest.fixture()
def successful_diagnosis_result() -> DiagnosisResult:
    """Fixture providing a valid DiagnosisResult."""
    return DiagnosisResult(
        likely_cause="Worker thread memory leak under sustained load",
        evidence=["Memory utilization exceeded 90%", "Worker process unresponsive"],
        confidence=0.92,
        recommended_action_id="restart_service",
        rationale="Restarting resets worker process heaps and clears memory bloat.",
        uncertainty_or_notes="Monitor worker thread count post-restart.",
    )


def _make_mock_diagnoser(diagnosis_result: DiagnosisResult | None = None) -> IncidentDiagnoser:
    """Helper creating an IncidentDiagnoser with a mocked client returning diagnosis_result."""
    mock_client = MagicMock(spec=NemotronClient)
    diagnoser = IncidentDiagnoser(client=mock_client)
    if diagnosis_result is not None:
        diagnoser.diagnose = MagicMock(return_value=diagnosis_result)
    return diagnoser


# ==============================================================================
# 1. Successful AI Diagnosis Proposes Recovery Action
# ==============================================================================

def test_successful_ai_diagnosis_proposes_recovery_action(
    infra, audit, base_policy_gate, successful_diagnosis_result
):
    """Test that a valid AI diagnosis proposes an action that gets executed and verified."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    diagnoser = _make_mock_diagnoser(successful_diagnosis_result)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.incident.status == IncidentStatus.VERIFIED
    assert response.recovery_action is not None
    assert response.recovery_action.action_type == RecoveryActionType.RESTART_SERVICE
    assert response.recovery_action.target_service == "web-frontend"
    assert response.recovery_action.parameters["diagnosis_likely_cause"] == successful_diagnosis_result.likely_cause
    assert response.recovery_action.parameters["diagnosis_confidence"] == 0.92
    assert response.recovery_result is not None
    assert response.recovery_result.success is True
    assert infra.get_service("web-frontend").status == ServiceStatus.HEALTHY


def test_successful_ai_diagnosis_scaling_calculates_target_instances(
    infra, audit, base_policy_gate
):
    """Test that AI recommending scale_service automatically populates target_instances."""
    incident = infra.inject_incident("cache-layer", IncidentSeverity.MEDIUM)
    initial_instances = infra.get_service("cache-layer").instances

    scale_diagnosis = DiagnosisResult(
        likely_cause="High request throughput overwhelming cache capacity",
        evidence=["Latency p99 spiked above 800ms", "Cache hit ratio dropped"],
        confidence=0.88,
        recommended_action_id="scale_service",
        rationale="Scaling instances distributes key lookups.",
        uncertainty_or_notes="Verify cluster partition balance.",
    )
    diagnoser = _make_mock_diagnoser(scale_diagnosis)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(max_scale_limit=10),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_action.action_type == RecoveryActionType.SCALE_SERVICE
    assert response.recovery_action.parameters["target_instances"] == initial_instances + 1
    assert infra.get_service("cache-layer").instances == initial_instances + 1


# ==============================================================================
# 2. Deterministic Policy Gate Vetoes Unsafe AI Recommendation
# ==============================================================================

def test_policy_gate_vetoes_ai_recommended_action_on_protected_service(
    infra, audit, base_policy_gate
):
    """Policy gate must override and veto AI recommendation on critical protected database."""
    incident = infra.inject_incident("database", IncidentSeverity.CRITICAL)

    # AI recommends restarting database
    ai_recommendation = DiagnosisResult(
        likely_cause="Deadlock in database transaction log writer",
        evidence=["Disk I/O stalled", "Lock count exceeded 5000"],
        confidence=0.95,
        recommended_action_id="restart_service",
        rationale="Restarting database clears deadlock state.",
        uncertainty_or_notes="Uncommitted transactions will be rolled back.",
    )
    diagnoser = _make_mock_diagnoser(ai_recommendation)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    # Policy gate must reject automated recovery on protected database with critical severity
    assert response.policy_decision.verdict == DecisionVerdict.MANUAL_REVIEW
    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.incident.status == IncidentStatus.REJECTED
    # Crucial safety check: execution NEVER happened
    assert response.recovery_result is None
    assert infra.get_service("database").status != ServiceStatus.HEALTHY


def test_policy_gate_vetoes_disallowed_action(infra, audit):
    """Policy gate must reject an action type that is not in allowed_actions."""
    strict_gate = DeterministicPolicyGate(
        allowed_actions={RecoveryActionType.CLEAR_QUEUE.value}  # Only CLEAR_QUEUE allowed
    )

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)

    ai_recommendation = DiagnosisResult(
        likely_cause="Stuck process",
        evidence=["No response"],
        confidence=0.8,
        recommended_action_id="restart_service",  # Not in allowed_actions
        rationale="Restart process",
        uncertainty_or_notes="None",
    )
    diagnoser = _make_mock_diagnoser(ai_recommendation)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=strict_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    assert response.policy_decision.verdict == DecisionVerdict.DENY
    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.recovery_result is None


# ==============================================================================
# 3. Diagnosis/Client Errors Fall Back to Heuristic Recovery Behavior
# ==============================================================================

@pytest.mark.parametrize(
    "exception_to_raise, expected_reason_keyword",
    [
        (NemotronTimeoutError("Request timed out after 30s"), "timeout"),
        (NemotronConnectionError("DNS lookup failed"), "connection_failure"),
        (NemotronAuthError("Invalid key"), "authentication_failure"),
        (NemotronAPIError("Rate limited", status_code=429), "api_error"),
        (DiagnosisError("Schema invalid"), "schema_validation_failed"),
    ],
)
def test_diagnosis_and_client_errors_trigger_fallback(
    infra, audit, base_policy_gate, exception_to_raise, expected_reason_keyword
):
    """When diagnosis or client errors occur, orchestrator must fall back to heuristics."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)

    mock_client = MagicMock(spec=NemotronClient)
    diagnoser = IncidentDiagnoser(client=mock_client)
    diagnoser.diagnose = MagicMock(side_effect=exception_to_raise)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    # Recovery still succeeds via heuristic fallback
    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.incident.status == IncidentStatus.VERIFIED

    # Verify audit details record the sanitized fallback reason without raw error bodies
    events = audit.get_events_for_incident(incident.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)

    assert "diagnosis_fallback" in action_event.details
    fallback_info = action_event.details["diagnosis_fallback"]
    assert fallback_info["status"] == "failed"
    assert expected_reason_keyword in fallback_info["reason"]
    # Ensure raw exception / trace is NOT leaked
    assert str(exception_to_raise) not in fallback_info["reason"] or expected_reason_keyword in fallback_info["reason"]


# ==============================================================================
# 4. Unexpected Programming Error is NOT Silently Swallowed
# ==============================================================================

def test_unexpected_programming_error_is_not_swallowed(infra, audit, base_policy_gate):
    """Unexpected exceptions (e.g. TypeError, RuntimeError) must raise instead of falling back."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)

    mock_client = MagicMock(spec=NemotronClient)
    diagnoser = IncidentDiagnoser(client=mock_client)
    diagnoser.diagnose = MagicMock(side_effect=TypeError("Unexpected code defect"))

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    with pytest.raises(TypeError) as exc_info:
        orchestrator.handle_incident(incident)

    assert "Unexpected code defect" in str(exc_info.value)


# ==============================================================================
# 5. Explicitly Supplied proposed_action Bypasses AI Diagnosis
# ==============================================================================

def test_explicit_proposed_action_bypasses_ai_diagnosis(
    infra, audit, base_policy_gate
):
    """When caller supplies proposed_action, diagnoser must not be called."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)

    explicit_action = RecoveryAction(
        incident_id=incident.id,
        action_type=RecoveryActionType.CLEAR_QUEUE,
        target_service="web-frontend",
        safe_for_simulation=True,
    )

    diagnoser = _make_mock_diagnoser()
    diagnoser.diagnose = MagicMock()

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident, proposed_action=explicit_action)

    # Diagnoser must NOT have been called
    assert diagnoser.diagnose.call_count == 0
    assert response.recovery_action.action_type == RecoveryActionType.CLEAR_QUEUE

    # Audit details must not have diagnosis keys
    events = audit.get_events_for_incident(incident.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)
    assert "diagnosis" not in action_event.details
    assert "diagnosis_fallback" not in action_event.details


# ==============================================================================
# 6. Audit Metadata & Invariant Preservation
# ==============================================================================

def test_audit_event_count_order_and_metadata_preservation(
    infra, audit, base_policy_gate, successful_diagnosis_result
):
    """Verify that audit events count (7) and exact sequence remain unchanged with AI diagnosis."""
    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    diagnoser = _make_mock_diagnoser(successful_diagnosis_result)

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        executor=SimulatedRecoveryExecutor(),
        verifier=IndependentVerifier(),
        audit_logger=audit,
        diagnoser=diagnoser,
    )

    response = orchestrator.handle_incident(incident)

    events = audit.get_events_for_incident(incident.id)

    # Exactly 7 events
    assert len(events) == 7

    # Exact event sequence
    expected_event_types = [
        AuditEventType.INCIDENT_RECEIVED.value,
        AuditEventType.STATE_LOADED.value,
        AuditEventType.ACTION_PROPOSED.value,
        AuditEventType.POLICY_EVALUATED.value,
        AuditEventType.RECOVERY_EXECUTED.value,
        AuditEventType.VERIFICATION_COMPLETED.value,
        AuditEventType.PIPELINE_COMPLETED.value,
    ]
    assert [e.event_type for e in events] == expected_event_types

    # ACTION_PROPOSED metadata structure
    action_event = events[2]
    assert "recovery_action" in action_event.details
    assert "diagnosis" in action_event.details

    diag_data = action_event.details["diagnosis"]
    assert diag_data["likely_cause"] == successful_diagnosis_result.likely_cause
    assert diag_data["confidence"] == 0.92
    assert diag_data["recommended_action_id"] == "restart_service"
    assert diag_data["evidence"] == successful_diagnosis_result.evidence
    assert diag_data["rationale"] == successful_diagnosis_result.rationale
    assert diag_data["uncertainty_or_notes"] == successful_diagnosis_result.uncertainty_or_notes

    # Verify chronological ordering
    for i in range(len(events) - 1):
        assert events[i].timestamp <= events[i + 1].timestamp


# ==============================================================================
# 7. Environment-Based Wiring & API Configuration Tests
# ==============================================================================

def test_ai_diagnosis_disabled_by_default(infra, audit, monkeypatch):
    """When ENABLE_AI_DIAGNOSIS is unset or false, diagnoser is None and heuristics are used."""
    monkeypatch.delenv("ENABLE_AI_DIAGNOSIS", raising=False)

    orchestrator = Orchestrator(infra=infra, audit_logger=audit)
    assert orchestrator.diagnoser is None

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    response = orchestrator.handle_incident(incident)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_action.action_type == RecoveryActionType.RESTART_SERVICE

    events = audit.get_events_for_incident(incident.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)
    assert "diagnosis" not in action_event.details
    assert "diagnosis_fallback" not in action_event.details


def test_ai_diagnosis_enabled_via_env_with_mock_mode(infra, audit, monkeypatch):
    """When ENABLE_AI_DIAGNOSIS=true and NEBIUS_MOCK_MODE=true, diagnoser is active in mock mode."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "true")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "true")

    orchestrator = Orchestrator(infra=infra, audit_logger=audit)
    assert orchestrator.diagnoser is not None
    assert isinstance(orchestrator.diagnoser, IncidentDiagnoser)
    assert orchestrator.diagnoser.client.mock_mode is True

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW, "Connection pool saturated")
    response = orchestrator.handle_incident(incident)

    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_action.action_type == RecoveryActionType.RESTART_SERVICE
    assert "diagnosis_likely_cause" in response.recovery_action.parameters

    events = audit.get_events_for_incident(incident.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)
    assert "diagnosis" in action_event.details
    assert action_event.details["diagnosis"]["confidence"] == 0.88


def test_explicit_diagnoser_precedence_over_env_disabled(infra, audit, monkeypatch):
    """An explicit diagnoser takes precedence even if ENABLE_AI_DIAGNOSIS is false in the environment."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "false")

    custom_diagnosis = DiagnosisResult(
        likely_cause="Explicit diagnoser took precedence",
        evidence=["Custom observation"],
        confidence=0.99,
        recommended_action_id="restart_service",
        rationale="Custom rationale",
        uncertainty_or_notes="None",
    )
    explicit_diagnoser = _make_mock_diagnoser(custom_diagnosis)

    orchestrator = Orchestrator(
        infra=infra,
        audit_logger=audit,
        diagnoser=explicit_diagnoser,
    )
    assert orchestrator.diagnoser is explicit_diagnoser

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    response = orchestrator.handle_incident(incident)

    assert response.recovery_action.parameters["diagnosis_likely_cause"] == "Explicit diagnoser took precedence"


def test_explicit_diagnoser_precedence_over_env_enabled(infra, audit, monkeypatch):
    """An explicit diagnoser takes precedence over default initialization when ENABLE_AI_DIAGNOSIS is true."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "true")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "true")

    custom_diagnosis = DiagnosisResult(
        likely_cause="Specialized injected diagnoser",
        evidence=["Special signal"],
        confidence=0.95,
        recommended_action_id="restart_service",
        rationale="Special rationale",
        uncertainty_or_notes="None",
    )
    explicit_diagnoser = _make_mock_diagnoser(custom_diagnosis)

    orchestrator = Orchestrator(
        infra=infra,
        audit_logger=audit,
        diagnoser=explicit_diagnoser,
    )
    assert orchestrator.diagnoser is explicit_diagnoser

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    response = orchestrator.handle_incident(incident)

    assert response.recovery_action.parameters["diagnosis_likely_cause"] == "Specialized injected diagnoser"


def test_env_enabled_ai_diagnosis_policy_veto_on_critical_database(
    infra, audit, base_policy_gate, monkeypatch
):
    """When AI diagnosis is enabled via environment, policy gate still vetoes critical database actions."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "true")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "true")

    orchestrator = Orchestrator(
        infra=infra,
        policy_gate=base_policy_gate,
        audit_logger=audit,
    )

    incident = infra.inject_incident("database", IncidentSeverity.CRITICAL, "Database freeze")
    response = orchestrator.handle_incident(incident)

    # Policy gate must strictly enforce MANUAL_REVIEW and deny execution
    assert response.policy_decision.verdict == DecisionVerdict.MANUAL_REVIEW
    assert response.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert response.recovery_result is None
    assert infra.get_service("database").status == ServiceStatus.DOWN


def test_env_enabled_ai_diagnosis_failure_falls_back_safely(infra, audit, monkeypatch):
    """When AI diagnosis is enabled via env but fails (missing credentials), fallback safely recovers."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "true")
    # Missing credentials with mock mode disabled triggers NemotronAuthError
    monkeypatch.delenv("NEBIUS_MOCK_MODE", raising=False)
    monkeypatch.delenv("NEMOTRON_MOCK_MODE", raising=False)
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEMOTRON_API_KEY", raising=False)

    orchestrator = Orchestrator(infra=infra, audit_logger=audit)

    incident = infra.inject_incident("web-frontend", IncidentSeverity.LOW, "Server latency")
    response = orchestrator.handle_incident(incident)

    # Heuristic fallback succeeded
    assert response.pipeline_status == PipelineStatus.SUCCESS
    assert response.recovery_result is not None
    assert response.recovery_result.success is True

    # Audit records the safe fallback category
    events = audit.get_events_for_incident(incident.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)
    assert "diagnosis_fallback" in action_event.details
    assert action_event.details["diagnosis_fallback"]["status"] == "failed"
    assert "authentication_failure" in action_event.details["diagnosis_fallback"]["reason"]
    assert "diagnosis" not in action_event.details


def test_api_endpoint_with_env_enabled_ai_diagnosis(monkeypatch):
    """Verify that POST /api/incidents executes AI diagnosis through REST API when ENABLE_AI_DIAGNOSIS=true."""
    monkeypatch.setenv("ENABLE_AI_DIAGNOSIS", "true")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "true")

    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    response = client.post(
        "/api/incidents",
        json={
            "service_name": "web-frontend",
            "severity": "low",
            "description": "API integration diagnosis test",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["pipeline_status"] == "success"
    assert data["recovery_action"]["action_type"] == "restart_service"
    assert "diagnosis_likely_cause" in data["recovery_action"]["parameters"]
    assert data["recovery_action"]["parameters"]["diagnosis_confidence"] == 0.88


