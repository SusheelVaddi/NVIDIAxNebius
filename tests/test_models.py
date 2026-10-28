"""Tests for Pydantic data models.

Covers:
- valid model creation
- invalid values
- required fields
- serialization and deserialization
- status fields progression
"""

import pytest
from pydantic import ValidationError

from app.models import (
    AuditEvent,
    AuditEventType,
    AuditRecord,
    DecisionVerdict,
    Incident,
    IncidentResponse,
    IncidentSeverity,
    IncidentStatus,
    PipelineStatus,
    PolicyDecision,
    RecoveryAction,
    RecoveryActionType,
    RecoveryResult,
    ServiceInfo,
    ServiceStatus,
    SystemState,
    VerificationOutcome,
    VerificationResult,
)


def test_service_info_creation():
    svc = ServiceInfo(name="test", status=ServiceStatus.HEALTHY, cpu_percent=10, memory_percent=20, error_rate=0.0)
    assert svc.status == ServiceStatus.HEALTHY
    assert svc.name == "test"
    assert svc.service_name == "test"


def test_system_state_invalid_metrics():
    with pytest.raises(ValidationError):
        # cpu_percent > 100
        SystemState(service_name="web", status=ServiceStatus.HEALTHY, cpu_percent=150.0, memory_percent=20, error_rate=0.0)

    with pytest.raises(ValidationError):
        # error_rate > 1.0
        SystemState(service_name="web", status=ServiceStatus.HEALTHY, cpu_percent=50.0, memory_percent=20, error_rate=1.5)


def test_incident_validation():
    inc = Incident(service_name="web", severity=IncidentSeverity.LOW, description="x")
    assert len(inc.id) == 12
    assert inc.status == IncidentStatus.DETECTED

    # Whitespace in service_name must raise ValidationError
    with pytest.raises(ValidationError):
        Incident(service_name="web frontend", severity=IncidentSeverity.LOW)


def test_recovery_action_creation_and_serialization():
    act = RecoveryAction(
        incident_id="inc-123",
        action_type=RecoveryActionType.CLEAR_QUEUE,
        target_service="queue-service",
        safe_for_simulation=True,
        risk_level=2,
    )
    json_str = act.model_dump_json()
    restored = RecoveryAction.model_validate_json(json_str)
    assert restored.action_type == RecoveryActionType.CLEAR_QUEUE
    assert restored.safe_for_simulation is True


def test_policy_decision_creation():
    pd = PolicyDecision(
        incident_id="inc-123",
        verdict=DecisionVerdict.APPROVE,
        reason="Approved",
    )
    assert pd.is_approved is True
    assert pd == DecisionVerdict.APPROVE


def test_recovery_result_serialisation():
    rr = RecoveryResult(
        action=RecoveryActionType.RESTART_SERVICE,
        service_name="web",
        success=True,
        message="ok",
    )
    data = rr.model_dump()
    assert data["action"] == "restart_service"
    assert data["success"] is True


def test_verification_result():
    vr = VerificationResult(
        service_name="web",
        outcome=VerificationOutcome.PASS,
        details="all good",
    )
    assert vr.outcome == VerificationOutcome.PASS


def test_audit_event_required_fields_and_serialization():
    ev = AuditEvent(
        incident_id="inc-999",
        component_name="DeterministicPolicyGate",
        event_type=AuditEventType.POLICY_EVALUATED.value,
        success=True,
        explanation="Gate approved action",
        details={"risk": 1},
    )
    assert len(ev.id) > 0
    assert ev.component_name == "DeterministicPolicyGate"
    assert ev.success is True

    json_str = ev.model_dump_json()
    restored = AuditEvent.model_validate_json(json_str)
    assert restored.id == ev.id
    assert restored.incident_id == ev.incident_id


def test_incident_response_round_trip():
    inc = Incident(service_name="api", severity=IncidentSeverity.HIGH, description="d")
    resp = IncidentResponse(
        incident=inc,
        policy_decision=PolicyDecision(incident_id=inc.id, verdict=DecisionVerdict.APPROVE, reason="ok"),
        pipeline_status=PipelineStatus.SUCCESS,
    )
    json_str = resp.model_dump_json()
    restored = IncidentResponse.model_validate_json(json_str)
    assert restored.incident.service_name == "api"
    assert restored.pipeline_status == PipelineStatus.SUCCESS


def test_audit_record_round_trip():
    inc = Incident(service_name="api", severity=IncidentSeverity.HIGH, description="d")
    record = AuditRecord(
        incident=inc,
        policy_decision=PolicyDecision.APPROVE,
        pipeline_status=PipelineStatus.SUCCESS,
    )
    json_str = record.model_dump_json()
    restored = AuditRecord.model_validate_json(json_str)
    assert restored.incident.service_name == "api"
    assert restored.pipeline_status == PipelineStatus.SUCCESS
