"""Tests for the JSONL audit logger."""

import pytest
from pathlib import Path
import tempfile

from app.audit import AuditLogger
from app.models import (
    AuditRecord,
    Incident,
    IncidentSeverity,
    PipelineStatus,
    PolicyDecision,
)


@pytest.fixture()
def logger(tmp_path: Path):
    """Logger writing to a temp directory."""
    log_path = tmp_path / "test_audit.jsonl"
    lg = AuditLogger(path=log_path)
    yield lg
    lg.clear()


def _make_record() -> AuditRecord:
    inc = Incident(service_name="web", severity=IncidentSeverity.LOW, description="test")
    return AuditRecord(
        incident=inc,
        policy_decision=PolicyDecision.APPROVE,
        pipeline_status=PipelineStatus.SUCCESS,
    )


def test_log_and_read_back(logger: AuditLogger):
    record = _make_record()
    logger.log(record)
    records = logger.read_all()
    assert len(records) == 1
    assert records[0].incident.service_name == "web"


def test_multiple_records(logger: AuditLogger):
    for _ in range(5):
        logger.log(_make_record())
    assert len(logger.read_all()) == 5


def test_read_empty_log(logger: AuditLogger):
    assert logger.read_all() == []


def test_clear(logger: AuditLogger):
    logger.log(_make_record())
    logger.clear()
    assert logger.read_all() == []


def test_pipeline_records_persist_alongside_events(logger: AuditLogger):
    record = _make_record()
    logger.record_event(
        incident_id=record.incident.id,
        component_name="Orchestrator",
        event_type="incident_received",
        success=True,
        explanation="Incident received.",
    )
    logger.log_pipeline_record(record)

    restarted_logger = AuditLogger(path=logger.path)
    persisted = restarted_logger.read_all()

    assert len(persisted) == 1
    assert isinstance(persisted[0], AuditRecord)
    assert persisted[0].incident.id == record.incident.id


def test_hash_chain_verifies_after_restart_and_detects_tampering(logger: AuditLogger):
    logger.record_event(
        incident_id="integrity-test",
        component_name="Orchestrator",
        event_type="incident_received",
        success=True,
        explanation="Incident received.",
    )
    logger.log(_make_record())
    assert logger.verify_integrity() is True
    assert AuditLogger(path=logger.path).verify_integrity() is True

    lines = logger.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("Incident received.", "Tampered event.")
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert logger.verify_integrity() is False
# ==============================================================================
# End-to-End Audit Trail & Observability Scenario Tests
# ==============================================================================

from unittest.mock import MagicMock
from app.diagnosis import IncidentDiagnoser, NemotronClient, NemotronTimeoutError
from app.infrastructure import InfrastructureSimulator
from app.models import (
    AuditEventType,
    RecoveryAction,
    RecoveryActionType,
    RecoveryResult,
    ServiceStatus,
    VerificationOutcome,
)
from app.orchestrator import Orchestrator
from app.policy import DeterministicPolicyGate
from app.recovery import SimulatedRecoveryExecutor
from app.verification import IndependentVerifier


def test_audit_successful_recovery_trail(tmp_path: Path):
    """Verify that a successful incident recovery logs all events with complete metadata."""
    log_path = tmp_path / "test_successful_recovery.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()
    orch = Orchestrator(infra=infra, audit_logger=audit)

    inc = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    resp = orch.handle_incident(inc)

    assert resp.pipeline_status == PipelineStatus.SUCCESS
    events = audit.get_events_for_incident(inc.id)
    assert len(events) in (7, 8)

    actual_types = [e.event_type for e in events]
    if len(events) == 8:
        assert actual_types == [
            AuditEventType.INCIDENT_RECEIVED.value,
            AuditEventType.STATE_LOADED.value,
            AuditEventType.DIAGNOSIS_COMPLETED.value,
            AuditEventType.ACTION_PROPOSED.value,
            AuditEventType.POLICY_EVALUATED.value,
            AuditEventType.RECOVERY_EXECUTED.value,
            AuditEventType.VERIFICATION_COMPLETED.value,
            AuditEventType.PIPELINE_COMPLETED.value,
        ]
    else:
        assert actual_types == [
            AuditEventType.INCIDENT_RECEIVED.value,
            AuditEventType.STATE_LOADED.value,
            AuditEventType.ACTION_PROPOSED.value,
            AuditEventType.POLICY_EVALUATED.value,
            AuditEventType.RECOVERY_EXECUTED.value,
            AuditEventType.VERIFICATION_COMPLETED.value,
            AuditEventType.PIPELINE_COMPLETED.value,
        ]

    # Verify action details are non-sensitive and complete
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)
    assert action_event.component_name in ("Orchestrator", "RecoveryPlanner")
    assert "recovery_action" in action_event.details
    action_dict = action_event.details["recovery_action"]
    assert action_dict["action_type"] == "restart_service"
    assert action_dict["target_service"] == "web-frontend"
    assert "severity" in action_dict["parameters"]

    # Verify JSONL persistence on disk
    persisted = audit.read_events()
    assert len(persisted) == len(events)


def test_audit_failed_recovery_audit(tmp_path: Path):
    """Verify that recovery execution failure is recorded and skips verification."""
    log_path = tmp_path / "test_failed_recovery.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()
    orch = Orchestrator(infra=infra, audit_logger=audit)

    inc = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    mock_executor = MagicMock(spec=SimulatedRecoveryExecutor)
    mock_executor.execute.return_value = RecoveryResult(
        incident_id=inc.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        success=False,
        message="Process failed to start on port 80",
    )
    orch.executor = mock_executor

    resp = orch.handle_incident(inc)
    assert resp.pipeline_status == PipelineStatus.RECOVERY_FAILED

    events = audit.get_events_for_incident(inc.id)
    event_types = [e.event_type for e in events]
    assert AuditEventType.RECOVERY_EXECUTED.value in event_types
    assert AuditEventType.VERIFICATION_COMPLETED.value not in event_types
    assert AuditEventType.PIPELINE_COMPLETED.value in event_types

    rec_event = next(e for e in events if e.event_type == AuditEventType.RECOVERY_EXECUTED.value)
    assert rec_event.success is False
    assert "Process failed to start on port 80" in rec_event.explanation

    final_event = events[-1]
    assert final_event.event_type == AuditEventType.PIPELINE_COMPLETED.value
    assert final_event.success is False
    assert final_event.details["pipeline_status"] == PipelineStatus.RECOVERY_FAILED.value


def test_audit_diagnosis_fallback_audit(tmp_path: Path):
    """Verify that diagnosis failure records diagnosis_fallback and uses deterministic action."""
    log_path = tmp_path / "test_diagnosis_fallback.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()

    mock_client = MagicMock(spec=NemotronClient)
    mock_client.complete.side_effect = NemotronTimeoutError("Request timed out after 30.0s")
    diagnoser = IncidentDiagnoser(client=mock_client)

    orch = Orchestrator(infra=infra, audit_logger=audit, diagnoser=diagnoser)
    inc = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    resp = orch.handle_incident(inc)

    events = audit.get_events_for_incident(inc.id)
    action_event = next(e for e in events if e.event_type == AuditEventType.ACTION_PROPOSED.value)

    assert "diagnosis_fallback" in action_event.details
    fallback_data = action_event.details["diagnosis_fallback"]
    assert fallback_data["status"] == "failed"
    assert "timeout" in fallback_data["reason"]
    assert action_event.details["recovery_action"]["action_type"] == "restart_service"


def test_audit_policy_rejection_audit(tmp_path: Path):
    """Verify that policy rejection logs policy_evaluated and recovery_skipped without executing."""
    log_path = tmp_path / "test_policy_rejection.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()
    policy_gate = DeterministicPolicyGate(protected_services={"database"})
    orch = Orchestrator(infra=infra, policy_gate=policy_gate, audit_logger=audit)

    inc = infra.inject_incident("database", IncidentSeverity.CRITICAL)
    resp = orch.handle_incident(inc)

    assert resp.pipeline_status == PipelineStatus.RECOVERY_DENIED
    events = audit.get_events_for_incident(inc.id)
    event_types = [e.event_type for e in events]

    assert AuditEventType.POLICY_EVALUATED.value in event_types
    assert AuditEventType.RECOVERY_SKIPPED.value in event_types
    assert AuditEventType.RECOVERY_EXECUTED.value not in event_types
    assert AuditEventType.VERIFICATION_COMPLETED.value not in event_types

    eval_event = next(e for e in events if e.event_type == AuditEventType.POLICY_EVALUATED.value)
    assert eval_event.success is False
    assert "manual_review" in eval_event.explanation or "denied" in eval_event.explanation

    skip_event = next(e for e in events if e.event_type == AuditEventType.RECOVERY_SKIPPED.value)
    assert skip_event.success is False
    assert "rejected by policy gate" in skip_event.explanation


def test_audit_verification_failure_audit(tmp_path: Path):
    """Verify that failed post-recovery verification logs failure and flags pipeline as verification_failed."""
    log_path = tmp_path / "test_verification_failure.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()
    orch = Orchestrator(infra=infra, audit_logger=audit)

    infra.set_queue_size("auth-service", 500)
    inc = Incident(
        service_name="auth-service",
        severity=IncidentSeverity.MEDIUM,
        title="Stalled workers",
        description="Workers stalled with backlog",
    )
    restart_action = RecoveryAction(
        incident_id=inc.id,
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="auth-service",
        safe_for_simulation=True,
    )
    resp = orch.handle_incident(inc, proposed_action=restart_action)

    assert resp.pipeline_status == PipelineStatus.VERIFICATION_FAILED
    events = audit.get_events_for_incident(inc.id)
    event_types = [e.event_type for e in events]

    assert AuditEventType.VERIFICATION_COMPLETED.value in event_types
    verif_event = next(e for e in events if e.event_type == AuditEventType.VERIFICATION_COMPLETED.value)
    assert verif_event.success is False
    assert "queue backlog 500 exceeds threshold" in verif_event.explanation

    final_event = events[-1]
    assert final_event.event_type == AuditEventType.PIPELINE_COMPLETED.value
    assert final_event.success is False
    assert final_event.details["pipeline_status"] == PipelineStatus.VERIFICATION_FAILED.value


def test_audit_chronological_ordering(tmp_path: Path):
    """Verify that all recorded audit events possess strictly non-decreasing UTC timestamps."""
    log_path = tmp_path / "test_chronological.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()
    orch = Orchestrator(infra=infra, audit_logger=audit)

    inc = infra.inject_incident("api-gateway", IncidentSeverity.LOW)
    orch.handle_incident(inc)

    events = audit.get_events_for_incident(inc.id)
    assert len(events) >= 5

    for i in range(len(events) - 1):
        assert events[i].timestamp <= events[i + 1].timestamp
        assert events[i].timestamp.tzinfo is not None


def test_audit_sensitive_information_exclusion(tmp_path: Path, monkeypatch):
    """Verify that raw API keys, bearer tokens, and credentials never enter audit logs or events."""
    secret_key = "nebius_super_secret_test_token_12345"
    monkeypatch.setenv("NEBIUS_API_KEY", secret_key)

    log_path = tmp_path / "test_secrets.jsonl"
    audit = AuditLogger(path=log_path)
    infra = InfrastructureSimulator()

    mock_client = MagicMock(spec=NemotronClient)
    mock_client.complete.side_effect = NemotronTimeoutError("Nebius timeout after 30s")
    diagnoser = IncidentDiagnoser(client=mock_client)

    orch = Orchestrator(infra=infra, audit_logger=audit, diagnoser=diagnoser)
    inc = infra.inject_incident("web-frontend", IncidentSeverity.LOW)
    orch.handle_incident(inc)

    with open(log_path, "r", encoding="utf-8") as fh:
        raw_content = fh.read()

    assert secret_key not in raw_content
    events = audit.get_events_for_incident(inc.id)
    for ev in events:
        ev_json = ev.model_dump_json()
        assert secret_key not in ev_json
        assert "Bearer" not in ev_json


# ==============================================================================
# Audit Hash Chain & Integrity Verification Tests
# ==============================================================================

import json
from app.audit.logger import GENESIS_HASH


def test_audit_hash_chain_normal_integrity(tmp_path: Path):
    """Verify that an untampered sequence of audit events passes integrity verification."""
    log_path = tmp_path / "test_normal_chain.jsonl"
    logger = AuditLogger(path=log_path)

    for i in range(5):
        logger.record_event(
            incident_id=f"inc-{i}",
            component_name="Orchestrator",
            event_type="incident_received",
            success=True,
            explanation=f"Step {i} executed normally.",
            details={"step": i},
        )

    report = logger.verify_integrity()
    assert report.is_valid is True
    assert report.verified_events == 5
    assert len(report.errors) == 0

    events = logger.read_events()
    assert events[0].previous_hash == GENESIS_HASH
    for j in range(1, len(events)):
        assert events[j].previous_hash == events[j - 1].event_hash


def test_audit_tampering_detection(tmp_path: Path):
    """Verify that unauthorized modification of event contents is detected as tampering."""
    log_path = tmp_path / "test_tampering.jsonl"
    logger = AuditLogger(path=log_path)

    for i in range(3):
        logger.record_event(
            incident_id="inc-tamper",
            component_name="RecoveryExecutor",
            event_type="recovery_executed",
            success=True,
            explanation=f"Legitimate action {i}",
        )

    # Tamper with the 2nd record directly in the JSONL file
    with open(log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    record_1 = json.loads(lines[1])
    record_1["explanation"] = "MALICIOUSLY TAMPERED EXPLANATION"
    lines[1] = json.dumps(record_1) + "\n"

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # Re-read and verify integrity
    reopened_logger = AuditLogger(path=log_path)
    report = reopened_logger.verify_integrity()

    assert report.is_valid is False
    assert any("tampering or hash corruption detected" in err for err in report.errors)


def test_audit_reordered_records_detection(tmp_path: Path):
    """Verify that reordering or swapping audit records breaks the hash chain and is detected."""
    log_path = tmp_path / "test_reorder.jsonl"
    logger = AuditLogger(path=log_path)

    for i in range(3):
        logger.record_event(
            incident_id="inc-reorder",
            component_name="Orchestrator",
            event_type=f"step_{i}",
            success=True,
            explanation=f"Sequential step {i}",
        )

    # Swap record 1 and record 2 in the file
    with open(log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    lines[1], lines[2] = lines[2], lines[1]

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    reopened_logger = AuditLogger(path=log_path)
    report = reopened_logger.verify_integrity()

    assert report.is_valid is False
    assert any("hash chain broken" in err or "timestamp anomaly" in err for err in report.errors)


def test_audit_corrupted_records_detection(tmp_path: Path):
    """Verify that corrupted event hashes or missing intermediate records are caught."""
    log_path = tmp_path / "test_corrupted.jsonl"
    logger = AuditLogger(path=log_path)

    for i in range(3):
        logger.record_event(
            incident_id="inc-corrupt",
            component_name="Verifier",
            event_type="verification_completed",
            success=True,
            explanation=f"Probe check {i}",
        )

    with open(log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    # Corrupt the hash in line 0
    rec = json.loads(lines[0])
    rec["event_hash"] = "deadbeef" * 8
    lines[0] = json.dumps(rec) + "\n"

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    reopened_logger = AuditLogger(path=log_path)
    report = reopened_logger.verify_integrity()

    assert report.is_valid is False
    assert any("content tampering or hash corruption" in err or "hash chain broken" in err for err in report.errors)


def test_audit_malformed_entries_detection(tmp_path: Path):
    """Verify that malformed / non-JSON lines produce explicit errors and warnings."""
    log_path = tmp_path / "test_malformed.jsonl"
    logger = AuditLogger(path=log_path)

    logger.record_event(
        incident_id="inc-malformed",
        component_name="Orchestrator",
        event_type="incident_received",
        success=True,
        explanation="Valid first record",
    )

    # Append a corrupted non-JSON line and a truncated JSON line
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write("THIS_IS_CORRUPTED_NON_JSON_DATA\n")
        fh.write("{\"id\": \"incomplete_record\"\n")

    reopened_logger = AuditLogger(path=log_path)
    report = reopened_logger.verify_integrity()

    assert report.is_valid is False
    assert any("malformed audit entry" in err for err in report.errors)

    # Strict read raises ValueError explicitly
    with pytest.raises(ValueError, match="Malformed audit record"):
        reopened_logger.read_events(strict=True)


def test_audit_secret_scrubbing_on_write(tmp_path: Path):
    """Verify that sensitive tokens, keys, and authorization secrets are scrubbed before persistence."""
    log_path = tmp_path / "test_scrubbing.jsonl"
    logger = AuditLogger(path=log_path)

    logger.record_event(
        incident_id="inc-scrub",
        component_name="APIClient",
        event_type="request_dispatched",
        success=True,
        explanation="Dispatched request with Bearer secret-auth-token-99999",
        details={
            "api_key": "raw_super_secret_nebius_key",
            "admin_reset_token": "admin_pass_1234",
            "user_token": "token_abc",
            "nested": {
                "secret_credential": "password_xyz",
                "normal_param": "safe_value",
            },
        },
    )

    with open(log_path, "r", encoding="utf-8") as fh:
        content = fh.read()

    assert "raw_super_secret_nebius_key" not in content
    assert "admin_pass_1234" not in content
    assert "password_xyz" not in content
    assert "secret-auth-token-99999" not in content
    assert "[REDACTED]" in content
    assert "safe_value" in content
