"""Tests for FastAPI endpoints.

Covers:
- successful recovery
- rejected action
- failed verification
- invalid request
- audit-log retrieval
- health check probe
"""

from fastapi.testclient import TestClient
import pytest

from app.api.routes import get_orchestrator
from app.audit import AuditLogger, audit_logger
from app.infrastructure import InfrastructureSimulator, infra
from app.main import app
from app.models import (
    AuditEvent,
    IncidentSeverity,
    RecoveryAction,
    RecoveryActionType,
    ServiceStatus,
    SystemState,
    VerificationOutcome,
    VerificationResult,
)
from app.orchestrator import Orchestrator
from app.policy import DeterministicPolicyGate
from app.recovery import SimulatedRecoveryExecutor
from app.verification import IndependentVerifier

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_state():
    """Reset infrastructure and audit log before each test."""
    client.post("/reset")
    yield
    client.post("/reset")


# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------

def test_health_check():
    """Liveness probe works at both /health and /api/health."""
    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json() == {"status": "ok"}

    res_api = client.get("/api/health")
    assert res_api.status_code == 200
    assert res_api.json() == {"status": "ok"}


def test_reset_requires_configured_admin_token(monkeypatch):
    monkeypatch.setenv("ADMIN_RESET_TOKEN", "test-admin-token")

    assert client.post("/reset").status_code == 403
    assert client.post(
        "/reset", headers={"X-Admin-Reset-Token": "wrong-token"}
    ).status_code == 403

    response = client.post(
        "/reset", headers={"X-Admin-Reset-Token": "test-admin-token"}
    )
    assert response.status_code == 200
    assert response.json() == {"status": "reset"}


def test_dashboard_is_served_from_application():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Incident recovery" in response.text

    dashboard_response = client.get("/dashboard")
    assert dashboard_response.status_code == 200
    assert dashboard_response.text == response.text


# ---------------------------------------------------------------------------
# 2. Successful recovery
# ---------------------------------------------------------------------------

def test_successful_recovery():
    """POST /incidents/recover successfully recovers degraded service."""
    payload = {
        "incident_id": "inc-success-001",
        "incident_type": "high_error_rate",
        "affected_service": "web-frontend",
        "proposed_recovery_action": {
            "incident_id": "inc-success-001",
            "action_type": "restart_service",
            "target_service": "web-frontend",
            "parameters": {},
            "safe_for_simulation": True,
            "risk_level": 1,
            "retry_count": 0,
        },
        "current_system_state": {
            "service_name": "web-frontend",
            "status": "degraded",
            "cpu_percent": 30.0,
            "memory_percent": 45.0,
            "error_rate": 0.5,
            "queue_size": 0,
            "instances": 2,
        },
    }

    res = client.post("/incidents/recover", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert data["incident_id"] == "inc-success-001"
    assert data["final_status"] == "success"
    assert data["policy_decision"]["verdict"] == "approve"
    assert data["recovery_result"]["success"] is True
    assert data["verification_result"]["outcome"] == "pass"
    assert len(data["audit_events"]) == 7


# ---------------------------------------------------------------------------
# 3. Rejected action
# ---------------------------------------------------------------------------

def test_rejected_action_unsafe():
    """POST /incidents/recover rejects unsafe actions without execution."""
    payload = {
        "incident_id": "inc-unsafe-002",
        "incident_type": "hardware_failure",
        "affected_service": "api-gateway",
        "proposed_recovery_action": {
            "incident_id": "inc-unsafe-002",
            "action_type": "restart_service",
            "target_service": "api-gateway",
            "parameters": {},
            "safe_for_simulation": False,  # Unsafe!
            "risk_level": 1,
        },
        "current_system_state": {
            "service_name": "api-gateway",
            "status": "down",
            "cpu_percent": 20.0,
            "memory_percent": 30.0,
            "error_rate": 1.0,
        },
    }

    res = client.post("/incidents/recover", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert data["incident_id"] == "inc-unsafe-002"
    assert data["final_status"] == "recovery_denied"
    assert data["policy_decision"]["verdict"] == "deny"
    assert "unsafe" in data["policy_decision"]["reason"].lower()
    assert data["recovery_result"] is None
    assert data["verification_result"] is None


def test_rejected_action_unknown_service():
    """POST /incidents/recover rejects actions on unknown service."""
    payload = {
        "incident_id": "inc-unknown-003",
        "incident_type": "service_outage",
        "affected_service": "ghost-service",
        "proposed_recovery_action": {
            "incident_id": "inc-unknown-003",
            "action_type": "restart_service",
            "target_service": "ghost-service",
            "safe_for_simulation": True,
        },
        "current_system_state": {
            "service_name": "ghost-service",
            "status": "down",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "error_rate": 1.0,
        },
    }

    res = client.post("/incidents/recover", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert data["final_status"] == "recovery_denied"
    assert data["policy_decision"]["verdict"] == "deny"
    assert "does not exist" in data["policy_decision"]["reason"].lower()


# ---------------------------------------------------------------------------
# 4. Failed verification
# ---------------------------------------------------------------------------

def test_failed_verification(tmp_path):
    """POST /incidents/recover reports verification_failed when independent verification fails."""
    # Custom verifier that independently detects an unhealthy post-state
    class FailingVerifier(IndependentVerifier):
        def verify(self, service_name, infra, action=None, incident_id=""):
            return VerificationResult(
                incident_id=incident_id,
                service_name=service_name,
                outcome=VerificationOutcome.FAIL,
                details="Independent health probe failed: service returned HTTP 500.",
                checks_performed=["service_exists:PASS", "status_healthy:FAIL"],
            )

    test_infra = InfrastructureSimulator()
    test_audit = AuditLogger(path=tmp_path / "test_failed_verif.jsonl")
    failing_orchestrator = Orchestrator(
        infra=test_infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=FailingVerifier(),
        audit_logger=test_audit,
    )

    app.dependency_overrides[get_orchestrator] = lambda: failing_orchestrator

    try:
        payload = {
            "incident_id": "inc-verif-fail-004",
            "incident_type": "service_degraded",
            "affected_service": "auth-service",
            "proposed_recovery_action": {
                "incident_id": "inc-verif-fail-004",
                "action_type": "restart_service",
                "target_service": "auth-service",
                "safe_for_simulation": True,
            },
            "current_system_state": {
                "service_name": "auth-service",
                "status": "degraded",
                "cpu_percent": 40.0,
                "memory_percent": 50.0,
                "error_rate": 0.4,
            },
        }

        res = client.post("/incidents/recover", json=payload)
        assert res.status_code == 200

        data = res.json()
        assert data["incident_id"] == "inc-verif-fail-004"
        assert data["final_status"] == "verification_failed"
        assert data["recovery_result"]["success"] is True
        assert data["verification_result"]["outcome"] == "fail"
        assert "probe failed" in data["verification_result"]["details"]

    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 5. Invalid request
# ---------------------------------------------------------------------------

def test_invalid_request():
    """Malformed or incomplete request body returns 422 Unprocessable Entity."""
    # Completely empty body
    res_empty = client.post("/incidents/recover", json={})
    assert res_empty.status_code == 422

    # Missing proposed_recovery_action
    res_missing_action = client.post(
        "/incidents/recover",
        json={
            "incident_id": "inc-invalid",
            "incident_type": "crash",
            "affected_service": "web-frontend",
            "current_system_state": {
                "service_name": "web-frontend",
                "status": "down",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "error_rate": 1.0,
            },
        },
    )
    assert res_missing_action.status_code == 422

    # Invalid metric types
    res_invalid_types = client.post(
        "/incidents/recover",
        json={
            "incident_id": "inc-invalid",
            "incident_type": "crash",
            "affected_service": "web-frontend",
            "proposed_recovery_action": {
                "incident_id": "inc-invalid",
                "action_type": "restart_service",
                "target_service": "web-frontend",
            },
            "current_system_state": {
                "service_name": "web-frontend",
                "status": "down",
                "cpu_percent": 150.0,  # Invalid: > 100
                "memory_percent": 0.0,
                "error_rate": 1.0,
            },
        },
    )
    assert res_invalid_types.status_code == 422


# ---------------------------------------------------------------------------
# 6. Audit-log retrieval
# ---------------------------------------------------------------------------

def test_audit_log_retrieval():
    """GET /incidents/{incident_id}/audit returns full event trail; 404 for unknown incident."""
    incident_id = "inc-audit-retrieval-005"
    payload = {
        "incident_id": incident_id,
        "incident_type": "memory_leak",
        "affected_service": "cache-layer",
        "proposed_recovery_action": {
            "incident_id": incident_id,
            "action_type": "restart_service",
            "target_service": "cache-layer",
            "safe_for_simulation": True,
        },
        "current_system_state": {
            "service_name": "cache-layer",
            "status": "degraded",
            "cpu_percent": 15.0,
            "memory_percent": 90.0,
            "error_rate": 0.2,
        },
    }

    # Execute recovery first
    res_post = client.post("/incidents/recover", json=payload)
    assert res_post.status_code == 200

    # Retrieve audit log for this incident
    res_audit = client.get(f"/incidents/{incident_id}/audit")
    assert res_audit.status_code == 200
    events = res_audit.json()
    assert len(events) == 7
    assert all(e["incident_id"] == incident_id for e in events)

    # Check event order
    event_types = [e["event_type"] for e in events]
    assert event_types == [
        "incident_received",
        "state_loaded",
        "action_proposed",
        "policy_evaluated",
        "recovery_executed",
        "verification_completed",
        "pipeline_completed",
    ]

    # Querying a non-existent incident returns 404
    res_404 = client.get("/incidents/nonexistent-incident-id/audit")
    assert res_404.status_code == 404
    assert "No audit events found" in res_404.json()["detail"]


# ---------------------------------------------------------------------------
# 7. Existing API endpoints continue to function
# ---------------------------------------------------------------------------

def test_list_and_get_services():
    res_list = client.get("/services")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 5

    res_get = client.get("/services/web-frontend")
    assert res_get.status_code == 200
    assert res_get.json()["service_name"] == "web-frontend"


def test_dashboard_incident_and_audit_endpoints():
    response = client.post(
        "/incidents",
        json={
            "service_name": "web-frontend",
            "severity": "low",
            "description": "Dashboard recovery integration test",
        },
    )
    assert response.status_code == 200
    record = response.json()
    assert record["pipeline_status"] == "success"
    assert record["recovery_action"]["action_type"] == "restart_service"
    assert record["policy_decision"]["verdict"] == "approve"
    assert record["recovery_result"]["success"] is True
    assert record["verification_result"]["outcome"] == "pass"

    history = client.get("/audit")
    assert history.status_code == 200
    assert any(item["incident"]["id"] == record["incident"]["id"] for item in history.json())

    audit = client.get(f"/incidents/{record['incident']['id']}/audit")
    assert audit.status_code == 200
    assert any(item["event_type"] == "action_proposed" for item in audit.json())


def test_audit_endpoint_reconstructs_legacy_event_only_history(monkeypatch):
    response = client.post(
        "/incidents",
        json={
            "service_name": "web-frontend",
            "severity": "low",
            "description": "Legacy audit history test",
        },
    )
    assert response.status_code == 200
    response_record = response.json()
    events = [
        AuditEvent.model_validate(event)
        for event in response_record["audit_events"]
    ]
    monkeypatch.setattr(audit_logger, "read_all", lambda: events)

    history = client.get("/audit")
    assert history.status_code == 200
    records = history.json()
    assert len(records) == 1
    assert records[0]["incident"]["id"] == response_record["incident"]["id"]
    assert records[0]["pipeline_status"] == response_record["pipeline_status"]


def test_openapi_operation_ids_are_unique():
    client = TestClient(app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    operation_ids = []
    for path, methods in schema.get("paths", {}).items():
        for method, operation in methods.items():
            if isinstance(operation, dict) and "operationId" in operation:
                operation_ids.append(operation["operationId"])
    assert len(operation_ids) == len(set(operation_ids)), f"Duplicate operation IDs found: {operation_ids}"
    assert len(operation_ids) > 0


def test_root_and_api_prefix_route_parity():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/api/health").status_code == 200
    assert client.get("/services").status_code == 200
    assert client.get("/api/services").status_code == 200
    assert client.get("/audit").status_code == 200
    assert client.get("/api/audit").status_code == 200


# ==============================================================================
# Reset Security & Audit Integrity Endpoint Tests
# ==============================================================================

def test_reset_unauthorized_when_token_configured(monkeypatch):
    """Verify that unauthorized requests cannot reset the system when an admin token is set."""
    admin_token = "secure-hackathon-admin-key-999"
    monkeypatch.setenv("ADMIN_RESET_TOKEN", admin_token)

    # Put a service into DEGRADED state
    infra.register_service("web-frontend", status=ServiceStatus.DEGRADED, error_rate=0.8)
    assert infra.get_service("web-frontend").status == ServiceStatus.DEGRADED

    # 1. Unauthenticated request without headers
    res_no_auth = client.post("/reset")
    assert res_no_auth.status_code == 401
    assert "Unauthorized" in res_no_auth.json()["detail"]
    assert infra.get_service("web-frontend").status == ServiceStatus.DEGRADED

    # 2. Invalid X-Admin-Token header
    res_wrong_token = client.post("/reset", headers={"X-Admin-Token": "invalid_wrong_token"})
    assert res_wrong_token.status_code == 401
    assert "Unauthorized" in res_wrong_token.json()["detail"]
    assert infra.get_service("web-frontend").status == ServiceStatus.DEGRADED

    # 3. Valid X-Admin-Token header
    res_valid_header = client.post("/reset", headers={"X-Admin-Token": admin_token})
    assert res_valid_header.status_code == 200
    assert res_valid_header.json()["status"] == "reset"
    assert infra.get_service("web-frontend").status == ServiceStatus.HEALTHY

    # 4. Valid Authorization Bearer header
    infra.register_service("web-frontend", status=ServiceStatus.DEGRADED)
    res_bearer = client.post("/reset", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_bearer.status_code == 200
    assert infra.get_service("web-frontend").status == ServiceStatus.HEALTHY


def test_reset_preserves_audit_log_by_default():
    """Verify that POST /reset preserves audit history by default and only clears it when explicitly requested."""
    # Record an event into audit logger
    audit_logger.record_event(
        incident_id="inc-preservation-check",
        component_name="Orchestrator",
        event_type="incident_received",
        success=True,
        explanation="Audit event must be preserved across service resets.",
    )
    events_before = audit_logger.get_events_for_incident("inc-preservation-check")
    assert len(events_before) == 1

    # Call reset without clear_audit flag
    res = client.post("/reset")
    assert res.status_code == 200
    assert res.json()["audit_cleared"] is False

    # Verify audit history is preserved
    events_after = audit_logger.get_events_for_incident("inc-preservation-check")
    assert len(events_after) == 1

    # Call reset with explicit clear_audit=True in JSON body
    res_clear = client.post("/reset", json={"clear_audit": True})
    assert res_clear.status_code == 200
    assert res_clear.json()["audit_cleared"] is True

    # Verify audit history is now cleared
    assert len(audit_logger.get_events_for_incident("inc-preservation-check")) == 0


def test_audit_verify_endpoint_cryptographic_integrity():
    """Verify that GET /audit/verify and /api/audit/verify validate the audit hash chain."""
    res_root = client.get("/audit/verify")
    assert res_root.status_code == 200
    report_root = res_root.json()
    assert "is_valid" in report_root
    assert "verified_events" in report_root
    assert report_root["is_valid"] is True

    res_api = client.get("/api/audit/verify")
    assert res_api.status_code == 200
    assert res_api.json()["is_valid"] is True
