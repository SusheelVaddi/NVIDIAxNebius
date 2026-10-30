"""Tests for end-to-end demo scenarios.

Verifies that the 5 demonstration scenarios work reliably in CI and test runs:
1. Primary Recovery (Payment Service)
2. Unsafe Action Rejection
3. Unknown Service Rejection
4. Executor Failure Handling
5. Independent Verification Failure
"""

from fastapi.testclient import TestClient
import pytest

from app.main import app
from demo import (
    run_scenario_1_primary_recovery,
    run_scenario_2_unsafe_action_rejected,
    run_scenario_3_unknown_service_rejected,
    run_scenario_4_executor_failure,
    run_scenario_5_verification_failure,
    run_all_demonstrations,
)


@pytest.fixture
def client():
    """Isolated test client with reset state."""
    c = TestClient(app)
    c.post("/reset")
    yield c
    c.post("/reset")


def test_demo_scenario_1_primary_recovery(client):
    """Scenario 1: Payment service is degraded, planner suggests restart, policy approves, service recovers."""
    result = run_scenario_1_primary_recovery(client)
    assert result["incident_id"] == "inc-payment-001"
    assert result["final_status"] == "success"
    assert result["policy_decision"]["verdict"] == "approve"
    assert result["recovery_result"]["success"] is True
    assert result["verification_result"]["outcome"] == "pass"
    assert len(result["audit_events"]) == 7


def test_demo_scenario_2_unsafe_action(client):
    """Scenario 2: Unsafe action is rejected by the deterministic policy gate."""
    result = run_scenario_2_unsafe_action_rejected(client)
    assert result["final_status"] == "recovery_denied"
    assert result["policy_decision"]["verdict"] == "deny"
    assert result["recovery_result"] is None
    assert result["verification_result"] is None


def test_demo_scenario_3_unknown_service(client):
    """Scenario 3: Unknown service rejected by policy gate."""
    result = run_scenario_3_unknown_service_rejected(client)
    assert result["final_status"] == "recovery_denied"
    assert result["policy_decision"]["verdict"] == "deny"
    assert "does not exist" in result["policy_decision"]["reason"].lower()


def test_demo_scenario_4_executor_failure(client):
    """Scenario 4: Scale exceeds maximum instances, executor returns failure."""
    result = run_scenario_4_executor_failure(client)
    assert result["final_status"] == "recovery_failed"
    assert result["policy_decision"]["verdict"] == "approve"
    assert result["recovery_result"]["success"] is False
    assert result["verification_result"] is None


def test_demo_scenario_5_verification_failure(client):
    """Scenario 5: Post-execution independent health probe fails."""
    result = run_scenario_5_verification_failure(client)
    assert result["final_status"] == "verification_failed"
    assert result["policy_decision"]["verdict"] == "approve"
    assert result["recovery_result"]["success"] is True
    assert result["verification_result"]["outcome"] == "fail"


def test_demo_all_demonstrations(client):
    """Verify entire suite runs sequentially without state pollution."""
    all_results = run_all_demonstrations(client)
    assert len(all_results) == 5
    assert all_results["scenario_1_payment_service_success"]["final_status"] == "success"
    assert all_results["scenario_2_unsafe_action_rejected"]["final_status"] == "recovery_denied"
    assert all_results["scenario_3_unknown_service_rejected"]["final_status"] == "recovery_denied"
    assert all_results["scenario_4_executor_failure"]["final_status"] == "recovery_failed"
    assert all_results["scenario_5_verification_failure"]["final_status"] == "verification_failed"
