"""Tests for the independent verification checker."""

import pytest

from app.infrastructure import InfrastructureSimulator
from app.models import IncidentSeverity, RecoveryAction, RecoveryActionType, ServiceStatus, VerificationOutcome
from app.verification import IndependentVerifier, verify


@pytest.fixture()
def sim():
    return InfrastructureSimulator()


def test_healthy_service_passes(sim: InfrastructureSimulator):
    result = verify("web-frontend", sim)
    assert result.outcome == VerificationOutcome.PASS


def test_down_service_fails(sim: InfrastructureSimulator):
    sim.inject_incident("web-frontend", IncidentSeverity.CRITICAL)
    result = verify("web-frontend", sim)
    assert result.outcome == VerificationOutcome.FAIL


def test_unknown_service_fails(sim: InfrastructureSimulator):
    result = verify("ghost-service", sim)
    assert result.outcome == VerificationOutcome.FAIL
    assert "not found" in result.details


def test_recovered_service_passes(sim: InfrastructureSimulator):
    sim.inject_incident("api-gateway", IncidentSeverity.HIGH)
    sim.set_service_healthy("api-gateway")
    result = verify("api-gateway", sim)
    assert result.outcome == VerificationOutcome.PASS

def test_restart_with_remaining_queue_backlog_fails(sim: InfrastructureSimulator):
    """A restart that leaves a significant queue backlog must fail independent verification."""
    sim.set_queue_size("auth-service", 500)
    sim.restart_service("auth-service")

    restart_action = RecoveryAction(
        incident_id="test-queue-inc-1",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="auth-service",
        safe_for_simulation=True,
    )
    result = verify("auth-service", sim, action=restart_action)

    assert result.outcome == VerificationOutcome.FAIL
    assert "queue backlog 500 exceeds threshold" in result.details
    assert any("queue_backlog_acceptable:FAIL" in c for c in result.checks_performed)


def test_clear_queue_action_clears_queue_and_passes(sim: InfrastructureSimulator):
    """A clear_queue action clears the backlog and passes independent verification."""
    sim.set_queue_size("auth-service", 500)
    sim.clear_queue("auth-service")

    clear_action = RecoveryAction(
        incident_id="test-queue-inc-2",
        action_type=RecoveryActionType.CLEAR_QUEUE,
        target_service="auth-service",
        safe_for_simulation=True,
    )
    result = verify("auth-service", sim, action=clear_action)

    assert result.outcome == VerificationOutcome.PASS
    assert sim.get_service("auth-service").queue_size == 0
    assert any("queue_cleared:PASS" in c for c in result.checks_performed)
    assert any("queue_backlog_acceptable:PASS" in c for c in result.checks_performed)


def test_normal_restart_recovery_with_no_backlog_passes(sim: InfrastructureSimulator):
    """Normal restart recovery with no queue backlog passes independent verification."""
    sim.inject_incident("web-frontend", IncidentSeverity.LOW)
    sim.restart_service("web-frontend")

    restart_action = RecoveryAction(
        incident_id="test-normal-inc-3",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="web-frontend",
        safe_for_simulation=True,
    )
    result = verify("web-frontend", sim, action=restart_action)

    assert result.outcome == VerificationOutcome.PASS
    assert any("queue_backlog_acceptable:PASS(0)" in c for c in result.checks_performed)


# ==============================================================================
# Production IndependentVerifier Component Tests
# ==============================================================================

def test_independent_verifier_target_mismatch_fails(sim: InfrastructureSimulator):
    verifier = IndependentVerifier()
    action = RecoveryAction(
        incident_id="inc-verif-target-01",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="auth-service",
        safe_for_simulation=True,
    )
    result = verifier.verify(service_name="web-frontend", infra=sim, action=action)
    assert result.outcome == VerificationOutcome.FAIL
    assert "target service mismatch" in result.details.lower()
    assert any("target_service_match:FAIL" in c for c in result.checks_performed)


def test_independent_verifier_high_error_rate_fails(sim: InfrastructureSimulator):
    verifier = IndependentVerifier(max_error_rate=0.05)
    current = sim.get_service("web-frontend")
    sim.update_service_state(current.model_copy(update={"error_rate": 0.15, "status": ServiceStatus.HEALTHY}))

    result = verifier.verify("web-frontend", sim)
    assert result.outcome == VerificationOutcome.FAIL
    assert "error rate" in result.details.lower()
    assert any("error_rate_acceptable:FAIL" in c for c in result.checks_performed)


def test_independent_verifier_scale_mismatch_fails(sim: InfrastructureSimulator):
    verifier = IndependentVerifier()
    sim.scale_service("web-frontend", 2)

    scale_action = RecoveryAction(
        incident_id="inc-verif-scale-01",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="web-frontend",
        parameters={"target_instances": 4},
        safe_for_simulation=True,
    )
    result = verifier.verify("web-frontend", sim, action=scale_action)
    assert result.outcome == VerificationOutcome.FAIL
    assert "instance count 2 does not match expected 4" in result.details.lower()
    assert any("instances_scaled:FAIL" in c for c in result.checks_performed)


def test_independent_verifier_scale_matches_passes(sim: InfrastructureSimulator):
    verifier = IndependentVerifier()
    sim.scale_service("web-frontend", 4)

    scale_action = RecoveryAction(
        incident_id="inc-verif-scale-02",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="web-frontend",
        parameters={"target_instances": 4},
        safe_for_simulation=True,
    )
    result = verifier.verify("web-frontend", sim, action=scale_action)
    assert result.outcome == VerificationOutcome.PASS
    assert any("instances_scaled:PASS(4)" in c for c in result.checks_performed)
    assert any("target_service_match:PASS(web-frontend)" in c for c in result.checks_performed)
