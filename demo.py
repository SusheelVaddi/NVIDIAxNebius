#!/usr/bin/env python3
"""End-to-End Demonstration of the Autonomous IT Reliability & Incident Recovery System.

NVIDIA x Nebius Hackathon

Demonstrates the complete lifecycle:
1. Primary Scenario:
   - Payment service is unhealthy.
   - Incident is created.
   - Planner recommends restarting the payment service.
   - Policy gate approves the action.
   - Simulated executor restarts the service.
   - Independent verifier confirms the service is healthy.
   - Audit log records every stage.
   - API returns a successful response.

2. Additional Failure & Guardrail Scenarios:
   - Unsafe action rejected by the policy gate.
   - Unknown service rejected.
   - Executor failure (e.g., scaling exceeds safety limits).
   - Verification failure (post-execution independent probe fails).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

from fastapi.testclient import TestClient

from app.api.routes import get_orchestrator
from app.audit import AuditLogger, audit_logger
from app.infrastructure import InfrastructureSimulator, infra
from app.main import app
from app.models import (
    Incident,
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
from app.recovery import (
    DeterministicMockPlanner,
    NebiusPlanner,
    SimulatedRecoveryExecutor,
)
from app.verification import IndependentVerifier

# Terminal styling helpers
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def reset_simulator(client: TestClient) -> None:
    """Reset demo state using the configured admin token, when required."""
    token = os.getenv("ADMIN_RESET_TOKEN", "")
    headers = {"X-Admin-Reset-Token": token} if token else {}
    response = client.post("/reset", headers=headers)
    response.raise_for_status()


def header(title: str) -> None:
    line = "=" * 80
    print(f"\n{BOLD}{CYAN}{line}{RESET}")
    print(f"{BOLD}{CYAN}  {title.upper()}{RESET}")
    print(f"{BOLD}{CYAN}{line}{RESET}\n")


def subheader(step: str, title: str) -> None:
    print(f"\n{BOLD}{YELLOW}[{step}] {title}{RESET}")


def pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def run_scenario_1_primary_recovery(client: TestClient) -> Dict[str, Any]:
    """Scenario 1: Primary End-to-End Payment Service Recovery Flow."""
    header("Scenario 1: End-to-End Autonomous Incident Recovery (Payment Service)")

    # 1. Reset state & register payment service in an unhealthy state
    subheader("Step 1", "Inject Incident: Payment Service is Unhealthy")
    reset_simulator(client)
    payment_initial_state = SystemState(
        service_name="payment-service",
        status=ServiceStatus.DEGRADED,
        cpu_percent=45.0,
        memory_percent=50.0,
        error_rate=0.65,
        queue_size=0,
        instances=2,
    )
    infra.register_service(payment_initial_state)

    print(f"{DIM}Current simulated system state for 'payment-service':{RESET}")
    print(pretty_json(payment_initial_state.model_dump()))

    # 2. Incident created
    subheader("Step 2", "Incident Created")
    incident = Incident(
        id="inc-payment-001",
        service_name="payment-service",
        severity=IncidentSeverity.MEDIUM,
        title="Payment Service Degradation",
        description="Payment transactions timing out with 65% error rate; restart recommended.",
    )
    print(f"{DIM}Incident Model:{RESET}")
    print(pretty_json(incident.model_dump()))

    # 3. Planner recommends restarting the service
    subheader("Step 3", "Recovery Planner Recommends Action")
    planner = DeterministicMockPlanner()
    proposed_action = planner.plan(incident, payment_initial_state)
    print(f"Planner recommended: {BOLD}{proposed_action.action_type.value}{RESET} on {BOLD}{proposed_action.target_service}{RESET}")
    print(pretty_json(proposed_action.model_dump()))

    # 4. Invoke API endpoint POST /incidents/recover
    subheader("Step 4", "Client Sends Recovery Request to API (POST /incidents/recover)")
    request_payload = {
        "incident_id": incident.id,
        "incident_type": "service_degraded",
        "affected_service": incident.service_name,
        "proposed_recovery_action": proposed_action.model_dump(mode="json"),
        "current_system_state": payment_initial_state.model_dump(mode="json"),
    }
    print(f"{DIM}API Request Payload:{RESET}")
    print(pretty_json(request_payload))

    response = client.post("/incidents/recover", json=request_payload)
    assert response.status_code == 200, f"API failed with {response.status_code}: {response.text}"
    response_data = response.json()

    # 5. Review Orchestrator decisions & verification
    subheader("Step 5", "Deterministic Policy Gate Evaluation")
    decision = response_data["policy_decision"]
    verdict = decision["verdict"]
    print(f"Policy Gate Verdict: {GREEN}{BOLD}{verdict.upper()}{RESET}")
    print(f"Rationale: {decision['reason']}")

    subheader("Step 6", "Simulated Recovery Executor Execution")
    rec_result = response_data["recovery_result"]
    print(f"Executor Success: {GREEN}{BOLD}{rec_result['success']}{RESET}")
    print(f"Message: {rec_result['message']}")

    subheader("Step 7", "Independent Verifier Post-Recovery Probe")
    verif_result = response_data["verification_result"]
    print(f"Verifier Outcome: {GREEN}{BOLD}{verif_result['outcome'].upper()}{RESET}")
    print(f"Details: {verif_result['details']}")
    print(f"Checks Performed: {verif_result['checks_performed']}")

    # 6. Retrieve complete audit trail from API
    subheader("Step 8", "Audit Log Records Every Stage (GET /incidents/inc-payment-001/audit)")
    audit_res = client.get(f"/incidents/{incident.id}/audit")
    assert audit_res.status_code == 200
    audit_events = audit_res.json()
    print(f"Total chronological audit events recorded: {BOLD}{len(audit_events)}{RESET}")
    for idx, event in enumerate(audit_events, 1):
        status_color = GREEN if event["success"] else RED
        print(f"  {idx}. [{event['timestamp'][:19]}] {BOLD}{event['component_name']}{RESET} -> {status_color}{event['event_type']}{RESET}: {event['explanation']}")

    # 7. Final API Response
    subheader("Step 9", "Final API Response")
    print(f"Final Pipeline Status: {GREEN}{BOLD}{response_data['final_status'].upper()}{RESET}")
    print(pretty_json(response_data))

    # Verify post-state
    svc_post = infra.get_service("payment-service")
    assert svc_post.status == ServiceStatus.HEALTHY
    assert svc_post.error_rate <= 0.05
    print(f"\n{GREEN}{BOLD}✓ Scenario 1 Completed Successfully!{RESET}")
    return response_data


def run_scenario_2_unsafe_action_rejected(client: TestClient) -> Dict[str, Any]:
    """Scenario 2: Unsafe Action Rejected by Policy Gate."""
    header("Scenario 2: Policy Gate Rejects Unsafe Action")

    reset_simulator(client)
    infra.register_service("payment-service", status=ServiceStatus.DEGRADED, cpu_percent=95.0, memory_percent=99.0, error_rate=0.4)

    # Proposed action is explicitly marked unsafe for simulation
    unsafe_action = RecoveryAction(
        incident_id="inc-unsafe-002",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="payment-service",
        safe_for_simulation=False,  # Unsafe!
        risk_level=4,
    )

    request_payload = {
        "incident_id": "inc-unsafe-002",
        "incident_type": "high_memory_exhaustion",
        "affected_service": "payment-service",
        "proposed_recovery_action": unsafe_action.model_dump(mode="json"),
        "current_system_state": {
            "service_name": "payment-service",
            "status": "degraded",
            "cpu_percent": 95.0,
            "memory_percent": 99.0,
            "error_rate": 0.4,
        },
    }

    print(f"{DIM}Submitting action with safe_for_simulation=False to /incidents/recover...{RESET}")
    res = client.post("/incidents/recover", json=request_payload)
    assert res.status_code == 200
    data = res.json()

    print(f"Policy Decision Verdict: {RED}{BOLD}{data['policy_decision']['verdict'].upper()}{RESET}")
    print(f"Rejection Reason: {data['policy_decision']['reason']}")
    print(f"Pipeline Status: {YELLOW}{BOLD}{data['final_status']}{RESET}")
    print(f"Executor Invoked: {BOLD}{data['recovery_result'] is not None}{RESET} (Expected: False)")
    print(f"Verifier Invoked: {BOLD}{data['verification_result'] is not None}{RESET} (Expected: False)")

    assert data["policy_decision"]["verdict"] == "deny"
    assert data["final_status"] == "recovery_denied"
    assert data["recovery_result"] is None
    assert data["verification_result"] is None
    print(f"\n{GREEN}{BOLD}✓ Scenario 2 Completed: Unsafe action successfully blocked by policy gate!{RESET}")
    return data


def run_scenario_3_unknown_service_rejected(client: TestClient) -> Dict[str, Any]:
    """Scenario 3: Unknown Service Rejected by Policy Gate."""
    header("Scenario 3: Policy Gate Rejects Unknown Service")

    reset_simulator(client)
    unknown_action = RecoveryAction(
        incident_id="inc-unknown-003",
        action_type=RecoveryActionType.RESTART_SERVICE,
        target_service="ghost-service",
        safe_for_simulation=True,
    )

    request_payload = {
        "incident_id": "inc-unknown-003",
        "incident_type": "unresponsive_worker",
        "affected_service": "ghost-service",
        "proposed_recovery_action": unknown_action.model_dump(mode="json"),
        "current_system_state": {
            "service_name": "ghost-service",
            "status": "down",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "error_rate": 1.0,
        },
    }

    print(f"{DIM}Submitting action targeting unknown service 'ghost-service'...{RESET}")
    res = client.post("/incidents/recover", json=request_payload)
    assert res.status_code == 200
    data = res.json()

    print(f"Policy Decision Verdict: {RED}{BOLD}{data['policy_decision']['verdict'].upper()}{RESET}")
    print(f"Rejection Reason: {data['policy_decision']['reason']}")
    print(f"Pipeline Status: {YELLOW}{BOLD}{data['final_status']}{RESET}")

    assert data["policy_decision"]["verdict"] == "deny"
    assert data["final_status"] == "recovery_denied"
    assert "does not exist" in data["policy_decision"]["reason"].lower()
    print(f"\n{GREEN}{BOLD}✓ Scenario 3 Completed: Unknown service safely rejected!{RESET}")
    return data


def run_scenario_4_executor_failure(client: TestClient) -> Dict[str, Any]:
    """Scenario 4: Executor Failure (Scale exceeds maximum limit)."""
    header("Scenario 4: Simulated Executor Failure")

    reset_simulator(client)
    infra.register_service("payment-service", status=ServiceStatus.DEGRADED, cpu_percent=85.0, memory_percent=70.0, error_rate=0.2, instances=2)

    # Approved by policy gate (scale_service with target_instances), but exceeds executor max scale limit (10)
    excessive_scale_action = RecoveryAction(
        incident_id="inc-scale-fail-004",
        action_type=RecoveryActionType.SCALE_SERVICE,
        target_service="payment-service",
        parameters={"target_instances": 50},  # Exceeds max limit 10
        safe_for_simulation=True,
        risk_level=2,
    )

    request_payload = {
        "incident_id": "inc-scale-fail-004",
        "incident_type": "traffic_surge",
        "affected_service": "payment-service",
        "proposed_recovery_action": excessive_scale_action.model_dump(mode="json"),
        "current_system_state": {
            "service_name": "payment-service",
            "status": "degraded",
            "cpu_percent": 85.0,
            "memory_percent": 70.0,
            "error_rate": 0.2,
            "instances": 2,
        },
    }

    print(f"{DIM}Submitting action scaling payment-service to 50 instances (max limit 10)...{RESET}")
    res = client.post("/incidents/recover", json=request_payload)
    assert res.status_code == 200
    data = res.json()

    print(f"Policy Gate Verdict: {GREEN}{BOLD}{data['policy_decision']['verdict'].upper()}{RESET} (Approved parameter presence)")
    print(f"Executor Success: {RED}{BOLD}{data['recovery_result']['success']}{RESET}")
    print(f"Executor Failure Message: {data['recovery_result']['message']}")
    print(f"Pipeline Status: {RED}{BOLD}{data['final_status'].upper()}{RESET}")
    print(f"Independent Verifier Skipped: {BOLD}{data['verification_result'] is None}{RESET} (Expected: True)")

    assert data["policy_decision"]["verdict"] == "approve"
    assert data["recovery_result"]["success"] is False
    assert data["final_status"] == "recovery_failed"
    assert data["verification_result"] is None
    print(f"\n{GREEN}{BOLD}✓ Scenario 4 Completed: Executor failure properly intercepted!{RESET}")
    return data


def run_scenario_5_verification_failure(client: TestClient) -> Dict[str, Any]:
    """Scenario 5: Independent Verification Failure."""
    header("Scenario 5: Post-Recovery Independent Verification Failure")

    reset_simulator(client)
    infra.register_service("payment-service", status=ServiceStatus.DEGRADED, cpu_percent=60.0, memory_percent=55.0, error_rate=0.4)

    # Custom verifier simulating post-recovery latent failure (health check probe returns 500)
    class LatentFailureVerifier(IndependentVerifier):
        def verify(self, service_name, infra, action=None, incident_id=""):
            return VerificationResult(
                incident_id=incident_id,
                service_name=service_name,
                outcome=VerificationOutcome.FAIL,
                details="Independent synthetic health probe failed: service returned HTTP 500.",
                checks_performed=["service_exists:PASS", "status_healthy:FAIL", "synthetic_probe:FAIL"],
            )

    test_orchestrator = Orchestrator(
        infra=infra,
        policy_gate=DeterministicPolicyGate(),
        executor=SimulatedRecoveryExecutor(),
        verifier=LatentFailureVerifier(),
        audit_logger=audit_logger,
    )

    # Dependency injection override for FastAPI route
    app.dependency_overrides[get_orchestrator] = lambda: test_orchestrator

    try:
        valid_action = RecoveryAction(
            incident_id="inc-verif-fail-005",
            action_type=RecoveryActionType.RESTART_SERVICE,
            target_service="payment-service",
            safe_for_simulation=True,
        )

        request_payload = {
            "incident_id": "inc-verif-fail-005",
            "incident_type": "service_degraded",
            "affected_service": "payment-service",
            "proposed_recovery_action": valid_action.model_dump(mode="json"),
            "current_system_state": {
                "service_name": "payment-service",
                "status": "degraded",
                "cpu_percent": 60.0,
                "memory_percent": 55.0,
                "error_rate": 0.4,
            },
        }

        print(f"{DIM}Submitting restart action with independent probe failure configured...{RESET}")
        res = client.post("/incidents/recover", json=request_payload)
        assert res.status_code == 200
        data = res.json()

        print(f"Policy Gate Verdict: {GREEN}{BOLD}{data['policy_decision']['verdict'].upper()}{RESET}")
        print(f"Executor Claimed Success: {GREEN}{BOLD}{data['recovery_result']['success']}{RESET}")
        print(f"Independent Verifier Outcome: {RED}{BOLD}{data['verification_result']['outcome'].upper()}{RESET}")
        print(f"Verifier Details: {data['verification_result']['details']}")
        print(f"Verifier Checks: {data['verification_result']['checks_performed']}")
        print(f"Pipeline Status: {RED}{BOLD}{data['final_status'].upper()}{RESET}")

        assert data["policy_decision"]["verdict"] == "approve"
        assert data["recovery_result"]["success"] is True
        assert data["verification_result"]["outcome"] == "fail"
        assert data["final_status"] == "verification_failed"
        print(f"\n{GREEN}{BOLD}✓ Scenario 5 Completed: Verification failure detected by independent verifier!{RESET}")
        return data

    finally:
        app.dependency_overrides.clear()


def run_all_demonstrations(client: Optional[TestClient] = None) -> Dict[str, Any]:
    """Execute all 5 scenarios and print comprehensive summary."""
    if client is None:
        client = TestClient(app)

    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}   AUTONOMOUS IT RELIABILITY & INCIDENT RECOVERY SYSTEM (NVIDIA x NEBIUS)     {RESET}")
    print(f"{BOLD}{CYAN}                      COMPLETE END-TO-END DEMO SUITE                           {RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")

    results = {
        "scenario_1_payment_service_success": run_scenario_1_primary_recovery(client),
        "scenario_2_unsafe_action_rejected": run_scenario_2_unsafe_action_rejected(client),
        "scenario_3_unknown_service_rejected": run_scenario_3_unknown_service_rejected(client),
        "scenario_4_executor_failure": run_scenario_4_executor_failure(client),
        "scenario_5_verification_failure": run_scenario_5_verification_failure(client),
    }

    header("Summary of All Demonstrations")
    print(f"  1. Primary Recovery (Payment Service) : {GREEN}{BOLD}PASS (Status: success){RESET}")
    print(f"  2. Unsafe Action Rejection             : {GREEN}{BOLD}PASS (Status: recovery_denied){RESET}")
    print(f"  3. Unknown Service Rejection           : {GREEN}{BOLD}PASS (Status: recovery_denied){RESET}")
    print(f"  4. Executor Failure Handling           : {GREEN}{BOLD}PASS (Status: recovery_failed){RESET}")
    print(f"  5. Independent Verification Failure    : {GREEN}{BOLD}PASS (Status: verification_failed){RESET}")
    print(f"\n{GREEN}{BOLD}All 5 demonstration scenarios executed successfully with full audit trail!{RESET}\n")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous Incident Recovery System Demonstration")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "all"], default="all",
                        help="Which scenario to run (1-5 or all, default: all)")
    args = parser.parse_args()

    client = TestClient(app)

    if args.scenario == "1":
        run_scenario_1_primary_recovery(client)
    elif args.scenario == "2":
        run_scenario_2_unsafe_action_rejected(client)
    elif args.scenario == "3":
        run_scenario_3_unknown_service_rejected(client)
    elif args.scenario == "4":
        run_scenario_4_executor_failure(client)
    elif args.scenario == "5":
        run_scenario_5_verification_failure(client)
    else:
        run_all_demonstrations(client)


if __name__ == "__main__":
    main()
