"""Independent verification checker.

Inspects the state of the simulated infrastructure after a recovery action
is executed, rather than trusting the executor's return value.
"""

from __future__ import annotations

from typing import List, Optional

from app.infrastructure import InfrastructureSimulator
from app.models import (
    RecoveryAction,
    RecoveryActionType,
    ServiceStatus,
    VerificationOutcome,
    VerificationResult,
)


class IndependentVerifier:
    """Independently verifies service health post-recovery by querying infrastructure state."""

    def __init__(self, max_error_rate: float = 0.10) -> None:
        self.max_error_rate = max_error_rate

    def verify(
        self,
        service_name: str,
        infra: InfrastructureSimulator,
        action: Optional[RecoveryAction] = None,
        incident_id: str = "",
    ) -> VerificationResult:
        """Inspect actual system state after execution without relying on executor claims."""
        svc = infra.get_service(service_name)
        inc_id = incident_id or (action.incident_id if action else "")

        if svc is None:
            return VerificationResult(
                incident_id=inc_id,
                service_name=service_name,
                outcome=VerificationOutcome.FAIL,
                details=f"Service '{service_name}' not found in infrastructure after recovery.",
                checks_performed=["service_exists:FAIL"],
            )

        checks_performed: List[str] = ["service_exists:PASS"]
        failures: List[str] = []

        # Check 1: Status must be HEALTHY
        if svc.status == ServiceStatus.HEALTHY:
            checks_performed.append("status_healthy:PASS")
        else:
            checks_performed.append(f"status_healthy:FAIL({svc.status.value})")
            failures.append(f"status is '{svc.status.value}' (expected healthy)")

        # Check 2: Error rate within acceptable threshold
        if svc.error_rate <= self.max_error_rate:
            checks_performed.append(f"error_rate_acceptable:PASS({svc.error_rate:.2f})")
        else:
            checks_performed.append(f"error_rate_acceptable:FAIL({svc.error_rate:.2f})")
            failures.append(f"error rate {svc.error_rate:.2f} exceeds threshold {self.max_error_rate:.2f}")

        # Check 3: Action-specific verification
        if action:
            if action.action_type == RecoveryActionType.CLEAR_QUEUE:
                if svc.queue_size == 0:
                    checks_performed.append("queue_cleared:PASS")
                else:
                    checks_performed.append(f"queue_cleared:FAIL(size={svc.queue_size})")
                    failures.append(f"queue_size is {svc.queue_size} (expected 0)")

            elif action.action_type in (RecoveryActionType.SCALE_SERVICE, RecoveryActionType.SCALE_UP):
                target_instances = action.parameters.get("target_instances")
                if target_instances is not None:
                    if svc.instances == target_instances:
                        checks_performed.append(f"instances_scaled:PASS({svc.instances})")
                    else:
                        checks_performed.append(
                            f"instances_scaled:FAIL(actual={svc.instances}, expected={target_instances})"
                        )
                        failures.append(
                            f"instance count {svc.instances} does not match expected {target_instances}"
                        )

        if failures:
            return VerificationResult(
                incident_id=inc_id,
                service_name=service_name,
                outcome=VerificationOutcome.FAIL,
                details=f"Independent verification failed: {'; '.join(failures)}.",
                checks_performed=checks_performed,
            )

        return VerificationResult(
            incident_id=inc_id,
            service_name=service_name,
            outcome=VerificationOutcome.PASS,
            details=(
                f"Independent verification passed: service is {svc.status.value}, "
                f"error_rate={svc.error_rate:.2f}, cpu={svc.cpu_percent:.1f}%, "
                f"mem={svc.memory_percent:.1f}%, instances={svc.instances}, queue_size={svc.queue_size}."
            ),
            checks_performed=checks_performed,
        )
