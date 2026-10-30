"""Simulated recovery executor modifying only in-memory infrastructure state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.infrastructure import InfrastructureSimulator
from app.models import (
    RecoveryAction,
    RecoveryActionType,
    RecoveryResult,
)


class SimulatedRecoveryExecutor:
    """Modifies only an in-memory simulated system state.

    Supports at least:
    - restarting a failed service
    - clearing a simulated queue
    - scaling a service within a configured limit
    """

    def __init__(self, min_scale_limit: int = 1, max_scale_limit: int = 10) -> None:
        self.min_scale_limit = min_scale_limit
        self.max_scale_limit = max_scale_limit

    def execute(
        self,
        action: RecoveryAction,
        infra: InfrastructureSimulator,
    ) -> RecoveryResult:
        """Execute the given recovery action against the simulated infrastructure."""
        started_at = datetime.now(timezone.utc)
        action_type = action.action_type

        try:
            # 1. Restarting a failed service
            if action_type in (RecoveryActionType.RESTART_SERVICE, RecoveryActionType.FAILOVER):
                infra.set_service_healthy(action.target_service)
                message = f"Service '{action.target_service}' successfully restarted."

            # 2. Clearing a simulated queue
            elif action_type == RecoveryActionType.CLEAR_QUEUE:
                infra.clear_queue(action.target_service)
                message = f"Queue for service '{action.target_service}' successfully cleared."

            # 3. Scaling a service within a configured limit
            elif action_type in (RecoveryActionType.SCALE_SERVICE, RecoveryActionType.SCALE_UP):
                current = infra.get_service(action.target_service)
                if current and (current.instances < self.min_scale_limit or current.instances > self.max_scale_limit):
                    return RecoveryResult(
                        action_id=action.id,
                        incident_id=action.incident_id,
                        action_type=action.action_type,
                        target_service=action.target_service,
                        success=False,
                        message=(
                            f"Scaling rejected: current instance count {current.instances} is out of bounds "
                            f"[{self.min_scale_limit}, {self.max_scale_limit}]."
                        ),
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                    )

                target_instances = action.parameters.get("target_instances")
                if target_instances is None:
                    target_instances = (current.instances + 1) if current else 2

                try:
                    target_instances = int(target_instances)
                except (ValueError, TypeError):
                    return RecoveryResult(
                        action_id=action.id,
                        incident_id=action.incident_id,
                        action_type=action.action_type,
                        target_service=action.target_service,
                        success=False,
                        message=f"Scaling failed: requested target_instances '{target_instances}' is not a valid integer.",
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                    )

                if target_instances > self.max_scale_limit:
                    return RecoveryResult(
                        action_id=action.id,
                        incident_id=action.incident_id,
                        action_type=action.action_type,
                        target_service=action.target_service,
                        success=False,
                        message=(
                            f"Scaling rejected: requested instances {target_instances} "
                            f"exceeds executor maximum limit of {self.max_scale_limit}."
                        ),
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                    )

                if target_instances < self.min_scale_limit:
                    return RecoveryResult(
                        action_id=action.id,
                        incident_id=action.incident_id,
                        action_type=action.action_type,
                        target_service=action.target_service,
                        success=False,
                        message=(
                            f"Scaling failed: target_instances {target_instances} must be at least "
                            f"{self.min_scale_limit}."
                        ),
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                    )

                infra.scale_service(action.target_service, target_instances)
                message = (
                    f"Service '{action.target_service}' scaled to {target_instances} instances "
                    f"(within limit {self.max_scale_limit})."
                )

            else:
                return RecoveryResult(
                    action_id=action.id,
                    incident_id=action.incident_id,
                    action_type=action.action_type,
                    target_service=action.target_service,
                    success=False,
                    message=f"Unsupported recovery action type: '{action_type}'.",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                )

            return RecoveryResult(
                action_id=action.id,
                incident_id=action.incident_id,
                action_type=action.action_type,
                target_service=action.target_service,
                success=True,
                message=message,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as exc:
            return RecoveryResult(
                action_id=action.id,
                incident_id=action.incident_id,
                action_type=action.action_type,
                target_service=action.target_service,
                success=False,
                message=f"Executor failed with exception: {exc}",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
