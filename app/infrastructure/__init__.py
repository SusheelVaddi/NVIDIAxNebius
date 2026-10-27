"""In-memory simulated infrastructure layer.

Provides a fleet of fake services that can be healthy, degraded, or down.
Incidents are injected by mutating service state; recovery actions restore it.
Everything is deterministic and thread-safe for single-process demo / testing.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional

from app.models import (
    Incident,
    IncidentSeverity,
    SystemState,
    ServiceStatus,
)


# ---------------------------------------------------------------------------
# Default service catalogue (5 core services)
# ---------------------------------------------------------------------------

_DEFAULT_SERVICES: List[Dict] = [
    {
        "service_name": "web-frontend",
        "cpu_percent": 25.0,
        "memory_percent": 40.0,
        "error_rate": 0.01,
        "queue_size": 0,
        "instances": 2,
    },
    {
        "service_name": "api-gateway",
        "cpu_percent": 30.0,
        "memory_percent": 35.0,
        "error_rate": 0.02,
        "queue_size": 0,
        "instances": 2,
    },
    {
        "service_name": "auth-service",
        "cpu_percent": 15.0,
        "memory_percent": 20.0,
        "error_rate": 0.00,
        "queue_size": 0,
        "instances": 1,
    },
    {
        "service_name": "database",
        "cpu_percent": 45.0,
        "memory_percent": 60.0,
        "error_rate": 0.01,
        "queue_size": 0,
        "instances": 1,
    },
    {
        "service_name": "cache-layer",
        "cpu_percent": 10.0,
        "memory_percent": 15.0,
        "error_rate": 0.00,
        "queue_size": 0,
        "instances": 1,
    },
]


class InfrastructureSimulator:
    """Holds the simulated service fleet in memory.

    Thread-safety: a lock guards mutations so the FastAPI event loop
    and background tasks won't race.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._services: Dict[str, SystemState] = {}
        self._reset_to_defaults()

    # -- public queries -----------------------------------------------------

    def list_services(self) -> List[SystemState]:
        """Return a snapshot of every service."""
        with self._lock:
            return list(self._services.values())

    def get_service(self, name: str) -> Optional[SystemState]:
        """Return one service by name, or ``None``."""
        with self._lock:
            return self._services.get(name)

    # -- incident injection -------------------------------------------------

    def inject_incident(
        self,
        service_name: str,
        severity: IncidentSeverity,
        description: str = "",
    ) -> Incident:
        """Simulate an incident by degrading / downing a service."""
        with self._lock:
            svc = self._services.get(service_name)
            if svc is None:
                raise ValueError(f"Unknown service: {service_name}")

            # Determine new status based on severity
            if severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH):
                new_status = ServiceStatus.DOWN
                new_error_rate = 1.0
            else:
                new_status = ServiceStatus.DEGRADED
                new_error_rate = 0.5

            self._services[service_name] = svc.model_copy(
                update={"status": new_status, "error_rate": new_error_rate},
            )

        title = f"{severity.value.upper()} incident on {service_name}"
        if not description:
            description = f"Simulated {severity.value} incident on {service_name}"

        return Incident(
            service_name=service_name,
            severity=severity,
            title=title,
            description=description,
        )

    # -- mutations used by recovery actions ---------------------------------

    def set_service_healthy(self, name: str) -> None:
        """Mark a service as healthy with nominal metrics."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            self._services[name] = svc.model_copy(
                update={
                    "status": ServiceStatus.HEALTHY,
                    "error_rate": 0.01,
                    "cpu_percent": 20.0,
                    "memory_percent": 30.0,
                },
            )

    def restart_service(self, name: str) -> None:
        """Restart a failed service back to healthy state."""
        self.set_service_healthy(name)

    def clear_queue(self, name: str) -> None:
        """Clear simulated queue for the target service."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            self._services[name] = svc.model_copy(
                update={
                    "queue_size": 0,
                    "status": ServiceStatus.HEALTHY,
                    "error_rate": 0.01,
                    "request_latency_ms": 10.0,
                },
            )

    def scale_service(self, name: str, target_instances: int) -> None:
        """Scale service replicas to target_instances."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            if target_instances < 1:
                raise ValueError("Target instances must be >= 1")

            old_instances = max(1, svc.instances)
            scale_ratio = old_instances / target_instances
            new_cpu = max(5.0, min(100.0, svc.cpu_percent * scale_ratio))
            new_mem = max(5.0, min(100.0, svc.memory_percent * scale_ratio))

            self._services[name] = svc.model_copy(
                update={
                    "status": ServiceStatus.HEALTHY,
                    "instances": target_instances,
                    "cpu_percent": round(new_cpu, 2),
                    "memory_percent": round(new_mem, 2),
                    "error_rate": 0.01,
                },
            )

    def scale_up_service(self, name: str) -> None:
        """Simulate scaling up – halve CPU & memory utilisation and increment instances."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            self._services[name] = svc.model_copy(
                update={
                    "status": ServiceStatus.HEALTHY,
                    "instances": svc.instances + 1,
                    "cpu_percent": svc.cpu_percent / 2,
                    "memory_percent": svc.memory_percent / 2,
                    "error_rate": 0.01,
                },
            )

    def set_queue_size(self, name: str, size: int) -> None:
        """Artificially set queue size on a service for simulation."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            self._services[name] = svc.model_copy(
                update={
                    "queue_size": size,
                    "status": ServiceStatus.DEGRADED if size > 100 else svc.status,
                    "error_rate": 0.4 if size > 100 else svc.error_rate,
                },
            )

    def fail_service(self, name: str, status: ServiceStatus = ServiceStatus.DOWN, error_rate: float = 1.0) -> None:
        """Explicitly set service to a failed state."""
        with self._lock:
            svc = self._services.get(name)
            if svc is None:
                raise ValueError(f"Unknown service: {name}")
            self._services[name] = svc.model_copy(
                update={
                    "status": status,
                    "error_rate": error_rate,
                },
            )

    # -- admin --------------------------------------------------------------

    def reset(self) -> None:
        """Restore every service to a healthy default."""
        self._reset_to_defaults()

    def _reset_to_defaults(self) -> None:
        with self._lock:
            self._services = {
                d["service_name"]: SystemState(status=ServiceStatus.HEALTHY, **d)
                for d in _DEFAULT_SERVICES
            }


# ---------------------------------------------------------------------------
# Module-level singleton used by the rest of the app
# ---------------------------------------------------------------------------

infra = InfrastructureSimulator()
