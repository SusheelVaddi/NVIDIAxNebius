"""
Deterministic scenario generators for simulated infrastructure telemetry.

Uses a local random.Random(seed) instance to guarantee 100% reproducible
telemetry datasets for unit tests, demonstrations, and baseline calibration.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from src.schemas import MetricSnapshot, LogEntry
from src.monitoring.config import MonitoringConfig
from src.monitoring.telemetry import DeploymentEvent, TelemetryWindow


DEFAULT_CONFIG = MonitoringConfig()
DETERMINISTIC_BASE_TIME = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)


def generate_healthy_scenario(
    service: Optional[str] = None,
    seed: int = 42,
    base_time: Optional[datetime] = None,
) -> TelemetryWindow:
    """Generates a reproducible healthy baseline scenario.

    Metrics remain comfortably within normal operational boundaries:
    - p99 latency < 150 ms (threshold: 500 ms)
    - error rate < 0.3% (threshold: 2.0%)
    - CPU utilization < 50% (threshold: 80.0%)
    - Memory utilization < 55% (threshold: 85.0%)
    - Service status is HEALTHY
    - Logs contain only INFO and DEBUG messages
    """
    svc = service or DEFAULT_CONFIG.default_service
    ref_time = base_time or DETERMINISTIC_BASE_TIME
    rng = random.Random(seed)

    # Deterministic metrics within normal healthy limits
    p50_latency = round(25.0 + rng.uniform(0.0, 10.0), 2)
    p99_latency = round(80.0 + rng.uniform(0.0, 35.0), 2)
    error_rate = round(0.05 + rng.uniform(0.0, 0.15), 2)
    request_rate = round(100.0 + rng.uniform(0.0, 25.0), 1)
    cpu = round(35.0 + rng.uniform(0.0, 10.0), 1)
    memory = round(42.0 + rng.uniform(0.0, 8.0), 1)

    metrics = MetricSnapshot(
        latency_p50_ms=p50_latency,
        latency_p99_ms=p99_latency,
        error_rate_pct=error_rate,
        request_rate_rps=request_rate,
        cpu_utilization_pct=cpu,
        memory_utilization_pct=memory,
    )

    # Realistic clean baseline logs
    logs: List[LogEntry] = [
        LogEntry(
            timestamp=ref_time - timedelta(seconds=45),
            level="INFO",
            message="Health check passed for worker cluster 'payment-workers'",
            component="health-monitor",
            trace_id="tr-healthy-01",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(seconds=30),
            level="DEBUG",
            message="Database connection pool utilization stable at 12/50",
            component="database-pool",
            trace_id="tr-healthy-02",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(seconds=15),
            level="INFO",
            message="Processed 150 payment authorizations successfully with 0 failures",
            component="payment-engine",
            trace_id="tr-healthy-03",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(seconds=2),
            level="INFO",
            message="All endpoints responding within SLA (< 100ms)",
            component="api-gateway",
            trace_id="tr-healthy-04",
        ),
    ]

    return TelemetryWindow(
        service=svc,
        timestamp=ref_time,
        metrics=metrics,
        logs=logs,
        recent_deployment=None,
        service_status="HEALTHY",
    )


def generate_faulty_deployment_scenario(
    service: Optional[str] = None,
    seed: int = 42,
    base_time: Optional[datetime] = None,
) -> TelemetryWindow:
    """Generates a reproducible faulty deployment scenario.

    Simulates a release containing a connection pool leak causing:
    - Highly elevated p99 latency (> 2000 ms, exceeding critical 1200 ms)
    - High error rate (> 12%, exceeding critical 8.0%)
    - Elevated CPU and memory utilization
    - Service status DEGRADED
    - Recent deployment event for version v2.4.1
    - ERROR and FATAL logs detailing database connection pool exhaustion
    """
    svc = service or DEFAULT_CONFIG.default_service
    ref_time = base_time or DETERMINISTIC_BASE_TIME + timedelta(minutes=15)
    rng = random.Random(seed)

    # Deterministic metrics in critical/degraded territory
    p50_latency = round(620.0 + rng.uniform(0.0, 90.0), 2)
    p99_latency = round(2200.0 + rng.uniform(0.0, 350.0), 2)
    error_rate = round(13.0 + rng.uniform(0.0, 4.0), 2)
    request_rate = round(95.0 + rng.uniform(0.0, 15.0), 1)
    cpu = round(88.0 + rng.uniform(0.0, 3.5), 1)
    memory = round(91.0 + rng.uniform(0.0, 2.5), 1)

    metrics = MetricSnapshot(
        latency_p50_ms=p50_latency,
        latency_p99_ms=p99_latency,
        error_rate_pct=error_rate,
        request_rate_rps=request_rate,
        cpu_utilization_pct=cpu,
        memory_utilization_pct=memory,
    )

    # Recent faulty deployment event
    deployment = DeploymentEvent(
        deployment_id="dep-v2.4.1-20261027",
        service=svc,
        version="v2.4.1",
        deployed_at=ref_time - timedelta(minutes=5),
        status="COMPLETED",
    )

    # Logs showing database connection pool exhaustion triggered after deployment
    logs: List[LogEntry] = [
        LogEntry(
            timestamp=ref_time - timedelta(minutes=4, seconds=50),
            level="INFO",
            message="Deployment v2.4.1 rollout finalized. Traffic routed to new instances.",
            component="deploy-agent",
            trace_id="tr-dep-001",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(minutes=3, seconds=20),
            level="WARN",
            message="Connection pool 'payment-db-pool' active connections reached 95% capacity (48/50)",
            component="database-pool",
            trace_id="tr-warn-002",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(minutes=2, seconds=10),
            level="ERROR",
            message="Timeout waiting for connection from pool 'payment-db-pool' after 5000ms",
            component="database-pool",
            trace_id="tr-err-003",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(minutes=1, seconds=30),
            level="ERROR",
            message="psycopg2.OperationalError: server closed the connection unexpectedly",
            component="payment-repository",
            trace_id="tr-err-004",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(seconds=45),
            level="ERROR",
            message="HTTP 500 Internal Server Error: POST /api/v1/payments failed due to database timeout",
            component="api-gateway",
            trace_id="tr-err-005",
        ),
        LogEntry(
            timestamp=ref_time - timedelta(seconds=10),
            level="FATAL",
            message="Database connection pool exhausted. Active: 50, Pending: 184. Refusing new requests.",
            component="database-pool",
            trace_id="tr-fatal-006",
        ),
    ]

    return TelemetryWindow(
        service=svc,
        timestamp=ref_time,
        metrics=metrics,
        logs=logs,
        recent_deployment=deployment,
        service_status="DEGRADED",
    )
