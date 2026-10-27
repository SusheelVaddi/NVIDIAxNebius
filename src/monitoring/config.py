"""
Monitoring configuration and deterministic detection thresholds.

All thresholds are centralized in the MonitoringConfig dataclass to prevent
magic numbers from being scattered across the codebase.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MonitoringConfig:
    """Configurable thresholds for deterministic incident detection.

    Attributes:
        latency_p99_warn_ms: Warning threshold for p99 latency in milliseconds (default: 500.0)
        latency_p99_crit_ms: Critical threshold for p99 latency in milliseconds (default: 1200.0)
        error_rate_warn_pct: Warning threshold for error rate percentage (default: 2.0%)
        error_rate_crit_pct: Critical threshold for error rate percentage (default: 8.0%)
        cpu_warn_pct: Warning threshold for CPU utilization percentage (default: 80.0%)
        cpu_crit_pct: Critical threshold for CPU utilization percentage (default: 90.0%)
        memory_warn_pct: Warning threshold for memory utilization percentage (default: 85.0%)
        memory_crit_pct: Critical threshold for memory utilization percentage (default: 95.0%)
        default_service: Default service name for simulated scenarios (default: 'payment-service')
    """
    # Latency thresholds (ms)
    latency_p99_warn_ms: float = 500.0
    latency_p99_crit_ms: float = 1200.0

    # Error rate thresholds (%)
    error_rate_warn_pct: float = 2.0
    error_rate_crit_pct: float = 8.0

    # CPU utilization thresholds (%)
    cpu_warn_pct: float = 80.0
    cpu_crit_pct: float = 90.0

    # Memory utilization thresholds (%)
    memory_warn_pct: float = 85.0
    memory_crit_pct: float = 95.0

    # Service identification
    default_service: str = "payment-service"
