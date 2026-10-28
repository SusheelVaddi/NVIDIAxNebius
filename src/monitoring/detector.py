"""
Deterministic threshold-based incident detection engine.

Evaluates TelemetryWindow snapshots against configured thresholds without calling
any LLM. Emits validated IncidentPayload objects with structured evidence and explicit
severity classification. Never triggers or authorizes recovery actions.
"""

from typing import Optional, List

from src.schemas import IncidentPayload, IncidentSeverity, EvidenceItem
from src.monitoring.config import MonitoringConfig
from src.monitoring.telemetry import TelemetryWindow


def _normalize_service_status(status: Optional[str]) -> str:
    """Normalizes service status by trimming whitespace and converting to uppercase."""
    return (status or "").strip().upper()


def _collect_evidence(
    telemetry: TelemetryWindow,
    config: MonitoringConfig,
) -> List[EvidenceItem]:
    """Inspects telemetry metrics and status against thresholds to collect evidence items."""
    evidence: List[EvidenceItem] = []
    m = telemetry.metrics

    # 1. Error rate checks
    if m.error_rate_pct >= config.error_rate_crit_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_ERROR_RATE_CRIT",
                metric_name="error_rate_pct",
                threshold_value=config.error_rate_crit_pct,
                observed_value=m.error_rate_pct,
                explanation=(
                    f"Observed error rate {m.error_rate_pct:.2f}% exceeds critical "
                    f"threshold {config.error_rate_crit_pct:.2f}%"
                ),
            )
        )
    elif m.error_rate_pct >= config.error_rate_warn_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_ERROR_RATE_WARN",
                metric_name="error_rate_pct",
                threshold_value=config.error_rate_warn_pct,
                observed_value=m.error_rate_pct,
                explanation=(
                    f"Observed error rate {m.error_rate_pct:.2f}% exceeds warning "
                    f"threshold {config.error_rate_warn_pct:.2f}%"
                ),
            )
        )

    # 2. Latency p99 checks
    if m.latency_p99_ms >= config.latency_p99_crit_ms:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_LATENCY_P99_CRIT",
                metric_name="latency_p99_ms",
                threshold_value=config.latency_p99_crit_ms,
                observed_value=m.latency_p99_ms,
                explanation=(
                    f"Observed p99 latency {m.latency_p99_ms:.2f}ms exceeds critical "
                    f"threshold {config.latency_p99_crit_ms:.2f}ms"
                ),
            )
        )
    elif m.latency_p99_ms >= config.latency_p99_warn_ms:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_LATENCY_P99_WARN",
                metric_name="latency_p99_ms",
                threshold_value=config.latency_p99_warn_ms,
                observed_value=m.latency_p99_ms,
                explanation=(
                    f"Observed p99 latency {m.latency_p99_ms:.2f}ms exceeds warning "
                    f"threshold {config.latency_p99_warn_ms:.2f}ms"
                ),
            )
        )

    # 3. CPU utilization checks
    if m.cpu_utilization_pct >= config.cpu_crit_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_CPU_CRIT",
                metric_name="cpu_utilization_pct",
                threshold_value=config.cpu_crit_pct,
                observed_value=m.cpu_utilization_pct,
                explanation=(
                    f"Observed CPU utilization {m.cpu_utilization_pct:.2f}% exceeds critical "
                    f"threshold {config.cpu_crit_pct:.2f}%"
                ),
            )
        )
    elif m.cpu_utilization_pct >= config.cpu_warn_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_CPU_WARN",
                metric_name="cpu_utilization_pct",
                threshold_value=config.cpu_warn_pct,
                observed_value=m.cpu_utilization_pct,
                explanation=(
                    f"Observed CPU utilization {m.cpu_utilization_pct:.2f}% exceeds warning "
                    f"threshold {config.cpu_warn_pct:.2f}%"
                ),
            )
        )

    # 4. Memory utilization checks
    if m.memory_utilization_pct >= config.memory_crit_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_MEMORY_CRIT",
                metric_name="memory_utilization_pct",
                threshold_value=config.memory_crit_pct,
                observed_value=m.memory_utilization_pct,
                explanation=(
                    f"Observed memory utilization {m.memory_utilization_pct:.2f}% exceeds critical "
                    f"threshold {config.memory_crit_pct:.2f}%"
                ),
            )
        )
    elif m.memory_utilization_pct >= config.memory_warn_pct:
        evidence.append(
            EvidenceItem(
                rule_id="RULE_MEMORY_WARN",
                metric_name="memory_utilization_pct",
                threshold_value=config.memory_warn_pct,
                observed_value=m.memory_utilization_pct,
                explanation=(
                    f"Observed memory utilization {m.memory_utilization_pct:.2f}% exceeds warning "
                    f"threshold {config.memory_warn_pct:.2f}%"
                ),
            )
        )

    # 5. Service health status check
    status = _normalize_service_status(telemetry.service_status)
    if status == "UNHEALTHY":
        evidence.append(
            EvidenceItem(
                rule_id="RULE_SERVICE_UNHEALTHY",
                metric_name="service_status",
                threshold_value=0.0,
                observed_value=1.0,
                explanation="Service status is explicitly reported as UNHEALTHY",
            )
        )
    elif status == "DEGRADED":
        evidence.append(
            EvidenceItem(
                rule_id="RULE_SERVICE_DEGRADED",
                metric_name="service_status",
                threshold_value=0.0,
                observed_value=1.0,
                explanation="Service status is reported as DEGRADED",
            )
        )

    return evidence


def _classify_severity(
    telemetry: TelemetryWindow,
    config: MonitoringConfig,
) -> IncidentSeverity:
    """Classifies incident severity using explicit, documented precedence rules.

    Precedence order:
    1. CRITICAL:
       - Critical error-rate breach (>= error_rate_crit_pct), OR
       - Warning breaches for both error rate AND p99 latency simultaneously, OR
       - Explicitly UNHEALTHY service status.
    2. HIGH:
       - Critical p99 latency breach (>= latency_p99_crit_ms), OR
       - Warning error-rate breach (>= error_rate_warn_pct), OR
       - Critical CPU utilization breach (>= cpu_crit_pct), OR
       - Critical memory utilization breach (>= memory_crit_pct).
    3. MEDIUM:
       - Any remaining single warning breach (p99 latency, CPU, memory, or DEGRADED status).

    Note on Overlapping Rules:
    - If both CRITICAL and HIGH conditions exist simultaneously (e.g. critical error rate
      AND critical latency), CRITICAL takes precedence and wins.
    - If a critical latency breach (HIGH) occurs alongside a warning CPU breach (MEDIUM),
      HIGH takes precedence and wins.
    """
    m = telemetry.metrics

    is_error_crit = m.error_rate_pct >= config.error_rate_crit_pct
    is_error_warn = m.error_rate_pct >= config.error_rate_warn_pct
    is_latency_crit = m.latency_p99_ms >= config.latency_p99_crit_ms
    is_latency_warn = m.latency_p99_ms >= config.latency_p99_warn_ms
    is_cpu_crit = m.cpu_utilization_pct >= config.cpu_crit_pct
    is_memory_crit = m.memory_utilization_pct >= config.memory_crit_pct
    is_unhealthy = _normalize_service_status(telemetry.service_status) == "UNHEALTHY"

    # Precedence Step 1: CRITICAL
    if is_error_crit or (is_error_warn and is_latency_warn) or is_unhealthy:
        return IncidentSeverity.CRITICAL

    # Precedence Step 2: HIGH
    if is_latency_crit or is_error_warn or is_cpu_crit or is_memory_crit:
        return IncidentSeverity.HIGH

    # Precedence Step 3: MEDIUM (remaining warning breach)
    return IncidentSeverity.MEDIUM


def detect_incident(
    telemetry: TelemetryWindow,
    config: Optional[MonitoringConfig] = None,
) -> Optional[IncidentPayload]:
    """Evaluates telemetry snapshots deterministically against configured thresholds.

    Args:
        telemetry: TelemetryWindow containing metrics, logs, and service status.
        config: Optional custom MonitoringConfig. If None, default thresholds are used.

    Returns:
        IncidentPayload: If any detection rule is breached.
        None: If all metrics and states are within healthy thresholds.
    """
    cfg = config or MonitoringConfig()

    evidence = _collect_evidence(telemetry, cfg)
    if not evidence:
        return None

    # Determine severity using explicit precedence
    severity = _classify_severity(telemetry, cfg)

    # Generate a deterministic, unique incident ID with microsecond precision
    timestamp_slug = telemetry.timestamp.strftime("%Y%m%d%H%M%S%f")
    incident_id = f"INC-{telemetry.service}-{timestamp_slug}"

    # Build concise human-readable summary
    summary_parts = [e.explanation for e in evidence[:2]]
    summary = f"[{severity.value}] Incident on {telemetry.service}: {len(evidence)} breach(es) detected. " + "; ".join(summary_parts)

    return IncidentPayload(
        incident_id=incident_id,
        service=telemetry.service,
        timestamp=telemetry.timestamp,
        severity=severity,
        summary=summary,
        metrics=telemetry.metrics,
        logs=telemetry.logs,
        evidence=evidence,
        recent_deployment=telemetry.recent_deployment,
    )
