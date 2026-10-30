"""Unit tests for Member 2 monitoring and detection using Python's unittest framework."""

import sys
from pathlib import Path
import unittest
from datetime import datetime, timezone

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import pytest
except ImportError:
    pytest = None

from src.schemas import IncidentSeverity, MetricSnapshot, DeploymentEvent
from src.monitoring.config import MonitoringConfig
from src.monitoring.telemetry import TelemetryWindow
from src.monitoring.scenarios import (
    generate_healthy_scenario,
    generate_faulty_deployment_scenario,
)
from src.monitoring.detector import detect_incident


def test_healthy_baseline_produces_no_incident():
    """Validates that a healthy baseline scenario generates zero incidents."""
    telemetry = generate_healthy_scenario(seed=42)
    incident = detect_incident(telemetry)
    assert incident is None, "Healthy baseline must produce None (no incident)"


def test_faulty_deployment_produces_incident():
    """Validates that the faulty deployment scenario deterministically triggers an incident."""
    telemetry = generate_faulty_deployment_scenario(seed=42)
    incident = detect_incident(telemetry)

    assert incident is not None, "Faulty scenario must trigger an incident"
    assert incident.service == "payment-service"
    assert incident.severity == IncidentSeverity.CRITICAL
    assert len(incident.evidence) >= 2, "Faulty scenario should contain multiple breach evidences"
    assert any(e.rule_id == "RULE_ERROR_RATE_CRIT" for e in incident.evidence)
    assert any(e.rule_id == "RULE_LATENCY_P99_CRIT" for e in incident.evidence)
    assert len(incident.logs) > 0, "Incident must contain relevant contextual logs"


def test_high_latency_warning_yields_medium():
    """A single p99 latency warning breach (500ms <= latency < 1200ms) with normal errors yields MEDIUM."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=40.0,
            latency_p99_ms=650.0,  # Exceeds 500ms warning, below 1200ms critical
            error_rate_pct=0.1,    # Normal
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_LATENCY_P99_WARN" for e in incident.evidence)


def test_high_latency_critical_yields_high():
    """A critical p99 latency breach (>= 1200ms) with normal errors yields HIGH."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=120.0,
            latency_p99_ms=1500.0,  # Exceeds 1200ms critical
            error_rate_pct=0.2,     # Normal
            request_rate_rps=100.0,
            cpu_utilization_pct=45.0,
            memory_utilization_pct=50.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert any(e.rule_id == "RULE_LATENCY_P99_CRIT" for e in incident.evidence)


def test_high_error_rate_warning_yields_high():
    """A warning error rate breach (2.0% <= error < 8.0%) with normal latency yields HIGH."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,   # Normal
            error_rate_pct=3.5,    # Exceeds 2.0% warning, below 8.0% critical
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert any(e.rule_id == "RULE_ERROR_RATE_WARN" for e in incident.evidence)


def test_high_error_rate_critical_yields_critical():
    """A critical error rate breach (>= 8.0%) yields CRITICAL."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=35.0,
            latency_p99_ms=95.0,   # Normal
            error_rate_pct=11.5,   # Exceeds 8.0% critical
            request_rate_rps=100.0,
            cpu_utilization_pct=42.0,
            memory_utilization_pct=46.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.CRITICAL
    assert any(e.rule_id == "RULE_ERROR_RATE_CRIT" for e in incident.evidence)


def test_dual_warning_latency_and_error_rate_yields_critical():
    """Simultaneous warning breaches for both error rate AND latency trigger CRITICAL."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=50.0,
            latency_p99_ms=550.0,  # Warning (> 500ms)
            error_rate_pct=2.5,    # Warning (> 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=45.0,
            memory_utilization_pct=50.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.CRITICAL, (
        "Dual warning in error rate and latency must evaluate to CRITICAL"
    )


def test_unhealthy_service_status_yields_critical():
    """An explicit UNHEALTHY status triggers CRITICAL even with normal metrics."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=80.0,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=30.0,
            memory_utilization_pct=35.0,
        ),
        logs=[],
        service_status="UNHEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.CRITICAL
    assert any(e.rule_id == "RULE_SERVICE_UNHEALTHY" for e in incident.evidence)


def test_severity_precedence_critical_over_high():
    """When both CRITICAL and HIGH conditions exist, CRITICAL wins."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=500.0,
            latency_p99_ms=2000.0,  # Critical latency (normally HIGH)
            error_rate_pct=15.0,    # Critical error rate (CRITICAL)
            request_rate_rps=100.0,
            cpu_utilization_pct=92.0, # Critical CPU
            memory_utilization_pct=96.0, # Critical Memory
        ),
        logs=[],
        service_status="DEGRADED",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.CRITICAL, "CRITICAL must take precedence over HIGH"


def test_incident_payload_contains_required_fields():
    """Validates that the emitted incident matches all agreed contract fields and types."""
    telemetry = generate_faulty_deployment_scenario(seed=42)
    incident = detect_incident(telemetry)

    assert incident is not None
    # Validate top-level required fields
    assert isinstance(incident.incident_id, str) and len(incident.incident_id) > 0
    assert incident.service == "payment-service"
    assert isinstance(incident.timestamp, datetime)
    assert incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH, IncidentSeverity.MEDIUM]
    assert isinstance(incident.summary, str) and len(incident.summary) > 0

    # Validate nested metrics
    assert incident.metrics.latency_p99_ms > 0
    assert incident.metrics.error_rate_pct > 0

    # Validate nested logs
    assert len(incident.logs) > 0
    for log in incident.logs:
        assert isinstance(log.timestamp, datetime)
        assert log.level in ["INFO", "WARN", "ERROR", "FATAL"]
        assert isinstance(log.message, str)

    # Validate nested evidence
    assert len(incident.evidence) > 0
    for ev in incident.evidence:
        assert ev.rule_id.startswith("RULE_")
        assert len(ev.metric_name) > 0
        assert isinstance(ev.threshold_value, float)
        assert isinstance(ev.observed_value, float)
        assert len(ev.explanation) > 0

    # Validate nested deployment event
    assert incident.recent_deployment is not None
    assert isinstance(incident.recent_deployment, DeploymentEvent)
    assert incident.recent_deployment.deployment_id == "dep-v2.4.1-20261027"
    assert incident.recent_deployment.version == "v2.4.1"


def test_repeated_scenarios_are_reproducible():
    """Validates that calling a scenario with the same seed produces identical results."""
    run1 = generate_faulty_deployment_scenario(seed=999)
    run2 = generate_faulty_deployment_scenario(seed=999)

    assert run1.metrics.latency_p99_ms == run2.metrics.latency_p99_ms
    assert run1.metrics.error_rate_pct == run2.metrics.error_rate_pct
    assert run1.metrics.cpu_utilization_pct == run2.metrics.cpu_utilization_pct
    assert len(run1.logs) == len(run2.logs)
    for log1, log2 in zip(run1.logs, run2.logs):
        assert log1.message == log2.message
        assert log1.level == log2.level


def test_incident_retains_deployment_event_metadata():
    """Validates that an incident generated from faulty deployment retains all deployment metadata."""
    telemetry = generate_faulty_deployment_scenario(seed=42)
    assert telemetry.recent_deployment is not None

    incident = detect_incident(telemetry)
    assert incident is not None
    assert incident.recent_deployment is not None
    assert incident.recent_deployment.deployment_id == "dep-v2.4.1-20261027"
    assert incident.recent_deployment.version == "v2.4.1"
    assert incident.recent_deployment.service == "payment-service"
    assert isinstance(incident.recent_deployment.deployed_at, datetime)
    assert incident.recent_deployment.status == "COMPLETED"


def test_healthy_telemetry_without_deployment_produces_no_incident():
    """Healthy telemetry without a deployment returns None when no detection rules are breached."""
    telemetry = generate_healthy_scenario(seed=42)
    assert telemetry.recent_deployment is None

    incident = detect_incident(telemetry)
    assert incident is None


def test_incident_without_deployment_event():
    """An incident triggered without a recent deployment maintains recent_deployment as None."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=40.0,
            latency_p99_ms=1500.0,  # Critical latency breach
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        recent_deployment=None,
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.recent_deployment is None


def test_deployment_event_importable_from_shared_schemas():
    """Confirms DeploymentEvent is importable from src.schemas without circular dependencies."""
    from src.schemas import DeploymentEvent as SchemasDeploymentEvent
    from src.monitoring.telemetry import DeploymentEvent as TelemetryDeploymentEvent
    from src.monitoring import DeploymentEvent as PkgDeploymentEvent

    assert SchemasDeploymentEvent is TelemetryDeploymentEvent
    assert SchemasDeploymentEvent is PkgDeploymentEvent

    dep = SchemasDeploymentEvent(
        deployment_id="dep-test-01",
        service="order-service",
        version="v1.0.0",
        deployed_at=datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc),
        status="COMPLETED",
    )
    assert dep.version == "v1.0.0"
    assert dep.deployment_id == "dep-test-01"


def test_distinct_microsecond_timestamps_produce_distinct_incident_ids():
    """Two incidents in the same second with different microseconds produce distinct IDs."""
    config = MonitoringConfig()
    base_second = datetime(2026, 10, 27, 10, 15, 0, tzinfo=timezone.utc)
    t1_time = base_second.replace(microsecond=100000)
    t2_time = base_second.replace(microsecond=200000)

    # Telemetry windows with identical metrics (causing breach) but different microseconds
    metrics = MetricSnapshot(
        latency_p50_ms=40.0,
        latency_p99_ms=1500.0,  # Critical breach
        error_rate_pct=0.1,
        request_rate_rps=100.0,
        cpu_utilization_pct=40.0,
        memory_utilization_pct=45.0,
    )
    window1 = TelemetryWindow(
        service="payment-service",
        timestamp=t1_time,
        metrics=metrics,
        logs=[],
        service_status="HEALTHY",
    )
    window2 = TelemetryWindow(
        service="payment-service",
        timestamp=t2_time,
        metrics=metrics,
        logs=[],
        service_status="HEALTHY",
    )

    inc1 = detect_incident(window1, config)
    inc2 = detect_incident(window2, config)

    assert inc1 is not None
    assert inc2 is not None
    assert inc1.incident_id != inc2.incident_id, (
        f"Incident IDs must differ for distinct microseconds: {inc1.incident_id} vs {inc2.incident_id}"
    )
    assert inc1.incident_id.endswith("100000")
    assert inc2.incident_id.endswith("200000")


def test_repeated_detection_produces_identical_incident_id():
    """Repeated detection calls on identical telemetry snapshots produce the exact same incident ID."""
    telemetry = generate_faulty_deployment_scenario(seed=42)
    inc1 = detect_incident(telemetry)
    inc2 = detect_incident(telemetry)

    assert inc1 is not None
    assert inc2 is not None
    assert inc1.incident_id == inc2.incident_id
    assert inc1.incident_id.startswith(f"INC-{telemetry.service}-")


def test_zero_microsecond_timestamp_generates_valid_incident_id():
    """Timestamps with zero microseconds generate a valid, correctly formatted incident ID."""
    ts_zero_micro = datetime(2026, 10, 27, 12, 30, 45, microsecond=0, tzinfo=timezone.utc)
    config = MonitoringConfig()
    window = TelemetryWindow(
        service="payment-service",
        timestamp=ts_zero_micro,
        metrics=MetricSnapshot(
            latency_p50_ms=40.0,
            latency_p99_ms=1500.0,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(window, config)
    assert incident is not None
    expected_slug = "20261027123045000000"
    expected_id = f"INC-payment-service-{expected_slug}"
    assert incident.incident_id == expected_id


def test_unhealthy_service_status_case_and_whitespace_variants():
    """Confirms UNHEALTHY status triggers CRITICAL across lowercase and whitespace-padded variants."""
    config = MonitoringConfig()
    normal_metrics = MetricSnapshot(
        latency_p50_ms=30.0,
        latency_p99_ms=80.0,
        error_rate_pct=0.1,
        request_rate_rps=100.0,
        cpu_utilization_pct=30.0,
        memory_utilization_pct=35.0,
    )
    unhealthy_variants = ["unhealthy", " UNHEALTHY ", "\tUNHEALTHY\n", "  UnHeAlThY  "]

    for variant in unhealthy_variants:
        telemetry = TelemetryWindow(
            service="payment-service",
            timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
            metrics=normal_metrics,
            logs=[],
            service_status=variant,
        )
        incident = detect_incident(telemetry, config)
        assert incident is not None, f"Expected incident for variant: {repr(variant)}"
        assert incident.severity == IncidentSeverity.CRITICAL, (
            f"Expected CRITICAL severity for variant {repr(variant)}, got {incident.severity}"
        )
        assert any(e.rule_id == "RULE_SERVICE_UNHEALTHY" for e in incident.evidence)


def test_degraded_service_status_case_and_whitespace_variants():
    """Confirms DEGRADED status triggers MEDIUM across lowercase and whitespace-padded variants."""
    config = MonitoringConfig()
    normal_metrics = MetricSnapshot(
        latency_p50_ms=30.0,
        latency_p99_ms=80.0,
        error_rate_pct=0.1,
        request_rate_rps=100.0,
        cpu_utilization_pct=30.0,
        memory_utilization_pct=35.0,
    )
    degraded_variants = ["DEGRADED", "degraded", " DEGRADED ", "  dEgRaDeD\t"]

    for variant in degraded_variants:
        telemetry = TelemetryWindow(
            service="payment-service",
            timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
            metrics=normal_metrics,
            logs=[],
            service_status=variant,
        )
        incident = detect_incident(telemetry, config)
        assert incident is not None, f"Expected incident for variant: {repr(variant)}"
        assert incident.severity == IncidentSeverity.MEDIUM, (
            f"Expected MEDIUM severity for variant {repr(variant)}, got {incident.severity}"
        )
        assert any(e.rule_id == "RULE_SERVICE_DEGRADED" for e in incident.evidence)


def test_healthy_service_status_case_and_whitespace_variants():
    """Confirms healthy service status variants produce no incident when metrics are normal."""
    config = MonitoringConfig()
    normal_metrics = MetricSnapshot(
        latency_p50_ms=30.0,
        latency_p99_ms=80.0,
        error_rate_pct=0.1,
        request_rate_rps=100.0,
        cpu_utilization_pct=30.0,
        memory_utilization_pct=35.0,
    )
    healthy_variants = ["HEALTHY", "healthy", " HEALTHY ", "  hEaLtHy  "]

    for variant in healthy_variants:
        telemetry = TelemetryWindow(
            service="payment-service",
            timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
            metrics=normal_metrics,
            logs=[],
            service_status=variant,
        )
        incident = detect_incident(telemetry, config)
        assert incident is None, f"Expected no incident for variant: {repr(variant)}"


def test_high_cpu_warning_yields_medium():
    """An isolated CPU utilization warning breach (cpu_warn_pct <= cpu < cpu_crit_pct) yields MEDIUM."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,   # Normal (< 500.0)
            error_rate_pct=0.1,    # Normal (< 2.0)
            request_rate_rps=100.0,
            cpu_utilization_pct=config.cpu_warn_pct,  # Exactly at warning threshold (80.0%)
            memory_utilization_pct=45.0,  # Normal (< 85.0)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_CPU_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_CPU_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.cpu_warn_pct
    assert incident.evidence[0].observed_value == config.cpu_warn_pct


def test_high_cpu_critical_yields_high():
    """An isolated critical CPU utilization breach (>= cpu_crit_pct) yields HIGH."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,   # Normal (< 500.0)
            error_rate_pct=0.1,    # Normal (< 2.0)
            request_rate_rps=100.0,
            cpu_utilization_pct=config.cpu_crit_pct,  # Exactly at critical threshold (90.0%)
            memory_utilization_pct=45.0,  # Normal (< 85.0)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert any(e.rule_id == "RULE_CPU_CRIT" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_CPU_WARN" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.cpu_crit_pct
    assert incident.evidence[0].observed_value == config.cpu_crit_pct


def test_high_memory_warning_yields_medium():
    """An isolated memory utilization warning breach (memory_warn_pct <= mem < memory_crit_pct) yields MEDIUM."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,   # Normal (< 500.0)
            error_rate_pct=0.1,    # Normal (< 2.0)
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,  # Normal (< 80.0)
            memory_utilization_pct=config.memory_warn_pct,  # Exactly at warning threshold (85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_MEMORY_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_MEMORY_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.memory_warn_pct
    assert incident.evidence[0].observed_value == config.memory_warn_pct


def test_high_memory_critical_yields_high():
    """An isolated critical memory utilization breach (>= memory_crit_pct) yields HIGH."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,   # Normal (< 500.0)
            error_rate_pct=0.1,    # Normal (< 2.0)
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,  # Normal (< 80.0)
            memory_utilization_pct=config.memory_crit_pct,  # Exactly at critical threshold (95.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert any(e.rule_id == "RULE_MEMORY_CRIT" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_MEMORY_WARN" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.memory_crit_pct
    assert incident.evidence[0].observed_value == config.memory_crit_pct


def test_exact_threshold_boundary_latency_warn():
    """p99 latency exactly at config.latency_p99_warn_ms triggers a MEDIUM incident."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=config.latency_p99_warn_ms,  # Exactly 500.0 ms
            error_rate_pct=0.1,                         # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,                   # Normal (< 80.0%)
            memory_utilization_pct=45.0,                # Normal (< 85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_LATENCY_P99_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_LATENCY_P99_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.latency_p99_warn_ms
    assert incident.evidence[0].observed_value == config.latency_p99_warn_ms


def test_exact_threshold_boundary_error_rate_warn():
    """Error rate exactly at config.error_rate_warn_pct triggers a HIGH incident."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,                        # Normal (< 500.0 ms)
            error_rate_pct=config.error_rate_warn_pct,  # Exactly 2.0%
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,                   # Normal (< 80.0%)
            memory_utilization_pct=45.0,                # Normal (< 85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert any(e.rule_id == "RULE_ERROR_RATE_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_ERROR_RATE_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.error_rate_warn_pct
    assert incident.evidence[0].observed_value == config.error_rate_warn_pct


def test_exact_threshold_boundary_cpu_warn():
    """CPU utilization exactly at config.cpu_warn_pct triggers a MEDIUM incident."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,                      # Normal (< 500.0 ms)
            error_rate_pct=0.1,                       # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=config.cpu_warn_pct,  # Exactly 80.0%
            memory_utilization_pct=45.0,              # Normal (< 85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_CPU_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_CPU_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.cpu_warn_pct
    assert incident.evidence[0].observed_value == config.cpu_warn_pct


def test_exact_threshold_boundary_memory_warn():
    """Memory utilization exactly at config.memory_warn_pct triggers a MEDIUM incident."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,                            # Normal (< 500.0 ms)
            error_rate_pct=0.1,                             # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,                       # Normal (< 80.0%)
            memory_utilization_pct=config.memory_warn_pct,  # Exactly 85.0%
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_MEMORY_WARN" for e in incident.evidence)
    assert not any(e.rule_id == "RULE_MEMORY_CRIT" for e in incident.evidence)
    assert len(incident.evidence) == 1
    assert incident.evidence[0].threshold_value == config.memory_warn_pct
    assert incident.evidence[0].observed_value == config.memory_warn_pct


def test_below_threshold_boundary_latency_produces_no_incident():
    """p99 latency just below config.latency_p99_warn_ms (threshold - 0.01) produces no incident."""
    config = MonitoringConfig()
    below_threshold = round(config.latency_p99_warn_ms - 0.01, 2)  # 499.99 ms
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=below_threshold,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is None, f"Expected no incident at {below_threshold}ms latency, got {incident}"


def test_below_threshold_boundary_error_rate_produces_no_incident():
    """Error rate just below config.error_rate_warn_pct (threshold - 0.01) produces no incident."""
    config = MonitoringConfig()
    below_threshold = round(config.error_rate_warn_pct - 0.01, 2)  # 1.99%
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,
            error_rate_pct=below_threshold,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is None, f"Expected no incident at {below_threshold}% error rate, got {incident}"


def test_below_threshold_boundary_cpu_produces_no_incident():
    """CPU utilization just below config.cpu_warn_pct (threshold - 0.01) produces no incident."""
    config = MonitoringConfig()
    below_threshold = round(config.cpu_warn_pct - 0.01, 2)  # 79.99%
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=below_threshold,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is None, f"Expected no incident at {below_threshold}% CPU, got {incident}"


def test_below_threshold_boundary_memory_produces_no_incident():
    """Memory utilization just below config.memory_warn_pct (threshold - 0.01) produces no incident."""
    config = MonitoringConfig()
    below_threshold = round(config.memory_warn_pct - 0.01, 2)  # 84.99%
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=below_threshold,
        ),
        logs=[],
        service_status="HEALTHY",
    )
    incident = detect_incident(telemetry, config)
    assert incident is None, f"Expected no incident at {below_threshold}% memory, got {incident}"


def test_custom_config_warning_only_trigger():
    """A metric triggers a warning under custom config but produces no incident under defaults."""
    custom_config = MonitoringConfig(
        latency_p99_warn_ms=250.0,  # Default is 500.0
        latency_p99_crit_ms=800.0,  # Default is 1200.0
        error_rate_warn_pct=3.0,
        error_rate_crit_pct=10.0,
        cpu_warn_pct=85.0,
        cpu_crit_pct=95.0,
        memory_warn_pct=90.0,
        memory_crit_pct=98.0,
    )
    # 300ms is > custom 250.0ms warn, but < default 500.0ms warn
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=300.0,
            error_rate_pct=0.1,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    # 1. Default config must produce NO incident
    default_incident = detect_incident(telemetry)
    assert default_incident is None, "300ms latency must not trigger incident under default config (warn=500ms)"

    # 2. Custom config must trigger a MEDIUM incident
    custom_incident = detect_incident(telemetry, config=custom_config)
    assert custom_incident is not None, "300ms latency must trigger incident under custom config (warn=250ms)"
    assert custom_incident.severity == IncidentSeverity.MEDIUM
    assert any(e.rule_id == "RULE_LATENCY_P99_WARN" for e in custom_incident.evidence)
    assert custom_incident.evidence[0].threshold_value == 250.0
    assert custom_incident.evidence[0].observed_value == 300.0


def test_custom_config_critical_trigger():
    """A metric triggers a critical threshold under custom config while producing no incident under defaults."""
    custom_config = MonitoringConfig(
        latency_p99_warn_ms=500.0,
        latency_p99_crit_ms=1200.0,
        error_rate_warn_pct=1.0,    # Default is 2.0
        error_rate_crit_pct=1.5,    # Default is 8.0
        cpu_warn_pct=80.0,
        cpu_crit_pct=90.0,
        memory_warn_pct=85.0,
        memory_crit_pct=95.0,
    )
    # 1.8% error rate is < default warn 2.0% (so NO incident under defaults),
    # but >= custom crit 1.5% (triggers CRITICAL under custom config)
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,
            error_rate_pct=1.8,
            request_rate_rps=100.0,
            cpu_utilization_pct=40.0,
            memory_utilization_pct=45.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    # 1. Default config must produce NO incident
    default_incident = detect_incident(telemetry)
    assert default_incident is None, "1.8% error rate must not trigger incident under default config (warn=2.0%)"

    # 2. Custom config must trigger a CRITICAL incident
    custom_incident = detect_incident(telemetry, config=custom_config)
    assert custom_incident is not None, "1.8% error rate must trigger incident under custom config (crit=1.5%)"
    assert custom_incident.severity == IncidentSeverity.CRITICAL
    assert any(e.rule_id == "RULE_ERROR_RATE_CRIT" for e in custom_incident.evidence)
    assert custom_incident.evidence[0].threshold_value == 1.5
    assert custom_incident.evidence[0].observed_value == 1.8


def test_dual_warning_latency_and_cpu_yields_medium():
    """Simultaneous warning breaches for latency and CPU with normal error rate yield MEDIUM."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=40.0,
            latency_p99_ms=600.0,      # Warning (> 500.0ms, < 1200.0ms)
            error_rate_pct=0.1,        # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=85.0,  # Warning (> 80.0%, < 90.0%)
            memory_utilization_pct=45.0,  # Normal (< 85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM, (
        f"Latency warning + CPU warning should be MEDIUM, got {incident.severity}"
    )
    rule_ids = {e.rule_id for e in incident.evidence}
    assert "RULE_LATENCY_P99_WARN" in rule_ids
    assert "RULE_CPU_WARN" in rule_ids
    assert len(incident.evidence) == 2


def test_dual_warning_cpu_and_memory_yields_medium():
    """Simultaneous warning breaches for CPU and memory with normal latency and error rate yield MEDIUM."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,          # Normal (< 500.0ms)
            error_rate_pct=0.1,           # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=85.0,     # Warning (> 80.0%, < 90.0%)
            memory_utilization_pct=88.0,  # Warning (> 85.0%, < 95.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.MEDIUM, (
        f"CPU warning + Memory warning should be MEDIUM, got {incident.severity}"
    )
    rule_ids = {e.rule_id for e in incident.evidence}
    assert "RULE_CPU_WARN" in rule_ids
    assert "RULE_MEMORY_WARN" in rule_ids
    assert len(incident.evidence) == 2


def test_critical_cpu_with_warning_latency_yields_high():
    """Critical CPU breach with warning latency yields HIGH (HIGH takes precedence over MEDIUM)."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=40.0,
            latency_p99_ms=600.0,      # Warning (> 500.0ms, < 1200.0ms)
            error_rate_pct=0.1,        # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=92.0,  # Critical (>= 90.0%)
            memory_utilization_pct=45.0,  # Normal (< 85.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH, (
        f"Critical CPU + Warning latency should be HIGH, got {incident.severity}"
    )
    rule_ids = {e.rule_id for e in incident.evidence}
    assert "RULE_CPU_CRIT" in rule_ids
    assert "RULE_LATENCY_P99_WARN" in rule_ids
    assert len(incident.evidence) == 2


def test_critical_memory_with_warning_cpu_yields_high():
    """Critical memory breach with warning CPU yields HIGH (HIGH takes precedence over MEDIUM)."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=30.0,
            latency_p99_ms=90.0,          # Normal (< 500.0ms)
            error_rate_pct=0.1,           # Normal (< 2.0%)
            request_rate_rps=100.0,
            cpu_utilization_pct=85.0,     # Warning (> 80.0%, < 90.0%)
            memory_utilization_pct=96.0,  # Critical (>= 95.0%)
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH, (
        f"Critical memory + Warning CPU should be HIGH, got {incident.severity}"
    )
    rule_ids = {e.rule_id for e in incident.evidence}
    assert "RULE_MEMORY_CRIT" in rule_ids
    assert "RULE_CPU_WARN" in rule_ids
    assert len(incident.evidence) == 2


def test_zero_traffic_with_zero_errors_produces_no_incident():
    """Documents current behavior: a zero-traffic condition (0 rps, 0% error) produces no incident."""
    config = MonitoringConfig()
    telemetry = TelemetryWindow(
        service="payment-service",
        timestamp=datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
        metrics=MetricSnapshot(
            latency_p50_ms=0.0,
            latency_p99_ms=0.0,
            error_rate_pct=0.0,
            request_rate_rps=0.0,  # Zero requests per second (complete traffic blackhole or idle)
            cpu_utilization_pct=10.0,
            memory_utilization_pct=25.0,
        ),
        logs=[],
        service_status="HEALTHY",
    )

    incident = detect_incident(telemetry, config)
    # Documents confirmed behavior: without a min request_rate_rps threshold or baseline traffic model,
    # zero requests per second with 0% errors evaluates as completely healthy.
    assert incident is None, (
        "Current detector does not monitor min request_rate_rps, so zero traffic returns None"
    )


class TestMonitoringSuite(unittest.TestCase):
    """Unittest wrapper allowing the test suite to run via python -m unittest."""

    def test_healthy_baseline_produces_no_incident(self):
        test_healthy_baseline_produces_no_incident()

    def test_faulty_deployment_produces_incident(self):
        test_faulty_deployment_produces_incident()

    def test_high_latency_warning_yields_medium(self):
        test_high_latency_warning_yields_medium()

    def test_high_latency_critical_yields_high(self):
        test_high_latency_critical_yields_high()

    def test_high_error_rate_warning_yields_high(self):
        test_high_error_rate_warning_yields_high()

    def test_high_error_rate_critical_yields_critical(self):
        test_high_error_rate_critical_yields_critical()

    def test_dual_warning_latency_and_error_rate_yields_critical(self):
        test_dual_warning_latency_and_error_rate_yields_critical()

    def test_unhealthy_service_status_yields_critical(self):
        test_unhealthy_service_status_yields_critical()

    def test_severity_precedence_critical_over_high(self):
        test_severity_precedence_critical_over_high()

    def test_incident_payload_contains_required_fields(self):
        test_incident_payload_contains_required_fields()

    def test_repeated_scenarios_are_reproducible(self):
        test_repeated_scenarios_are_reproducible()

    def test_incident_retains_deployment_event_metadata(self):
        test_incident_retains_deployment_event_metadata()

    def test_healthy_telemetry_without_deployment_produces_no_incident(self):
        test_healthy_telemetry_without_deployment_produces_no_incident()

    def test_incident_without_deployment_event(self):
        test_incident_without_deployment_event()

    def test_deployment_event_importable_from_shared_schemas(self):
        test_deployment_event_importable_from_shared_schemas()

    def test_distinct_microsecond_timestamps_produce_distinct_incident_ids(self):
        test_distinct_microsecond_timestamps_produce_distinct_incident_ids()

    def test_repeated_detection_produces_identical_incident_id(self):
        test_repeated_detection_produces_identical_incident_id()

    def test_zero_microsecond_timestamp_generates_valid_incident_id(self):
        test_zero_microsecond_timestamp_generates_valid_incident_id()

    def test_unhealthy_service_status_case_and_whitespace_variants(self):
        test_unhealthy_service_status_case_and_whitespace_variants()

    def test_degraded_service_status_case_and_whitespace_variants(self):
        test_degraded_service_status_case_and_whitespace_variants()

    def test_healthy_service_status_case_and_whitespace_variants(self):
        test_healthy_service_status_case_and_whitespace_variants()

    def test_high_cpu_warning_yields_medium(self):
        test_high_cpu_warning_yields_medium()

    def test_high_cpu_critical_yields_high(self):
        test_high_cpu_critical_yields_high()

    def test_high_memory_warning_yields_medium(self):
        test_high_memory_warning_yields_medium()

    def test_high_memory_critical_yields_high(self):
        test_high_memory_critical_yields_high()

    def test_exact_threshold_boundary_latency_warn(self):
        test_exact_threshold_boundary_latency_warn()

    def test_exact_threshold_boundary_error_rate_warn(self):
        test_exact_threshold_boundary_error_rate_warn()

    def test_exact_threshold_boundary_cpu_warn(self):
        test_exact_threshold_boundary_cpu_warn()

    def test_exact_threshold_boundary_memory_warn(self):
        test_exact_threshold_boundary_memory_warn()

    def test_below_threshold_boundary_latency_produces_no_incident(self):
        test_below_threshold_boundary_latency_produces_no_incident()

    def test_below_threshold_boundary_error_rate_produces_no_incident(self):
        test_below_threshold_boundary_error_rate_produces_no_incident()

    def test_below_threshold_boundary_cpu_produces_no_incident(self):
        test_below_threshold_boundary_cpu_produces_no_incident()

    def test_below_threshold_boundary_memory_produces_no_incident(self):
        test_below_threshold_boundary_memory_produces_no_incident()

    def test_custom_config_warning_only_trigger(self):
        test_custom_config_warning_only_trigger()

    def test_custom_config_critical_trigger(self):
        test_custom_config_critical_trigger()

    def test_dual_warning_latency_and_cpu_yields_medium(self):
        test_dual_warning_latency_and_cpu_yields_medium()

    def test_dual_warning_cpu_and_memory_yields_medium(self):
        test_dual_warning_cpu_and_memory_yields_medium()

    def test_critical_cpu_with_warning_latency_yields_high(self):
        test_critical_cpu_with_warning_latency_yields_high()

    def test_critical_memory_with_warning_cpu_yields_high(self):
        test_critical_memory_with_warning_cpu_yields_high()

    def test_zero_traffic_with_zero_errors_produces_no_incident(self):
        test_zero_traffic_with_zero_errors_produces_no_incident()


if __name__ == "__main__":
    unittest.main()

