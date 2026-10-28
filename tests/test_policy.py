"""Tests for the policy decision engine."""

from app.models import (
    Incident,
    IncidentSeverity,
    PolicyDecision,
    ServiceInfo,
    ServiceStatus,
)
from app.policy import evaluate


def _make_service(name: str, status: ServiceStatus) -> ServiceInfo:
    return ServiceInfo(name=name, status=status, cpu_percent=50, memory_percent=50, error_rate=0.5)


def test_healthy_service_is_denied():
    inc = Incident(service_name="web", severity=IncidentSeverity.HIGH, description="x")
    svc = _make_service("web", ServiceStatus.HEALTHY)
    assert evaluate(inc, svc) == PolicyDecision.DENY


def test_low_severity_approved():
    inc = Incident(service_name="web", severity=IncidentSeverity.LOW, description="x")
    svc = _make_service("web", ServiceStatus.DEGRADED)
    assert evaluate(inc, svc) == PolicyDecision.APPROVE


def test_high_severity_approved():
    inc = Incident(service_name="web", severity=IncidentSeverity.HIGH, description="x")
    svc = _make_service("web", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.APPROVE


def test_critical_protected_service_manual_review():
    inc = Incident(service_name="database", severity=IncidentSeverity.CRITICAL, description="x")
    svc = _make_service("database", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.MANUAL_REVIEW


def test_critical_non_protected_service_manual_review():
    """CRITICAL exceeds AUTO_APPROVE_MAX_SEVERITY (HIGH) → MANUAL_REVIEW."""
    inc = Incident(service_name="web", severity=IncidentSeverity.CRITICAL, description="x")
    svc = _make_service("web", ServiceStatus.DOWN)
    assert evaluate(inc, svc) == PolicyDecision.MANUAL_REVIEW
