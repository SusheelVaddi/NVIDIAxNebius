"""Tests for the orchestration pipeline (end-to-end)."""

import pytest
from pathlib import Path

from app.audit import AuditLogger
from app.infrastructure import InfrastructureSimulator
from app.models import (
    IncidentSeverity,
    PipelineStatus,
    PolicyDecision,
    ServiceStatus,
)
from app.orchestrator import detect_and_recover


@pytest.fixture()
def sim():
    return InfrastructureSimulator()


@pytest.fixture()
def logger(tmp_path: Path):
    lg = AuditLogger(path=tmp_path / "test.jsonl")
    yield lg
    lg.clear()


def test_full_pipeline_success(sim, logger):
    """LOW severity on a normal service → full success."""
    record = detect_and_recover("web-frontend", IncidentSeverity.LOW, sim, logger)
    assert record.policy_decision == PolicyDecision.APPROVE
    assert record.pipeline_status == PipelineStatus.SUCCESS
    assert record.recovery is not None
    assert record.recovery.success is True
    assert record.verification is not None
    assert record.verification.outcome.value == "pass"
    # Service should be healthy again
    assert sim.get_service("web-frontend").status == ServiceStatus.HEALTHY


def test_pipeline_denied_for_critical_protected(sim, logger):
    """CRITICAL severity on 'database' (protected) → denied / manual review."""
    record = detect_and_recover("database", IncidentSeverity.CRITICAL, sim, logger)
    assert record.policy_decision == PolicyDecision.MANUAL_REVIEW
    assert record.pipeline_status == PipelineStatus.RECOVERY_DENIED
    assert record.recovery is None


def test_pipeline_high_severity_success(sim, logger):
    """HIGH severity on a normal service → approved and recovered."""
    record = detect_and_recover("api-gateway", IncidentSeverity.HIGH, sim, logger)
    assert record.pipeline_status == PipelineStatus.SUCCESS


def test_pipeline_audit_trail(sim, logger):
    """Two pipeline runs should produce two audit records."""
    detect_and_recover("web-frontend", IncidentSeverity.LOW, sim, logger)
    sim.reset()
    detect_and_recover("cache-layer", IncidentSeverity.MEDIUM, sim, logger)
    records = logger.read_all()
    assert len(records) == 2


def test_pipeline_unknown_service(sim, logger):
    """Injecting on an unknown service raises ValueError."""
    with pytest.raises(ValueError, match="Unknown service"):
        detect_and_recover("nonexistent", IncidentSeverity.LOW, sim, logger)
