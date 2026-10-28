"""Tests for recovery actions."""

import pytest

from app.infrastructure import InfrastructureSimulator
from app.models import (
    Incident,
    IncidentSeverity,
    RecoveryActionType,
    ServiceStatus,
)
from app.recovery import execute, pick_action


def test_pick_action_critical():
    inc = Incident(service_name="x", severity=IncidentSeverity.CRITICAL, description="")
    assert pick_action(inc) == RecoveryActionType.FAILOVER


def test_pick_action_high():
    inc = Incident(service_name="x", severity=IncidentSeverity.HIGH, description="")
    assert pick_action(inc) == RecoveryActionType.SCALE_UP


def test_pick_action_low():
    inc = Incident(service_name="x", severity=IncidentSeverity.LOW, description="")
    assert pick_action(inc) == RecoveryActionType.RESTART_SERVICE


@pytest.fixture()
def sim():
    return InfrastructureSimulator()


def test_execute_restart(sim: InfrastructureSimulator):
    sim.inject_incident("cache-layer", IncidentSeverity.LOW)
    inc = Incident(service_name="cache-layer", severity=IncidentSeverity.LOW, description="")
    result = execute(inc, sim)
    assert result.success is True
    assert result.action == RecoveryActionType.RESTART_SERVICE
    assert sim.get_service("cache-layer").status == ServiceStatus.HEALTHY


def test_execute_scale_up(sim: InfrastructureSimulator):
    sim.inject_incident("api-gateway", IncidentSeverity.HIGH)
    inc = Incident(service_name="api-gateway", severity=IncidentSeverity.HIGH, description="")
    result = execute(inc, sim)
    assert result.success is True
    assert result.action == RecoveryActionType.SCALE_UP


def test_execute_failover(sim: InfrastructureSimulator):
    sim.inject_incident("web-frontend", IncidentSeverity.CRITICAL)
    inc = Incident(service_name="web-frontend", severity=IncidentSeverity.CRITICAL, description="")
    result = execute(inc, sim)
    assert result.success is True
    assert result.action == RecoveryActionType.FAILOVER
    assert sim.get_service("web-frontend").status == ServiceStatus.HEALTHY
