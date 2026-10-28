"""Tests for the in-memory infrastructure simulator."""

import pytest

from app.infrastructure import InfrastructureSimulator
from app.models import IncidentSeverity, ServiceStatus


@pytest.fixture()
def sim():
    """Fresh simulator for each test."""
    return InfrastructureSimulator()


def test_list_services_returns_all(sim: InfrastructureSimulator):
    services = sim.list_services()
    assert len(services) == 5
    names = {s.name for s in services}
    assert "web-frontend" in names
    assert "database" in names


def test_all_services_start_healthy(sim: InfrastructureSimulator):
    for svc in sim.list_services():
        assert svc.status == ServiceStatus.HEALTHY


def test_get_service_known(sim: InfrastructureSimulator):
    svc = sim.get_service("api-gateway")
    assert svc is not None
    assert svc.name == "api-gateway"


def test_get_service_unknown(sim: InfrastructureSimulator):
    assert sim.get_service("nonexistent") is None


def test_inject_incident_high_severity(sim: InfrastructureSimulator):
    incident = sim.inject_incident("web-frontend", IncidentSeverity.HIGH)
    assert incident.service_name == "web-frontend"
    svc = sim.get_service("web-frontend")
    assert svc.status == ServiceStatus.DOWN


def test_inject_incident_low_severity(sim: InfrastructureSimulator):
    sim.inject_incident("cache-layer", IncidentSeverity.LOW)
    svc = sim.get_service("cache-layer")
    assert svc.status == ServiceStatus.DEGRADED


def test_inject_unknown_service_raises(sim: InfrastructureSimulator):
    with pytest.raises(ValueError, match="Unknown service"):
        sim.inject_incident("ghost", IncidentSeverity.LOW)


def test_set_service_healthy(sim: InfrastructureSimulator):
    sim.inject_incident("api-gateway", IncidentSeverity.CRITICAL)
    sim.set_service_healthy("api-gateway")
    svc = sim.get_service("api-gateway")
    assert svc.status == ServiceStatus.HEALTHY


def test_scale_up_service(sim: InfrastructureSimulator):
    sim.inject_incident("web-frontend", IncidentSeverity.MEDIUM)
    sim.scale_up_service("web-frontend")
    svc = sim.get_service("web-frontend")
    assert svc.status == ServiceStatus.HEALTHY
    assert svc.cpu_percent < 50


def test_reset(sim: InfrastructureSimulator):
    sim.inject_incident("database", IncidentSeverity.CRITICAL)
    sim.reset()
    for svc in sim.list_services():
        assert svc.status == ServiceStatus.HEALTHY
