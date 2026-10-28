"""Tests for the independent verification checker."""

import pytest

from app.infrastructure import InfrastructureSimulator
from app.models import IncidentSeverity, VerificationOutcome
from app.verification import verify


@pytest.fixture()
def sim():
    return InfrastructureSimulator()


def test_healthy_service_passes(sim: InfrastructureSimulator):
    result = verify("web-frontend", sim)
    assert result.outcome == VerificationOutcome.PASS


def test_down_service_fails(sim: InfrastructureSimulator):
    sim.inject_incident("web-frontend", IncidentSeverity.CRITICAL)
    result = verify("web-frontend", sim)
    assert result.outcome == VerificationOutcome.FAIL


def test_unknown_service_fails(sim: InfrastructureSimulator):
    result = verify("ghost-service", sim)
    assert result.outcome == VerificationOutcome.FAIL
    assert "not found" in result.details


def test_recovered_service_passes(sim: InfrastructureSimulator):
    sim.inject_incident("api-gateway", IncidentSeverity.HIGH)
    sim.set_service_healthy("api-gateway")
    result = verify("api-gateway", sim)
    assert result.outcome == VerificationOutcome.PASS
