"""
Monitoring and detection module for Member 2.

Exposes configuration, telemetry models, scenarios, and the incident detector.
"""

from src.monitoring.config import MonitoringConfig
from src.monitoring.telemetry import DeploymentEvent, TelemetryWindow
from src.monitoring.scenarios import (
    generate_healthy_scenario,
    generate_faulty_deployment_scenario,
)
from src.monitoring.detector import detect_incident

__all__ = [
    "MonitoringConfig",
    "DeploymentEvent",
    "TelemetryWindow",
    "generate_healthy_scenario",
    "generate_faulty_deployment_scenario",
    "detect_incident",
]
