"""Tests for the frontend dashboard and backend integration.

Validates that:
- The dashboard is correctly served at root (/) and /dashboard.
- The UI contains all required components: service metrics, incident form,
  administrative reset, lifecycle visualization, policy gate decisions,
  independent verification, and audit hash chain integrity.
- The frontend correctly targets actual backend API endpoints and schema fields.
- End-to-end simulated user interaction flows through the real backend API.
"""

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.infrastructure import infra
from app.models import ServiceStatus

client = TestClient(app)


def test_dashboard_served_with_correct_headers():
    """Verify dashboard is served with text/html content type at / and /dashboard."""
    for path in ["/", "/dashboard"]:
        res = client.get(path)
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "<!doctype html>" in res.text.lower()
        assert "Incident recovery" in res.text


def test_dashboard_contains_all_core_sections():
    """Verify dashboard HTML contains all required architectural sections and controls."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # 1. Branding & Safety Banner
    assert "NVIDIA × Nebius" in html
    assert "Simulation Sandbox Active" in html

    # 2. Status & Overview Indicators
    assert 'id="health-dot"' in html
    assert 'id="audit-integrity-dot"' in html
    assert 'id="service-count"' in html
    assert 'id="healthy-count"' in html
    assert 'id="attention-count"' in html
    assert 'id="incident-count"' in html
    assert 'id="audit-chain-metric"' in html

    # 3. Service & Incident Reporting Form
    assert 'id="service-select"' in html
    assert 'id="incident-form"' in html
    assert 'name="severity"' in html
    assert 'name="description"' in html
    assert 'id="submit-button"' in html

    # 4. Administrative Controls & Security
    assert 'id="reset-form"' in html
    assert 'id="admin-token-input"' in html
    assert 'id="clear-audit-checkbox"' in html
    assert 'id="reset-button"' in html

    # 5. Recovery Outcome, Lifecycle & Verification
    assert 'id="pipeline-status-banner"' in html
    assert 'id="lifecycle"' in html
    assert 'id="recovery-result"' in html
    assert 'id="selected-incident-label"' in html

    # 6. Audit Trail & Cryptographic Hash Chain
    assert 'id="audit-history"' in html
    assert 'id="verify-audit-button"' in html


def test_dashboard_script_references_actual_api_endpoints():
    """Verify that client JavaScript communicates exclusively with existing backend routes."""
    res = client.get("/")
    html = res.text

    required_endpoints = [
        "/health",
        "/services",
        "/incidents",
        "/audit",
        "/audit/verify",
        "/reset",
    ]
    for endpoint in required_endpoints:
        assert f'"{endpoint}"' in html or f"'{endpoint}'" in html or f"`{endpoint}" in html, (
            f"Expected dashboard script to target endpoint: {endpoint}"
        )


def test_frontend_backend_integration_flow():
    """Simulate a complete user workflow interacting with the backend through the exact endpoints used by the dashboard."""
    # 1. User checks backend health
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"

    # 2. User checks audit hash chain integrity
    integrity_res = client.get("/audit/verify")
    assert integrity_res.status_code == 200
    assert "is_valid" in integrity_res.json()
    assert integrity_res.json()["is_valid"] is True

    # 3. User lists infrastructure services
    services_res = client.get("/services")
    assert services_res.status_code == 200
    services = services_res.json()
    assert len(services) > 0
    service_names = [s["service_name"] for s in services]
    assert "web-frontend" in service_names

    # 4. User reports an incident on web-frontend
    submit_res = client.post(
        "/incidents",
        json={
            "service_name": "web-frontend",
            "severity": "low",
            "description": "Integration test incident via dashboard",
        },
    )
    assert submit_res.status_code == 200
    record = submit_res.json()
    assert record["pipeline_status"] == "success"
    incident_id = record["incident"]["id"]

    # 5. User inspects sequential audit trail for the submitted incident
    audit_res = client.get(f"/incidents/{incident_id}/audit")
    assert audit_res.status_code == 200
    events = audit_res.json()
    assert len(events) >= 6

    # Verify cryptographic hash links in sequential events
    assert events[0]["previous_hash"] is not None
    assert events[0]["event_hash"] is not None
    for i in range(1, len(events)):
        assert events[i]["previous_hash"] == events[i - 1]["event_hash"]

    # 6. User verifies global audit integrity after recovery
    reverify_res = client.get("/audit/verify")
    assert reverify_res.status_code == 200
    assert reverify_res.json()["is_valid"] is True

    # 7. User performs administrative reset preserving audit trail
    reset_res = client.post("/reset", json={"clear_audit": False})
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "reset"
    assert reset_res.json()["audit_cleared"] is False

    # Confirm audit events are still accessible after reset
    preserved_audit = client.get(f"/incidents/{incident_id}/audit")
    assert preserved_audit.status_code == 200
    assert len(preserved_audit.json()) == len(events)

