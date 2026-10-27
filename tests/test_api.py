"""Tests for FastAPI endpoints."""

from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_services():
    response = client.get("/api/services")
    assert response.status_code == 200
    services = response.json()
    assert len(services) == 5


def test_get_service_known():
    response = client.get("/api/services/web-frontend")
    assert response.status_code == 200
    assert response.json()["service_name"] == "web-frontend"


def test_get_service_unknown():
    response = client.get("/api/services/nonexistent")
    assert response.status_code == 404


def test_create_incident_and_recover():
    response = client.post(
        "/api/incidents",
        json={
            "service_name": "web-frontend",
            "severity": "low",
            "description": "API test incident",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["pipeline_status"] == "success"
    assert data["incident"]["service_name"] == "web-frontend"


def test_reset_infrastructure():
    response = client.post("/api/reset")
    assert response.status_code == 200
    assert response.json() == {"status": "reset"}
