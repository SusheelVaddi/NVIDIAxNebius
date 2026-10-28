"""Tests for the JSONL audit logger."""

import pytest
from pathlib import Path
import tempfile

from app.audit import AuditLogger
from app.models import (
    AuditRecord,
    Incident,
    IncidentSeverity,
    PipelineStatus,
    PolicyDecision,
)


@pytest.fixture()
def logger(tmp_path: Path):
    """Logger writing to a temp directory."""
    log_path = tmp_path / "test_audit.jsonl"
    lg = AuditLogger(path=log_path)
    yield lg
    lg.clear()


def _make_record() -> AuditRecord:
    inc = Incident(service_name="web", severity=IncidentSeverity.LOW, description="test")
    return AuditRecord(
        incident=inc,
        policy_decision=PolicyDecision.APPROVE,
        pipeline_status=PipelineStatus.SUCCESS,
    )


def test_log_and_read_back(logger: AuditLogger):
    record = _make_record()
    logger.log(record)
    records = logger.read_all()
    assert len(records) == 1
    assert records[0].incident.service_name == "web"


def test_multiple_records(logger: AuditLogger):
    for _ in range(5):
        logger.log(_make_record())
    assert len(logger.read_all()) == 5


def test_read_empty_log(logger: AuditLogger):
    assert logger.read_all() == []


def test_clear(logger: AuditLogger):
    logger.log(_make_record())
    logger.clear()
    assert logger.read_all() == []
