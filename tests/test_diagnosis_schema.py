"""Isolated tests for the DiagnosisResult Pydantic schema.

Verifies:
- Valid diagnosis instantiation and field extraction
- All supported RecoveryActionType values are accepted
- Confidence boundaries (0.0 and 1.0 inclusive)
- Missing required fields rejection
- Invalid confidence rejection (< 0.0 or > 1.0)
- Unsupported action ID rejection (including 'rollback_deployment')
- Rejection of unexpected/extra fields (extra='forbid')
- Serialization and deserialization roundtrip
"""

import pytest
from pydantic import ValidationError

from app.diagnosis import DiagnosisResult
from app.models import RecoveryActionType


@pytest.fixture
def valid_diagnosis_payload() -> dict:
    """Returns a valid dictionary payload for creating a DiagnosisResult."""
    return {
        "likely_cause": "Database connection pool exhaustion caused by unindexed queries",
        "evidence": [
            "Active connections reached pool limit of 100",
            "API error rate spiked to 45%",
            "Query latency p99 exceeded 5000ms",
        ],
        "confidence": 0.85,
        "recommended_action_id": "restart_service",
        "rationale": "Restarting the service immediately clears leaked and stalled connections.",
        "uncertainty_or_notes": "If connection pool exhausts again within 5 minutes, scale_service is advised.",
    }


def test_valid_diagnosis_creation(valid_diagnosis_payload):
    """Test that DiagnosisResult can be created with valid data."""
    diagnosis = DiagnosisResult(**valid_diagnosis_payload)

    assert diagnosis.likely_cause == valid_diagnosis_payload["likely_cause"]
    assert diagnosis.evidence == valid_diagnosis_payload["evidence"]
    assert diagnosis.confidence == 0.85
    assert diagnosis.recommended_action_id == "restart_service"
    assert diagnosis.rationale == valid_diagnosis_payload["rationale"]
    assert diagnosis.uncertainty_or_notes == valid_diagnosis_payload["uncertainty_or_notes"]


@pytest.mark.parametrize(
    "action_id",
    [
        "restart_service",
        "clear_queue",
        "scale_service",
        "scale_up",
        "failover",
        RecoveryActionType.RESTART_SERVICE,
        RecoveryActionType.CLEAR_QUEUE,
        RecoveryActionType.SCALE_SERVICE,
        RecoveryActionType.SCALE_UP,
        RecoveryActionType.FAILOVER,
    ],
)
def test_all_supported_recovery_action_types_accepted(valid_diagnosis_payload, action_id):
    """Test that all supported RecoveryActionType values are valid."""
    payload = {**valid_diagnosis_payload, "recommended_action_id": action_id}
    diagnosis = DiagnosisResult(**payload)
    expected_value = action_id.value if hasattr(action_id, "value") else action_id
    assert diagnosis.recommended_action_id == expected_value


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_valid_confidence_boundaries(valid_diagnosis_payload, confidence):
    """Test confidence edge values: 0.0, middle, and 1.0."""
    payload = {**valid_diagnosis_payload, "confidence": confidence}
    diagnosis = DiagnosisResult(**payload)
    assert diagnosis.confidence == confidence


@pytest.mark.parametrize(
    "missing_field",
    [
        "likely_cause",
        "evidence",
        "confidence",
        "recommended_action_id",
        "rationale",
        "uncertainty_or_notes",
    ],
)
def test_missing_required_fields_rejected(valid_diagnosis_payload, missing_field):
    """Test that omitting any required field raises ValidationError."""
    payload = dict(valid_diagnosis_payload)
    del payload[missing_field]

    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult(**payload)

    errors = exc_info.value.errors()
    assert any(err["loc"] == (missing_field,) for err in errors)


def test_empty_payload_rejected():
    """Test that initializing with an empty payload raises ValidationError for all fields."""
    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult()

    errors = exc_info.value.errors()
    assert len(errors) == 6


@pytest.mark.parametrize("invalid_confidence", [-0.01, -0.5, -1.0])
def test_invalid_confidence_below_zero(valid_diagnosis_payload, invalid_confidence):
    """Test that confidence < 0.0 raises ValidationError."""
    payload = {**valid_diagnosis_payload, "confidence": invalid_confidence}
    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult(**payload)

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("confidence",) for err in errors)


@pytest.mark.parametrize("invalid_confidence", [1.01, 1.5, 2.0])
def test_invalid_confidence_above_one(valid_diagnosis_payload, invalid_confidence):
    """Test that confidence > 1.0 raises ValidationError."""
    payload = {**valid_diagnosis_payload, "confidence": invalid_confidence}
    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult(**payload)

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("confidence",) for err in errors)


@pytest.mark.parametrize(
    "unsupported_action",
    [
        "rollback_deployment",
        "reboot_server",
        "unknown_action",
        "",
        "RESTART_SERVICE",  # Case-sensitive check
    ],
)
def test_unsupported_action_id_rejected(valid_diagnosis_payload, unsupported_action):
    """Test that unsupported recovery actions (including rollback_deployment) are rejected."""
    payload = {**valid_diagnosis_payload, "recommended_action_id": unsupported_action}
    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult(**payload)

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("recommended_action_id",) for err in errors)
    assert any("Unsupported action ID" in str(err.get("msg", "")) for err in errors)


def test_unexpected_extra_fields_rejected(valid_diagnosis_payload):
    """Test that unexpected extra fields raise ValidationError due to extra='forbid'."""
    payload = {
        **valid_diagnosis_payload,
        "unexpected_field": "disallowed_value",
        "another_extra": 123,
    }
    with pytest.raises(ValidationError) as exc_info:
        DiagnosisResult(**payload)

    errors = exc_info.value.errors()
    extra_locs = {err["loc"][0] for err in errors}
    assert "unexpected_field" in extra_locs
    assert "another_extra" in extra_locs


def test_invalid_evidence_type(valid_diagnosis_payload):
    """Test that evidence must be a list of strings."""
    payload = {**valid_diagnosis_payload, "evidence": "not a list"}
    with pytest.raises(ValidationError):
        DiagnosisResult(**payload)


def test_serialization_roundtrip(valid_diagnosis_payload):
    """Test serialization to dict/json and deserialization back into DiagnosisResult."""
    diagnosis = DiagnosisResult(**valid_diagnosis_payload)
    dumped_dict = diagnosis.model_dump()
    assert dumped_dict == valid_diagnosis_payload

    json_str = diagnosis.model_dump_json()
    reconstructed = DiagnosisResult.model_validate_json(json_str)
    assert reconstructed == diagnosis
