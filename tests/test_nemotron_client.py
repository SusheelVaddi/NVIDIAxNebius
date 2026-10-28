"""Unit tests for the NemotronClient using mocked HTTP responses.

Verifies:
- Configuration from environment variables and constructor parameters
- Security: API keys are never exposed in __repr__
- Missing API credentials handling (explicit failure, never silent mock)
- Explicit mock mode (returns mock response without network calls or API key)
- Custom mock responses (dict, string, callable)
- Successful chat completion with mocked HTTP 200 response
- HTTP header and payload verification (Authorization: Bearer ..., Content-Type, etc.)
- Helper method .complete() returns content string
- Connection error handling (URLError -> NemotronConnectionError)
- Request timeout handling (socket.timeout / URLError -> NemotronTimeoutError)
- Authentication error handling (HTTP 401/403 -> NemotronAuthError)
- API error handling (HTTP 429/500 -> NemotronAPIError)
- Malformed response handling (non-JSON, missing choices, missing content -> NemotronResponseError)
- Input validation (empty or invalid messages -> ValueError)
"""

import io
import json
import socket
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from app.diagnosis import (
    NemotronAPIError,
    NemotronAuthError,
    NemotronClient,
    NemotronConnectionError,
    NemotronResponseError,
    NemotronTimeoutError,
)
from app.diagnosis.client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_ID,
    DEFAULT_TIMEOUT_SECONDS,
)


@pytest.fixture
def sample_messages():
    """Return standard test chat messages."""
    return [
        {"role": "system", "content": "You are a reliability engineer."},
        {"role": "user", "content": "Analyze incident inc-12345."},
    ]


@pytest.fixture
def mock_http_response_factory():
    """Factory creating a mock urllib HTTP response object."""

    def _create(status: int = 200, body_dict: dict | None = None, raw_body: str | None = None):
        if raw_body is None:
            raw_body = json.dumps(body_dict or {})
        resp = MagicMock()
        resp.status = status
        resp.read.return_value = raw_body.encode("utf-8")
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    return _create


# ==============================================================================
# Configuration & Initialization Tests
# ==============================================================================

def test_client_default_configuration(monkeypatch):
    """Test defaults when no environment variables or arguments are provided."""
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEMOTRON_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_API_BASE", raising=False)
    monkeypatch.delenv("NEBIUS_BASE_URL", raising=False)
    monkeypatch.delenv("NEBIUS_MODEL_ID", raising=False)
    monkeypatch.delenv("NEMOTRON_MODEL", raising=False)
    monkeypatch.delenv("NEBIUS_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("NEBIUS_MOCK_MODE", raising=False)

    client = NemotronClient()
    assert client.api_key is None
    assert client.base_url == DEFAULT_BASE_URL
    assert client.model_id == DEFAULT_MODEL_ID
    assert client.timeout == DEFAULT_TIMEOUT_SECONDS
    assert client.mock_mode is False


def test_client_configuration_from_env(monkeypatch):
    """Test reading configuration from environment variables."""
    monkeypatch.setenv("NEBIUS_API_KEY", "env-secret-key-12345")
    monkeypatch.setenv("NEBIUS_API_BASE", "https://custom.api.nebius.com/v1/")
    monkeypatch.setenv("NEBIUS_MODEL_ID", "nvidia/nemotron-custom-model")
    monkeypatch.setenv("NEBIUS_TIMEOUT_SECONDS", "45.5")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "true")

    client = NemotronClient()
    assert client.api_key == "env-secret-key-12345"
    assert client.base_url == "https://custom.api.nebius.com/v1"
    assert client.model_id == "nvidia/nemotron-custom-model"
    assert client.timeout == 45.5
    assert client.mock_mode is True


def test_constructor_overrides_env(monkeypatch):
    """Test that explicit constructor arguments override environment variables."""
    monkeypatch.setenv("NEBIUS_API_KEY", "env-key")
    monkeypatch.setenv("NEBIUS_API_BASE", "https://env-base.com/v1")
    monkeypatch.setenv("NEBIUS_MODEL_ID", "env-model")
    monkeypatch.setenv("NEBIUS_TIMEOUT_SECONDS", "10")
    monkeypatch.setenv("NEBIUS_MOCK_MODE", "false")

    client = NemotronClient(
        api_key="arg-key",
        base_url="https://arg-base.com/v1",
        model_id="arg-model",
        timeout=25.0,
        mock_mode=True,
    )
    assert client.api_key == "arg-key"
    assert client.base_url == "https://arg-base.com/v1"
    assert client.model_id == "arg-model"
    assert client.timeout == 25.0
    assert client.mock_mode is True


def test_secret_masking_in_repr(monkeypatch):
    """Verify that sensitive API keys are masked in string representation."""
    client = NemotronClient(api_key="very-secret-token-abcdef123456")
    repr_str = repr(client)
    assert "very-secret-token-abcdef123456" not in repr_str
    assert "very...3456" in repr_str or "***" in repr_str

    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEMOTRON_API_KEY", raising=False)
    client_no_key = NemotronClient(api_key=None)
    assert "None" in repr(client_no_key)


# ==============================================================================
# Missing Credentials & Mock Mode Tests
# ==============================================================================

def test_missing_api_key_raises_auth_error_when_mock_disabled(monkeypatch, sample_messages):
    """Critical: Missing API key must fail explicitly and NEVER silently mock."""
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEMOTRON_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_MOCK_MODE", raising=False)

    client = NemotronClient(api_key=None, mock_mode=False)

    with pytest.raises(NemotronAuthError) as exc_info:
        client.create_chat_completion(sample_messages)

    assert "API credentials missing" in str(exc_info.value)
    assert "Mock mode is disabled" in str(exc_info.value)


def test_explicit_mock_mode_default_response(sample_messages):
    """Explicit mock mode should succeed without API credentials or network calls."""
    client = NemotronClient(mock_mode=True)
    response = client.create_chat_completion(sample_messages)

    assert response["object"] == "chat.completion"
    assert len(response["choices"]) > 0
    content = response["choices"][0]["message"]["content"]
    assert "likely_cause" in content

    # Test .complete() helper
    content_str = client.complete(sample_messages)
    assert "likely_cause" in content_str


def test_explicit_mock_mode_custom_responses(sample_messages):
    """Test custom mock responses (string, dict, callable)."""
    # Custom string
    client_str = NemotronClient(mock_mode=True, mock_response="custom mock diagnosis")
    assert client_str.complete(sample_messages) == "custom mock diagnosis"

    # Custom dict
    custom_dict = {
        "id": "mock-custom-1",
        "choices": [{"message": {"role": "assistant", "content": "custom json string"}}],
    }
    client_dict = NemotronClient(mock_mode=True, mock_response=custom_dict)
    resp = client_dict.create_chat_completion(sample_messages)
    assert resp == custom_dict
    assert client_dict.complete(sample_messages) == "custom json string"

    # Dynamic callable
    def mock_fn(msgs):
        return f"echo: {len(msgs)} messages"

    client_fn = NemotronClient(mock_mode=True, mock_response=mock_fn)
    assert client_fn.complete(sample_messages) == "echo: 2 messages"


# ==============================================================================
# Network Request & Response Handling Tests (Mocked Transport)
# ==============================================================================

def test_successful_chat_completion(mock_http_response_factory, sample_messages):
    """Test a successful API call and response parsing."""
    expected_response = {
        "id": "chatcmpl-test-12345",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "nvidia/nemotron-3-super-120b-a12b",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"likely_cause": "OOM", "confidence": 0.9}',
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
    }

    mock_resp = mock_http_response_factory(status=200, body_dict=expected_response)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        client = NemotronClient(api_key="test-api-key")
        result = client.create_chat_completion(sample_messages, temperature=0.1)

        assert result == expected_response
        assert mock_urlopen.call_count == 1

        # Verify request parameters
        req_arg = mock_urlopen.call_args[0][0]
        assert req_arg.full_url == "https://api.tokenfactory.nebius.com/v1/chat/completions"
        assert req_arg.headers["Authorization"] == "Bearer test-api-key"
        assert req_arg.headers["Content-type"] == "application/json"

        # Verify payload
        sent_body = json.loads(req_arg.data.decode("utf-8"))
        assert sent_body["model"] == "nvidia/nemotron-3-super-120b-a12b"
        assert sent_body["temperature"] == 0.1
        assert len(sent_body["messages"]) == 2

        # Test .complete() convenience helper
        content = client.complete(sample_messages)
        assert content == '{"likely_cause": "OOM", "confidence": 0.9}'


def test_connection_error_handling(sample_messages):
    """Test handling of network/DNS connection failures."""
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("Name or service not known"),
    ):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronConnectionError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert "Failed to connect to Nebius API" in str(exc_info.value)


def test_timeout_error_handling(sample_messages):
    """Test handling of request timeouts."""
    with patch(
        "urllib.request.urlopen",
        side_effect=socket.timeout("The read operation timed out"),
    ):
        client = NemotronClient(api_key="test-key", timeout=5.0)
        with pytest.raises(NemotronTimeoutError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert "timed out after 5.0 seconds" in str(exc_info.value)

    # Also test URLError wrapping socket.timeout
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError(socket.timeout("timed out")),
    ):
        client = NemotronClient(api_key="test-key", timeout=5.0)
        with pytest.raises(NemotronTimeoutError):
            client.create_chat_completion(sample_messages)


def test_auth_error_http_401(sample_messages):
    """Test handling of HTTP 401 Unauthorized."""
    http_error = urllib.error.HTTPError(
        url="https://api.tokenfactory.nebius.com/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=io.BytesIO(b'{"error": "Invalid API Key"}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        client = NemotronClient(api_key="invalid-key")
        with pytest.raises(NemotronAuthError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert "authentication failed" in str(exc_info.value)
        assert "401" in str(exc_info.value)


def test_auth_error_http_403(sample_messages):
    """Test handling of HTTP 403 Forbidden."""
    http_error = urllib.error.HTTPError(
        url="https://api.tokenfactory.nebius.com/v1/chat/completions",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=io.BytesIO(b'{"error": "Quota or permission denied"}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronAuthError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert "403" in str(exc_info.value)


def test_api_error_http_429_and_500(sample_messages):
    """Test handling of HTTP 429 and HTTP 500 error responses."""
    # HTTP 429 Rate Limit
    error_429 = urllib.error.HTTPError(
        url="https://api.tokenfactory.nebius.com/v1/chat/completions",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b'{"error": "Rate limit exceeded"}'),
    )
    with patch("urllib.request.urlopen", side_effect=error_429):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronAPIError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in exc_info.value.response_body

    # HTTP 500 Internal Error
    error_500 = urllib.error.HTTPError(
        url="https://api.tokenfactory.nebius.com/v1/chat/completions",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=io.BytesIO(b'{"error": "Backend failure"}'),
    )
    with patch("urllib.request.urlopen", side_effect=error_500):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronAPIError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert exc_info.value.status_code == 500


# ==============================================================================
# Malformed Response & Validation Tests
# ==============================================================================

def test_invalid_json_response(mock_http_response_factory, sample_messages):
    """Test handling of non-JSON response body (e.g., HTML error page)."""
    mock_resp = mock_http_response_factory(status=200, raw_body="<html>502 Bad Gateway</html>")

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronResponseError) as exc_info:
            client.create_chat_completion(sample_messages)

        assert "Failed to parse Nebius API response as JSON" in str(exc_info.value)


@pytest.mark.parametrize(
    "malformed_payload",
    [
        "not a dict",
        {},
        {"choices": "not a list"},
        {"choices": []},
        {"choices": [{"no_message": 1}]},
        {"choices": [{"message": "not a dict"}]},
        {"choices": [{"message": {}}]},  # Missing 'content'
    ],
)
def test_malformed_response_structures(
    mock_http_response_factory, sample_messages, malformed_payload
):
    """Test various malformed API response shapes."""
    raw = json.dumps(malformed_payload) if not isinstance(malformed_payload, str) else malformed_payload
    mock_resp = mock_http_response_factory(status=200, raw_body=raw)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronResponseError):
            client.create_chat_completion(sample_messages)


def test_complete_null_content_handling(mock_http_response_factory, sample_messages):
    """Test that null content in message raises NemotronResponseError on complete()."""
    payload = {
        "choices": [{"message": {"role": "assistant", "content": None}}],
    }
    mock_resp = mock_http_response_factory(status=200, body_dict=payload)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronResponseError) as exc_info:
            client.complete(sample_messages)

        assert "null content" in str(exc_info.value)

def test_complete_null_content_with_length_finish_reason(mock_http_response_factory, sample_messages):
    """Test that null content due to length limit gives informative NemotronResponseError."""
    payload = {
        "choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": None}}],
    }
    mock_resp = mock_http_response_factory(status=200, body_dict=payload)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        client = NemotronClient(api_key="test-key")
        with pytest.raises(NemotronResponseError) as exc_info:
            client.complete(sample_messages)

        assert "max_tokens" in str(exc_info.value)
        assert "reasoning tokens" in str(exc_info.value)


def test_invalid_messages_input():
    """Test that invalid messages arguments raise ValueError."""
    client = NemotronClient(api_key="test-key", mock_mode=True)

    with pytest.raises(ValueError):
        client.create_chat_completion([])

    with pytest.raises(ValueError):
        client.create_chat_completion("not a list")
