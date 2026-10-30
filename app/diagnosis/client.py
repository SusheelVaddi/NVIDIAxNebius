"""Client for NVIDIA Nemotron hosted on Nebius Token Factory.

Provides an OpenAI-compatible HTTP client for chat completions with
explicit error handling, configurable timeouts, security protections,
and an explicit mock mode for local testing and offline workflows.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Union

from app.config import (
    DEFAULT_NEBIUS_API_BASE,
    DEFAULT_NEBIUS_MODEL_ID,
    DEFAULT_NEBIUS_TIMEOUT_SECONDS,
    get_nebius_api_base,
    get_nebius_api_key,
    get_nebius_model_id,
    get_nebius_timeout_seconds,
    is_nebius_mock_mode,
)
from app.diagnosis.exceptions import (
    NemotronAPIError,
    NemotronAuthError,
    NemotronClientError,
    NemotronConnectionError,
    NemotronResponseError,
    NemotronTimeoutError,
)

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = DEFAULT_NEBIUS_API_BASE
DEFAULT_MODEL_ID = DEFAULT_NEBIUS_MODEL_ID
DEFAULT_TIMEOUT_SECONDS = DEFAULT_NEBIUS_TIMEOUT_SECONDS


def _mask_secret(secret: Optional[str]) -> str:
    """Safely mask a secret for logging or representation without leaking characters."""
    if not secret:
        return "None"
    if len(secret) <= 8:
        return "***"
    return f"{secret[:4]}...{secret[-4:]}"


class NemotronClient:
    """Reusable API client for NVIDIA Nemotron models on Nebius Token Factory.

    Attributes:
        base_url: Base URL of the Nebius Token Factory endpoint.
        model_id: Model identifier (e.g., 'nvidia/nemotron-3-super-120b-a12b').
        timeout: Request timeout in seconds.
        mock_mode: Whether mock mode is explicitly active.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        timeout: Optional[float] = None,
        mock_mode: Optional[bool] = None,
        mock_response: Optional[Union[Dict[str, Any], str, Callable[..., Any]]] = None,
    ) -> None:
        """Initialize the NemotronClient.

        Configuration is read from arguments, falling back to environment variables:
        - API Key: NEBIUS_API_KEY (aliases: NEMOTRON_API_KEY, NEBIUS_TOKEN_FACTORY_API_KEY)
        - Base URL: NEBIUS_API_BASE (aliases: NEBIUS_BASE_URL, NEBIUS_TOKEN_FACTORY_BASE_URL)
        - Model ID: NEBIUS_MODEL_ID (aliases: NEBIUS_MODEL, NEMOTRON_MODEL)
        - Timeout: NEBIUS_TIMEOUT_SECONDS (alias: NEMOTRON_TIMEOUT_SECONDS)
        - Mock Mode: NEBIUS_MOCK_MODE (alias: NEMOTRON_MOCK_MODE)

        Args:
            api_key: Nebius Token Factory API key.
            base_url: Base URL for OpenAI-compatible completions.
            model_id: Model identifier.
            timeout: Request timeout in seconds.
            mock_mode: If True, returns mock responses without network calls.
            mock_response: Optional custom mock response or callable for mock mode.
        """
        # Resolve API Key (never hardcoded)
        resolved_key = api_key
        if resolved_key is None:
            resolved_key = get_nebius_api_key()
        self._api_key: Optional[str] = resolved_key.strip() if resolved_key else None

        # Resolve Base URL
        resolved_base_url = base_url
        if resolved_base_url is None:
            resolved_base_url = get_nebius_api_base()
        self.base_url: str = resolved_base_url.rstrip("/")

        # Resolve Model ID
        resolved_model_id = model_id
        if resolved_model_id is None:
            resolved_model_id = get_nebius_model_id()
        self.model_id: str = resolved_model_id

        # Resolve Timeout
        resolved_timeout = timeout
        if resolved_timeout is None:
            resolved_timeout = get_nebius_timeout_seconds()
        self.timeout: float = max(0.1, float(resolved_timeout))

        # Resolve Mock Mode
        resolved_mock_mode = mock_mode
        if resolved_mock_mode is None:
            resolved_mock_mode = is_nebius_mock_mode()
        self.mock_mode: bool = bool(resolved_mock_mode)

        self._mock_response: Optional[Union[Dict[str, Any], str, Callable[..., Any]]] = (
            mock_response
        )

    @property
    def api_key(self) -> Optional[str]:
        """Return the configured API key."""
        return self._api_key

    def set_mock_response(
        self, response: Optional[Union[Dict[str, Any], str, Callable[..., Any]]]
    ) -> None:
        """Set or update the custom mock response used in mock mode."""
        self._mock_response = response

    def __repr__(self) -> str:
        """Return a safe representation that never reveals secrets."""
        return (
            f"NemotronClient("
            f"base_url={self.base_url!r}, "
            f"model_id={self.model_id!r}, "
            f"timeout={self.timeout}, "
            f"mock_mode={self.mock_mode}, "
            f"api_key={_mask_secret(self._api_key)!r})"
        )

    def create_chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Send a chat completion request to Nebius Token Factory.

        Args:
            messages: List of chat messages, each with 'role' and 'content'.
            temperature: Sampling temperature (e.g. 0.2 for deterministic diagnosis).
            max_tokens: Maximum tokens in generated completion.
            **kwargs: Extra parameters passed to the OpenAI-compatible endpoint.

        Returns:
            Parsed response JSON dictionary from the Nebius API.

        Raises:
            ValueError: If messages is empty or invalid.
            NemotronAuthError: If API credentials are missing or invalid (HTTP 401/403).
            NemotronConnectionError: If network connection fails.
            NemotronTimeoutError: If the request times out.
            NemotronAPIError: If the Nebius API returns a non-2xx status code.
            NemotronResponseError: If the response is not valid JSON or lacks required fields.
        """
        if not messages or not isinstance(messages, list):
            raise ValueError("Messages must be a non-empty list of message dicts.")

        # If mock mode is explicitly enabled, return the mock response directly
        if self.mock_mode:
            return self._build_mock_response(messages)

        # Explicit failure when API credentials are missing (do not silently substitute mock)
        if not self._api_key:
            raise NemotronAuthError(
                "API credentials missing: set the 'NEBIUS_API_KEY' environment variable "
                "or supply 'api_key' to NemotronClient. "
                "Mock mode is disabled. To enable mock mode for testing, pass 'mock_mode=True'."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "IncidentRecoverySystem-NemotronClient/1.0",
        }

        payload: Dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        payload.update(kwargs)

        try:
            body_bytes = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError) as err:
            raise NemotronClientError(f"Failed to serialize request payload: {err}") from err

        raw_response = self._send_http_request(
            endpoint=endpoint,
            headers=headers,
            body=body_bytes,
            timeout=self.timeout,
        )

        return self._parse_and_validate_response(raw_response)

    def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        """Convenience method returning the text content of the completion.

        Args:
            messages: List of chat messages.
            temperature: Sampling temperature.
            max_tokens: Optional token limit.
            **kwargs: Extra arguments forwarded to create_chat_completion.

        Returns:
            The string content of the assistant message.
        """
        response_dict = self.create_chat_completion(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        choices = response_dict.get("choices", [])
        content = choices[0]["message"]["content"] if choices else None
        if content is None:
            finish_reason = choices[0].get("finish_reason") if choices else None
            msg = "Nebius API returned null content in choices[0].message.content."
            if finish_reason == "length":
                msg += " Generation reached max_tokens before completing content (reasoning tokens may have consumed token budget)."
            raise NemotronResponseError(msg)
        return str(content)

    def _send_http_request(
        self,
        endpoint: str,
        headers: Dict[str, str],
        body: bytes,
        timeout: float,
    ) -> str:
        """Execute the HTTP request using standard library urllib with strict error handling."""
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            error_body = ""
            try:
                error_body = err.read().decode("utf-8")
            except Exception:
                pass

            if err.code in (401, 403):
                raise NemotronAuthError(
                    f"Nebius API authentication failed (HTTP {err.code}): {error_body}"
                ) from err

            raise NemotronAPIError(
                message=f"Nebius API returned error HTTP {err.code}: {error_body}",
                status_code=err.code,
                response_body=error_body,
            ) from err
        except urllib.error.URLError as err:
            reason = err.reason
            if isinstance(reason, socket.timeout) or "timed out" in str(reason).lower():
                raise NemotronTimeoutError(
                    f"Request to Nebius API timed out after {timeout} seconds: {reason}"
                ) from err
            raise NemotronConnectionError(
                f"Failed to connect to Nebius API endpoint '{endpoint}': {reason}"
            ) from err
        except (socket.timeout, TimeoutError) as err:
            raise NemotronTimeoutError(
                f"Request to Nebius API timed out after {timeout} seconds"
            ) from err
        except Exception as err:
            raise NemotronClientError(
                f"Unexpected error communicating with Nebius API: {err}"
            ) from err

    def _parse_and_validate_response(self, raw_body: str) -> Dict[str, Any]:
        """Parse raw response text as JSON and validate OpenAI completion format."""
        try:
            data = json.loads(raw_body)
        except Exception as err:
            raise NemotronResponseError(
                f"Failed to parse Nebius API response as JSON: {err}. Raw body: {raw_body[:200]}"
            ) from err

        if not isinstance(data, dict):
            raise NemotronResponseError(
                f"Malformed response from Nebius API: expected JSON object, got {type(data).__name__}"
            )

        choices = data.get("choices")
        if not isinstance(choices, list) or len(choices) == 0:
            raise NemotronResponseError(
                "Malformed response from Nebius API: missing or empty 'choices' list."
            )

        first_choice = choices[0]
        if not isinstance(first_choice, dict) or "message" not in first_choice:
            raise NemotronResponseError(
                "Malformed response from Nebius API: choice[0] missing 'message' object."
            )

        message = first_choice.get("message")
        if not isinstance(message, dict) or "content" not in message:
            raise NemotronResponseError(
                "Malformed response from Nebius API: choice[0].message missing 'content' field."
            )

        return data

    def _build_mock_response(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Generate a simulated response when mock_mode is active."""
        if self._mock_response is not None:
            if callable(self._mock_response):
                result = self._mock_response(messages)
            else:
                result = self._mock_response

            if isinstance(result, dict):
                return result
            if isinstance(result, str):
                return {
                    "id": "mock-nemotron-custom",
                    "object": "chat.completion",
                    "model": self.model_id,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": result,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
                }

        # Default simulated Nemotron response
        default_content = (
            '{"likely_cause": "Database connection pool exhaustion caused by unindexed queries", '
            '"evidence": ["Active connections reached pool limit of 100", "API error rate spiked to 45%"], '
            '"confidence": 0.88, '
            '"recommended_action_id": "restart_service", '
            '"rationale": "Restarting the service immediately clears leaked and stalled connections.", '
            '"uncertainty_or_notes": "If connection pool exhausts again within 5 minutes, scale_service is advised."}'
        )

        return {
            "id": "mock-nemotron-default",
            "object": "chat.completion",
            "model": self.model_id,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": default_content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 120,
                "completion_tokens": 65,
                "total_tokens": 185,
            },
        }
