"""Exceptions for the Nemotron API client and diagnosis engine."""

from __future__ import annotations

from typing import Optional


class NemotronClientError(Exception):
    """Base exception for all Nemotron API client errors."""


class NemotronAuthError(NemotronClientError):
    """Raised when API credentials are missing, invalid, or rejected (401/403)."""


class NemotronConnectionError(NemotronClientError):
    """Raised when network connection to the Nebius API fails."""


class NemotronTimeoutError(NemotronClientError):
    """Raised when an API request times out."""


class NemotronAPIError(NemotronClientError):
    """Raised when the Nebius API returns a non-2xx HTTP status code."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class NemotronResponseError(NemotronClientError):
    """Raised when the API returns an invalid JSON or malformed response structure."""


class DiagnosisError(Exception):
    """Raised when incident diagnosis fails due to invalid output, validation, or processing error."""
