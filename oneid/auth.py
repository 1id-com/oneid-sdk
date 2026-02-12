"""
OAuth2 token management for the 1id.com SDK.

After enrollment, agents authenticate using standard OAuth2
client_credentials grant. No TPM operations needed for daily use.

This module handles:
- Token acquisition (client_credentials grant)
- Token caching (in-memory, with expiry awareness)
- Token refresh
- Authorization header formatting

The token endpoint is Keycloak:
  POST https://1id.com/realms/agents/protocol/openid-connect/token
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from .credentials import StoredCredentials, load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError
from .identity import Token

logger = logging.getLogger("oneid.auth")

# -- Configuration --
TOKEN_REFRESH_MARGIN_SECONDS = 60  # Refresh tokens this many seconds before expiry
TOKEN_REQUEST_TIMEOUT_SECONDS = 15.0

# -- Module-level token cache --
_cached_token: Token | None = None


def get_token(
  force_refresh: bool = False,
  credentials: StoredCredentials | None = None,
) -> Token:
  """Get a valid OAuth2 access token, refreshing if needed.

  This is the primary authentication method for daily use. It uses
  the OAuth2 client_credentials grant with the credentials stored
  during enrollment.

  Tokens are cached in memory and automatically refreshed when they
  are within TOKEN_REFRESH_MARGIN_SECONDS of expiry.

  Args:
      force_refresh: If True, always fetch a new token even if the
                     cached one is still valid.
      credentials: Optional pre-loaded credentials. If None, loads
                   from the credentials file.

  Returns:
      A valid Token object.

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token request fails.
      NetworkError: If the token endpoint cannot be reached.
  """
  global _cached_token

  # Check if cached token is still valid (with margin)
  if not force_refresh and _cached_token is not None:
    margin = timedelta(seconds=TOKEN_REFRESH_MARGIN_SECONDS)
    if datetime.now(timezone.utc) + margin < _cached_token.expires_at:
      return _cached_token

  # Load credentials
  if credentials is None:
    credentials = load_credentials()

  # Request a new token
  token = _request_token_from_keycloak(credentials)
  _cached_token = token

  return token


def _request_token_from_keycloak(credentials: StoredCredentials) -> Token:
  """Request a new access token from Keycloak using client_credentials grant.

  Args:
      credentials: The stored enrollment credentials.

  Returns:
      A new Token object.

  Raises:
      AuthenticationError: If the token request fails (401, 403, etc.).
      NetworkError: If the token endpoint cannot be reached.
  """
  token_endpoint = credentials.token_endpoint

  request_body = {
    "grant_type": "client_credentials",
    "client_id": credentials.client_id,
    "client_secret": credentials.client_secret,
  }

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      response = http_client.post(
        token_endpoint,
        data=request_body,
        headers={
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "oneid-sdk-python/0.1.0",
        },
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(
      f"Could not connect to token endpoint {token_endpoint}: {connection_error}"
    ) from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(
      f"Token request to {token_endpoint} timed out: {timeout_error}"
    ) from timeout_error
  except httpx.HTTPError as http_error:
    raise NetworkError(
      f"HTTP error requesting token from {token_endpoint}: {http_error}"
    ) from http_error

  if response.status_code != 200:
    # Keycloak returns error details in JSON
    try:
      error_body = response.json()
      error_description = error_body.get("error_description", error_body.get("error", "Unknown error"))
    except Exception:
      error_description = f"HTTP {response.status_code}: {response.text[:200]}"

    raise AuthenticationError(
      f"Token request failed: {error_description}"
    )

  try:
    token_response = response.json()
  except Exception as json_error:
    raise AuthenticationError(
      f"Invalid JSON in token response: {json_error}"
    ) from json_error

  # Parse the standard OAuth2 token response
  access_token = token_response.get("access_token")
  if not access_token:
    raise AuthenticationError("Token response missing 'access_token' field")

  expires_in_seconds = token_response.get("expires_in", 3600)
  expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

  return Token(
    access_token=access_token,
    token_type=token_response.get("token_type", "Bearer"),
    expires_at=expires_at,
    refresh_token=token_response.get("refresh_token"),
  )


def clear_cached_token() -> None:
  """Clear the in-memory cached token.

  Useful for testing or when credentials have changed.
  """
  global _cached_token
  _cached_token = None
