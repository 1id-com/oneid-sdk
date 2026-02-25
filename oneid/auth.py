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

  This is the primary authentication method for daily use.

  For sovereign and virtual tier agents with a TPM, this automatically
  uses TPM challenge-response authentication (no passwords transmitted).
  For all other tiers, it uses the standard OAuth2 client_credentials
  grant. If TPM auth fails, it falls back to client_credentials.

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

  _TIERS_SUPPORTING_TPM_AUTH = ("sovereign", "virtual")
  this_agent_has_tpm_key = (
    credentials.trust_tier in _TIERS_SUPPORTING_TPM_AUTH
    and credentials.hsm_key_reference is not None
  )

  if this_agent_has_tpm_key:
    try:
      logger.debug("Attempting TPM-based passwordless authentication...")
      token = authenticate_with_tpm(credentials=credentials)
      _cached_token = token
      return token
    except Exception as tpm_auth_error:
      logger.info(
        "TPM auth failed (%s), falling back to client_credentials grant",
        tpm_auth_error,
      )

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


# ---------------------------------------------------------------------------
# TPM-backed passwordless authentication (sovereign/virtual tier)
# ---------------------------------------------------------------------------

def authenticate_with_tpm(
  identity_id: str | None = None,
  ak_handle: str | None = None,
  api_base_url: str | None = None,
  credentials: StoredCredentials | None = None,
) -> Token:
  """Authenticate using the TPM -- passwordless, zero-elevation sign-in.

  This is the "OAuth for agents" flow:
    1. Requests a challenge nonce from the server
    2. Signs it with the TPM AK (no elevation needed)
    3. Sends the signature back to the server
    4. Server verifies and issues a JWT

  No passwords, no client_secret transmitted, no UAC prompt.
  The AK private key never leaves the TPM chip.

  Args:
      identity_id: The 1id internal ID. If None, loaded from credentials.
      ak_handle: The AK persistent handle (hex). If None, loaded from credentials.
      api_base_url: Base URL for the 1id API. If None, loaded from credentials.
      credentials: Pre-loaded credentials. If None, loaded from file.

  Returns:
      A valid Token object.

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the challenge-response fails.
      NetworkError: If the server cannot be reached.
  """
  global _cached_token

  # Load credentials if not provided
  if credentials is None:
    credentials = load_credentials()

  if identity_id is None:
    identity_id = credentials.client_id  # client_id IS the identity ID

  if ak_handle is None:
    ak_handle = credentials.hsm_key_reference
    if not ak_handle:
      raise AuthenticationError(
        "No AK handle found in credentials. TPM authentication requires "
        "a sovereign or virtual tier enrollment with a TPM."
      )

  if api_base_url is None:
    api_base_url = credentials.api_base_url

  # Step 1: Request a challenge nonce from the server
  challenge_url = f"{api_base_url}/api/v1/auth/challenge"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      challenge_response = http_client.post(
        challenge_url,
        json={"identity_id": identity_id},
        headers={"User-Agent": "oneid-sdk-python/0.1.0"},
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(
      f"Could not connect to {challenge_url}: {connection_error}"
    ) from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(
      f"Challenge request to {challenge_url} timed out: {timeout_error}"
    ) from timeout_error

  if challenge_response.status_code != 200:
    try:
      error_body = challenge_response.json()
      error_msg = error_body.get("error", {}).get("message", f"HTTP {challenge_response.status_code}")
    except Exception:
      error_msg = f"HTTP {challenge_response.status_code}"
    raise AuthenticationError(f"Challenge request failed: {error_msg}")

  challenge_data = challenge_response.json().get("data", {})
  challenge_id = challenge_data.get("challenge_id")
  nonce_b64 = challenge_data.get("nonce_b64")

  if not challenge_id or not nonce_b64:
    raise AuthenticationError("Server returned incomplete challenge response")

  logger.debug("Received auth challenge: %s", challenge_id)

  # Step 2: Sign the nonce with the TPM AK (NO elevation needed)
  from .helper import sign_challenge_with_tpm

  sign_result = sign_challenge_with_tpm(nonce_b64=nonce_b64, ak_handle=ak_handle)
  signature_b64 = sign_result.get("signature_b64", "")

  if not signature_b64:
    raise AuthenticationError("TPM signing returned empty signature")

  logger.debug("Nonce signed successfully, verifying with server...")

  # Step 3: Send the signature to the server for verification
  verify_url = f"{api_base_url}/api/v1/auth/verify"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      verify_response = http_client.post(
        verify_url,
        json={
          "challenge_id": challenge_id,
          "signature_b64": signature_b64,
        },
        headers={"User-Agent": "oneid-sdk-python/0.1.0"},
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(
      f"Could not connect to {verify_url}: {connection_error}"
    ) from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(
      f"Verify request to {verify_url} timed out: {timeout_error}"
    ) from timeout_error

  if verify_response.status_code != 200:
    try:
      error_body = verify_response.json()
      error_msg = error_body.get("error", {}).get("message", f"HTTP {verify_response.status_code}")
    except Exception:
      error_msg = f"HTTP {verify_response.status_code}"
    raise AuthenticationError(f"TPM authentication failed: {error_msg}")

  verify_data = verify_response.json().get("data", {})

  if not verify_data.get("authenticated"):
    raise AuthenticationError("Server did not confirm authentication")

  # Extract token from response
  tokens = verify_data.get("tokens")
  if tokens and tokens.get("access_token"):
    expires_in_seconds = tokens.get("expires_in", 3600)
    token = Token(
      access_token=tokens["access_token"],
      token_type=tokens.get("token_type", "Bearer"),
      expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds),
      refresh_token=tokens.get("refresh_token"),
    )
    _cached_token = token
    logger.info(
      "TPM authentication successful for %s (handle: %s)",
      identity_id,
      verify_data.get("identity", {}).get("handle", "?"),
    )
    return token
  else:
    raise AuthenticationError(
      "TPM signature verified but no tokens were issued. "
      "The Keycloak token endpoint may be unavailable."
    )
