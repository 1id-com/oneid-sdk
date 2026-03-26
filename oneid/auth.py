"""
OAuth2 token management for the 1id.com SDK.

After enrollment, agents authenticate via hardware challenge-response
(TPM for sovereign/virtual, PIV for portable, Secure Enclave for enclave)
or OAuth2 client_credentials grant (declared tier only).

SECURITY RULE: Hardware-tier identities NEVER fall back to bare
client_credentials. If the hardware device is absent, get_token() raises
HardwareDeviceNotPresentError. This is intentional: a stolen
credentials.json is useless without the physical device.

Token endpoint (F-05 hardened):
  POST https://1id.com/api/v1/auth/token  (declared tier only)
  POST https://1id.com/api/v1/auth/challenge + /verify  (hardware tiers)
  Direct Keycloak token endpoint is blocked by nginx to external clients.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from ._version import USER_AGENT
from .credentials import StoredCredentials, load_credentials
from .exceptions import (
  AuthenticationError,
  HardwareDeviceNotPresentError,
  NetworkError,
  NotEnrolledError,
)
from .identity import Token

logger = logging.getLogger("oneid.auth")

# -- Configuration --
TOKEN_REFRESH_MARGIN_SECONDS = 60
TOKEN_REQUEST_TIMEOUT_SECONDS = 15.0

_TIERS_REQUIRING_HARDWARE_AUTH = frozenset({"sovereign", "portable", "enclave", "virtual"})
_TIERS_USING_TPM = frozenset({"sovereign", "virtual"})
_TIERS_USING_PIV = frozenset({"portable"})
_TIERS_USING_ENCLAVE = frozenset({"enclave"})

# -- Module-level token cache --
_cached_token: Token | None = None


def get_token(
  force_refresh: bool = False,
  credentials: StoredCredentials | None = None,
) -> Token:
  """Get a valid OAuth2 access token, refreshing if needed.

  For hardware-backed tiers (sovereign, portable, virtual), this invokes
  the hardware challenge-response flow via the Go binary. The physical
  device must be present. If it is absent, HardwareDeviceNotPresentError
  is raised -- there is NO fallback to bare client_credentials.

  For declared tier, the standard OAuth2 client_credentials grant is used.

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
      HardwareDeviceNotPresentError: If a hardware tier and device is absent.
      AuthenticationError: If the token request fails.
      NetworkError: If the token endpoint cannot be reached.
  """
  global _cached_token

  if not force_refresh and _cached_token is not None:
    margin = timedelta(seconds=TOKEN_REFRESH_MARGIN_SECONDS)
    if datetime.now(timezone.utc) + margin < _cached_token.expires_at:
      return _cached_token

  if credentials is None:
    credentials = load_credentials()

  if credentials.trust_tier in _TIERS_REQUIRING_HARDWARE_AUTH:
    token = _authenticate_with_hardware_challenge_response(credentials)
    _cached_token = token
    return token

  token = _request_token_via_api_proxy(credentials)
  _cached_token = token
  return token


def _authenticate_with_hardware_challenge_response(credentials: StoredCredentials) -> Token:
  """Route to TPM or PIV challenge-response based on local device type.

  Uses hsm_key_reference to determine which signing path to use, with
  trust_tier as a fallback. This is necessary because an identity can
  have multiple device types (e.g. sovereign tier recovered via PIV on
  a different machine stores trust_tier=sovereign but hsm_key_reference=piv-slot-9a).

  Raises HardwareDeviceNotPresentError on any hardware failure -- never
  falls back to client_credentials.
  """
  local_device_is_piv = (
    getattr(credentials, "hsm_key_reference", None) or ""
  ).startswith("piv-")

  if local_device_is_piv or credentials.trust_tier in _TIERS_USING_PIV:
    try:
      logger.debug("Attempting PIV-based passwordless authentication...")
      return authenticate_with_piv(credentials=credentials)
    except HardwareDeviceNotPresentError:
      raise
    except Exception as piv_error:
      raise HardwareDeviceNotPresentError(
        f"PIV authentication failed and hardware is required for "
        f"{credentials.trust_tier} tier. YubiKey may be absent or "
        f"inaccessible: {piv_error}"
      ) from piv_error

  if credentials.trust_tier in _TIERS_USING_TPM:
    try:
      logger.debug("Attempting TPM-based passwordless authentication...")
      return authenticate_with_tpm(credentials=credentials)
    except HardwareDeviceNotPresentError:
      raise
    except Exception as tpm_error:
      raise HardwareDeviceNotPresentError(
        f"TPM authentication failed and hardware is required for "
        f"{credentials.trust_tier} tier. Device may be absent or "
        f"inaccessible: {tpm_error}"
      ) from tpm_error

  if credentials.trust_tier in _TIERS_USING_ENCLAVE:
    try:
      logger.debug("Attempting Secure Enclave passwordless authentication...")
      return authenticate_with_enclave(credentials=credentials)
    except HardwareDeviceNotPresentError:
      raise
    except Exception as enclave_error:
      raise HardwareDeviceNotPresentError(
        f"Secure Enclave authentication failed and hardware is required for "
        f"{credentials.trust_tier} tier. Enclave may be absent or "
        f"inaccessible: {enclave_error}"
      ) from enclave_error

  raise HardwareDeviceNotPresentError(
    f"Trust tier '{credentials.trust_tier}' requires hardware but no "
    f"supported authentication method is available."
  )


def _request_token_via_api_proxy(credentials: StoredCredentials) -> Token:
  """Request a new access token via the 1id API token proxy.

  For declared-tier identities, this is the only permitted token path.
  The API proxy (POST /api/v1/auth/token) validates that the identity
  is not hardware-backed before forwarding to Keycloak. This prevents
  stolen credentials.json from obtaining hardware-tier JWTs.

  Args:
      credentials: The stored enrollment credentials.

  Returns:
      A new Token object.

  Raises:
      AuthenticationError: If the token request fails (401, 403, etc.).
      NetworkError: If the token endpoint cannot be reached.
  """
  api_base = getattr(credentials, "api_base_url", None) or "https://1id.com"
  token_endpoint = f"{api_base.rstrip('/')}/api/v1/auth/token"

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
          "User-Agent": USER_AGENT,
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
    try:
      error_body = response.json()
      error_description = (
        error_body.get("error", {}).get("message")
        or error_body.get("error_description")
        or error_body.get("error", "Unknown error")
      )
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

  if "ok" in token_response and "data" in token_response:
    token_response = token_response["data"]

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
    ak_handle = credentials.hsm_key_reference or ""

  if api_base_url is None:
    api_base_url = credentials.api_base_url

  challenge_url = f"{api_base_url}/api/v1/auth/challenge"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      challenge_response = http_client.post(
        challenge_url,
        json={"identity_id": identity_id, "device_type": "tpm"},
        headers={"User-Agent": USER_AGENT},
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
        headers={"User-Agent": USER_AGENT},
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


# ---------------------------------------------------------------------------
# PIV-backed passwordless authentication (portable tier)
# ---------------------------------------------------------------------------

def authenticate_with_piv(
  identity_id: str | None = None,
  api_base_url: str | None = None,
  credentials: StoredCredentials | None = None,
) -> Token:
  """Authenticate using a PIV device (YubiKey) -- passwordless sign-in.

  Same challenge-response flow as TPM but uses PIV slot 9a ECDSA signing.
  No PIN, no elevation, no human interaction required.

  Args:
      identity_id: The 1id internal ID. If None, loaded from credentials.
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

  if credentials is None:
    credentials = load_credentials()

  if identity_id is None:
    identity_id = credentials.client_id

  if api_base_url is None:
    api_base_url = credentials.api_base_url

  challenge_url = f"{api_base_url}/api/v1/auth/challenge"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      challenge_response = http_client.post(
        challenge_url,
        json={"identity_id": identity_id, "device_type": "piv"},
        headers={"User-Agent": USER_AGENT},
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

  logger.debug("Received PIV auth challenge: %s", challenge_id)

  from .helper import sign_challenge_with_piv

  sign_result = sign_challenge_with_piv(nonce_b64=nonce_b64)
  signature_b64 = sign_result.get("signature_b64", "")

  if not signature_b64:
    raise AuthenticationError("PIV signing returned empty signature")

  logger.debug("PIV nonce signed successfully, verifying with server...")

  verify_url = f"{api_base_url}/api/v1/auth/verify"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      verify_response = http_client.post(
        verify_url,
        json={
          "challenge_id": challenge_id,
          "signature_b64": signature_b64,
        },
        headers={"User-Agent": USER_AGENT},
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
    raise AuthenticationError(f"PIV authentication failed: {error_msg}")

  verify_data = verify_response.json().get("data", {})

  if not verify_data.get("authenticated"):
    raise AuthenticationError("Server did not confirm PIV authentication")

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
      "PIV authentication successful for %s (handle: %s)",
      identity_id,
      verify_data.get("identity", {}).get("handle", "?"),
    )
    return token
  else:
    raise AuthenticationError(
      "PIV signature verified but no tokens were issued. "
      "The Keycloak token endpoint may be unavailable."
    )


# ---------------------------------------------------------------------------
# Secure Enclave passwordless authentication (enclave tier)
# ---------------------------------------------------------------------------

def authenticate_with_enclave(
  identity_id: str | None = None,
  api_base_url: str | None = None,
  credentials: StoredCredentials | None = None,
) -> Token:
  """Authenticate using the Apple Secure Enclave -- passwordless sign-in.

  Same challenge-response flow as TPM/PIV but uses the P-256 key stored
  in the Secure Enclave via the oneid-se-helper binary.

  Args:
      identity_id: The 1id internal ID. If None, loaded from credentials.
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

  if credentials is None:
    credentials = load_credentials()

  if identity_id is None:
    identity_id = credentials.client_id

  if api_base_url is None:
    api_base_url = credentials.api_base_url

  challenge_url = f"{api_base_url}/api/v1/auth/challenge"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      challenge_response = http_client.post(
        challenge_url,
        json={"identity_id": identity_id, "device_type": "enclave"},
        headers={"User-Agent": USER_AGENT},
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

  logger.debug("Received enclave auth challenge: %s", challenge_id)

  from .helper import sign_challenge_with_enclave

  sign_result = sign_challenge_with_enclave(nonce_b64=nonce_b64)
  signature_b64 = sign_result.get("signature_b64", "")

  if not signature_b64:
    raise AuthenticationError("Secure Enclave signing returned empty signature")

  logger.debug("Enclave nonce signed successfully, verifying with server...")

  verify_url = f"{api_base_url}/api/v1/auth/verify"

  try:
    with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
      verify_response = http_client.post(
        verify_url,
        json={
          "challenge_id": challenge_id,
          "signature_b64": signature_b64,
        },
        headers={"User-Agent": USER_AGENT},
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
    raise AuthenticationError(f"Secure Enclave authentication failed: {error_msg}")

  verify_data = verify_response.json().get("data", {})

  if not verify_data.get("authenticated"):
    raise AuthenticationError("Server did not confirm Secure Enclave authentication")

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
      "Secure Enclave authentication successful for %s (handle: %s)",
      identity_id,
      verify_data.get("identity", {}).get("handle", "?"),
    )
    return token
  else:
    raise AuthenticationError(
      "Secure Enclave signature verified but no tokens were issued. "
      "The Keycloak token endpoint may be unavailable."
    )
