"""
OAuth2 token management for the 1id.com SDK.

After enrollment, agents authenticate via hardware challenge-response
(TPM for sovereign/virtual, PIV for portable, Secure Enclave for enclave)
or, for the declared tier, the same challenge signed by the enrolled software key.

SECURITY RULE: Hardware-tier identities NEVER fall back to bare
client_credentials. If the hardware device is absent, get_token() raises
HardwareDeviceNotPresentError. This is intentional: a stolen
credentials.json is useless without the physical device.

Token endpoint (F-05 hardened):
  POST https://1id.com/api/v1/auth/challenge + /verify  (every tier; declared signs
  with its enrolled software key -- no static client_secret is ever sent)
  Direct Keycloak token endpoint is blocked by nginx to external clients.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

from . import _http as httpx  # stdlib-backed drop-in (no httpx dependency)

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
# Overridable via ONEID_HTTP_TIMEOUT_SECONDS: some real agent hosts reach
# the Issuer over slow/proxied/split-DNS links (REAL_USER_ROADBLOCKS R-U 3)
# where the default 15s is too tight for the TPM challenge round trip.
TOKEN_REQUEST_TIMEOUT_SECONDS = float(
  os.environ.get("ONEID_HTTP_TIMEOUT_SECONDS", "15.0"))

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

  For declared tier, the challenge is signed with the enrolled software key
  (Binding-Proof Authentication); the client_secret is never sent.

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

  token = authenticate_with_declared_software_key(credentials=credentials)
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


def _convert_ecdsa_signature_to_rfc9421_raw_if_der_encoded(signature: bytes) -> bytes:
  """PIV, Secure Enclave and `cryptography` return ECDSA P-256 signatures as
  ASN.1 DER; RFC 9421 ecdsa-p256-sha256 wants the 64-octet r||s form."""
  from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
  try:
    r, s = decode_dss_signature(signature)
    signature_is_der = encode_dss_signature(r, s) == signature
  except ValueError:
    signature_is_der = False
  if not signature_is_der:
    if len(signature) != 64:
      raise AuthenticationError("ECDSA P-256 signature is neither DER nor 64-octet r||s")
    return signature
  return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def build_airs_request_signer_for_enrolled_key(
  enrolled_key_kind: str,
  ak_handle: str = "",
  software_private_key_pem: str | None = None,
):
  """Return a function that signs an RFC 9421 signature base with the
  enrolled key that authenticates this identity (registry-04 sender
  constraint, OWN-038): "tpm" (the AK, via oneid-enroll >= 2.2.0, which
  hashes inputs over 1024 bytes with a TPM hash sequence), "piv" (the slot
  9a key), "enclave" (the Secure Enclave key) or "declared" (the enrolled
  software key). Every call reaches the hardware; nothing is cached."""
  import base64 as _base64

  if enrolled_key_kind == "tpm":
    def sign_with_tpm_attestation_key(signature_base: bytes) -> bytes:
      from .helper import sign_challenge_with_tpm
      result = sign_challenge_with_tpm(
        nonce_b64=_base64.b64encode(signature_base).decode("ascii"), ak_handle=ak_handle)
      return _base64.b64decode(result["signature_b64"])
    return sign_with_tpm_attestation_key
  if enrolled_key_kind == "piv":
    def sign_with_piv_slot_key(signature_base: bytes) -> bytes:
      from .helper import sign_challenge_with_piv
      result = sign_challenge_with_piv(nonce_b64=_base64.b64encode(signature_base).decode("ascii"))
      return _convert_ecdsa_signature_to_rfc9421_raw_if_der_encoded(_base64.b64decode(result["signature_b64"]))
    return sign_with_piv_slot_key
  if enrolled_key_kind == "enclave":
    def sign_with_secure_enclave_key(signature_base: bytes) -> bytes:
      from .helper import sign_challenge_with_enclave
      result = sign_challenge_with_enclave(nonce_b64=_base64.b64encode(signature_base).decode("ascii"))
      return _convert_ecdsa_signature_to_rfc9421_raw_if_der_encoded(_base64.b64decode(result["signature_b64"]))
    return sign_with_secure_enclave_key
  if enrolled_key_kind == "declared":
    if not software_private_key_pem:
      raise AuthenticationError("declared identity has no enrolled software key to sign requests with")

    def sign_with_declared_software_key(signature_base: bytes) -> bytes:
      from cryptography.hazmat.primitives.asymmetric import ec
      from cryptography.hazmat.primitives import serialization
      signature, _public_key_pem = _sign_nonce_with_enrolled_software_key(software_private_key_pem, signature_base)
      private_key = serialization.load_pem_private_key(software_private_key_pem.encode("utf-8"), password=None)
      if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return _convert_ecdsa_signature_to_rfc9421_raw_if_der_encoded(signature)
      return signature
    return sign_with_declared_software_key
  raise AuthenticationError("unknown enrolled key kind %r" % enrolled_key_kind)


def _server_clock_offset_seconds(access_token: str) -> float:
  from .airs_http_message_signatures import server_clock_offset_seconds_from_access_token
  return server_clock_offset_seconds_from_access_token(access_token)


def confirmation_jwk_from_access_token(access_token: str):
  """The token's cnf.jwk (read without verification: the SDK only uses it
  as the RFC 9421 keyid; relying parties verify the token themselves)."""
  import base64 as _base64
  import json as _json
  try:
    payload_segment = access_token.split(".")[1]
    payload = _json.loads(_base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))
    confirmation = payload.get("cnf") or {}
    return confirmation.get("jwk") if isinstance(confirmation.get("jwk"), dict) else None
  except (IndexError, ValueError, AttributeError):
    return None


def _sign_nonce_with_enrolled_software_key(private_key_pem: str, nonce: bytes) -> tuple:
  """Return (signature, public_key_pem) for the declared-tier challenge."""
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

  private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
  if isinstance(private_key, ec.EllipticCurvePrivateKey):
    signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
  elif isinstance(private_key, rsa.RSAPrivateKey):
    signature = private_key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())
  elif isinstance(private_key, ed25519.Ed25519PrivateKey):
    signature = private_key.sign(nonce)
  else:
    raise AuthenticationError(f"Unsupported enrolled key type: {type(private_key).__name__}")
  public_key_pem = private_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
  return signature, public_key_pem


def authenticate_with_declared_software_key(
  credentials: StoredCredentials | None = None,
) -> Token:
  """Declared-tier Binding-Proof Authentication: sign the server's nonce with
  the software key enrolled for this identity (the Registrar checks it against
  the key's RFC 7638 thumbprint recorded at enrollment). No static
  client_secret is sent (registry draft, "Client Credentials Grant").

  Raises:
      AuthenticationError: no enrolled key on this machine, or the proof fails.
      NetworkError: If the server cannot be reached.
  """
  import base64

  global _cached_token

  if credentials is None:
    credentials = load_credentials()
  if not credentials.private_key_pem:
    raise AuthenticationError(
      "This declared identity has no enrolled signing key in its credentials file, "
      "so it cannot perform binding-proof authentication."
    )
  api_base_url = (getattr(credentials, "api_base_url", None) or "https://1id.com").rstrip("/")
  challenge_url = f"{api_base_url}/api/v1/auth/challenge"
  verify_url = f"{api_base_url}/api/v1/auth/verify"

  def post_json(url, body, what):
    try:
      with httpx.Client(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
        response = http_client.post(url, json=body, headers={"User-Agent": USER_AGENT})
    except httpx.ConnectError as connection_error:
      raise NetworkError(f"Could not connect to {url}: {connection_error}") from connection_error
    except httpx.TimeoutException as timeout_error:
      raise NetworkError(f"{what} request to {url} timed out: {timeout_error}") from timeout_error
    if response.status_code != 200:
      try:
        error_msg = response.json().get("error", {}).get("message", f"HTTP {response.status_code}")
      except Exception:
        error_msg = f"HTTP {response.status_code}"
      raise AuthenticationError(f"{what} failed: {error_msg}")
    return response.json().get("data", {})

  challenge_data = post_json(
    challenge_url, {"identity_id": credentials.client_id, "device_type": "declared"}, "Challenge request")
  challenge_id = challenge_data.get("challenge_id")
  nonce_b64 = challenge_data.get("nonce_b64")
  if not challenge_id or not nonce_b64:
    raise AuthenticationError("Server returned incomplete challenge response")

  signature, public_key_pem = _sign_nonce_with_enrolled_software_key(
    credentials.private_key_pem, base64.b64decode(nonce_b64))
  verify_data = post_json(verify_url, {
    "challenge_id": challenge_id,
    "signature_b64": base64.b64encode(signature).decode("ascii"),
    "public_key_pem": public_key_pem,
  }, "Declared-tier binding-proof authentication")

  tokens = verify_data.get("tokens") if verify_data.get("authenticated") else None
  if not tokens or not tokens.get("access_token"):
    raise AuthenticationError("Binding proof verified but no tokens were issued")
  token = Token(
    access_token=tokens["access_token"],
    token_type=tokens.get("token_type", "Bearer"),
    expires_at=datetime.now(timezone.utc) + timedelta(seconds=tokens.get("expires_in", 3600)),
    refresh_token=tokens.get("refresh_token"),
    airs_request_signer=build_airs_request_signer_for_enrolled_key(
      "declared", software_private_key_pem=credentials.private_key_pem),
    confirmation_jwk=confirmation_jwk_from_access_token(tokens["access_token"]),
    server_clock_offset_seconds=_server_clock_offset_seconds(tokens["access_token"]),
  )
  _cached_token = token
  return token


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

  # OWN-039: fetch/verify the helper BEFORE asking for a challenge -- a first
  # download on a slow link (minutes) must not outlive the challenge.
  from .helper import ensure_binary_available
  ensure_binary_available()

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
      airs_request_signer=build_airs_request_signer_for_enrolled_key("tpm", ak_handle=ak_handle),
      confirmation_jwk=confirmation_jwk_from_access_token(tokens["access_token"]),
      server_clock_offset_seconds=_server_clock_offset_seconds(tokens["access_token"]),
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

  # OWN-039: fetch/verify the helper BEFORE asking for a challenge -- a first
  # download on a slow link (minutes) must not outlive the challenge.
  from .helper import ensure_binary_available
  ensure_binary_available()

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
      airs_request_signer=build_airs_request_signer_for_enrolled_key("piv"),
      confirmation_jwk=confirmation_jwk_from_access_token(tokens["access_token"]),
      server_clock_offset_seconds=_server_clock_offset_seconds(tokens["access_token"]),
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
      airs_request_signer=build_airs_request_signer_for_enrolled_key("enclave"),
      confirmation_jwk=confirmation_jwk_from_access_token(tokens["access_token"]),
      server_clock_offset_seconds=_server_clock_offset_seconds(tokens["access_token"]),
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
