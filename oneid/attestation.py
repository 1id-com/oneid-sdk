"""
Protocol-agnostic attestation primitive for the 1id.com SDK.

    proof = oneid.prepare_attestation(content_digest="sha256:abc123...")
    proof = oneid.prepare_attestation(content=b"raw email bytes")

Returns an AttestationProof containing:
  - sd_jwt: Per-message SD-JWT from 1id.com (ES256, 300s TTL, nonce=message_hash)
  - contact_token: The X-1ID-Contact-Token header value
  - tpm_signature: (if sovereign tier) CMS-wrapped TPM attestation signature

SD-JWT endpoint: POST /api/v1/proof/sd-jwt/message
  Request:  {"nonce": "<base64url SHA-256>", "proposed_iat": <unix-ts>, "disclosed_claims": ["trust_tier"]}
  Response: {"ok": true, "data": {"sd_jwt": "...", "disclosures": {...}, "iat": ..., "exp": ...}}

RFC: draft-drake-email-hardware-attestation-00 Section 5.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from ._version import USER_AGENT
from .auth import get_token
from .credentials import DEFAULT_API_BASE_URL, load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.attestation")

_HTTP_TIMEOUT_SECONDS = 15.0


@dataclass
class AttestationProof:
  """Result of prepare_attestation(). Contains all proof artifacts."""
  sd_jwt: Optional[str] = None
  sd_jwt_disclosures: Dict[str, str] = field(default_factory=dict)
  contact_token: Optional[str] = None
  contact_address: Optional[str] = None
  tpm_signature_b64: Optional[str] = None
  content_digest: Optional[str] = None


def prepare_attestation(
  content: Optional[bytes] = None,
  content_digest: Optional[str] = None,
  disclosed_claims: Optional[List[str]] = None,
  include_contact_token: bool = True,
  include_sd_jwt: bool = True,
  api_base_url: Optional[str] = None,
) -> AttestationProof:
  """
  Prepare a protocol-agnostic attestation proof.

  This is the core primitive that all attestation workflows use.
  It gathers the per-message SD-JWT proof and contact token in one call.

  For email attestation, use oneid.mailpal.send() which calls this
  internally and adds the appropriate email headers.

  Args:
    content: Raw content bytes to attest. Will be hashed to SHA-256.
             Mutually exclusive with content_digest.
    content_digest: Pre-computed content digest ("sha256:hex...").
                    Mutually exclusive with content.
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["trust_tier"].
    include_contact_token: Whether to fetch a contact token (default True).
    include_sd_jwt: Whether to fetch an SD-JWT proof (default True).
    api_base_url: Override the 1id.com API base URL.

  Returns:
    AttestationProof with the requested proof artifacts.

  Raises:
    NotEnrolledError: If no credentials exist.
    AuthenticationError: If token refresh fails.
    NetworkError: If the 1id.com API is unreachable.
  """
  if content is not None and content_digest is not None:
    raise ValueError("Provide content OR content_digest, not both.")

  if content is not None:
    digest_hex = hashlib.sha256(content).hexdigest()
    content_digest = f"sha256:{digest_hex}"

  if disclosed_claims is None:
    disclosed_claims = ["trust_tier"]

  creds = load_credentials()
  if api_base_url is None:
    api_base_url = creds.api_base_url or DEFAULT_API_BASE_URL

  token = get_token()
  auth_headers = {
    "Authorization": f"Bearer {token.access_token}",
    "User-Agent": USER_AGENT,
  }

  proof = AttestationProof(content_digest=content_digest)

  if include_sd_jwt:
    message_hash = content_digest.split(":", 1)[1] if content_digest and ":" in content_digest else (content_digest or "")
    proof.sd_jwt, proof.sd_jwt_disclosures = _fetch_sd_jwt_proof_for_message(
      api_base_url=api_base_url,
      auth_headers=auth_headers,
      message_hash=message_hash,
      disclosed_claims=disclosed_claims,
    )

  if include_contact_token:
    proof.contact_token, proof.contact_address = _fetch_contact_token(
      api_base_url=api_base_url,
      auth_headers=auth_headers,
    )

  return proof


def _fetch_sd_jwt_proof_for_message(
  api_base_url: str,
  auth_headers: Dict[str, str],
  message_hash: str,
  disclosed_claims: List[str],
) -> tuple:
  """Fetch a per-message SD-JWT proof from the new endpoint.

  Endpoint: POST /api/v1/proof/sd-jwt/message
  Algorithm: ES256 (server-side, 300s fixed TTL)
  Binding: nonce claim = base64url(raw SHA-256 bytes)

  The server requires {nonce, proposed_iat, disclosed_claims} where nonce
  is a base64url string and proposed_iat is a Unix timestamp.
  """
  url = f"{api_base_url}/api/v1/proof/sd-jwt/message"
  nonce_as_base64url = base64.urlsafe_b64encode(
    bytes.fromhex(message_hash)
  ).rstrip(b"=").decode("ascii")
  body: Dict[str, Any] = {
    "nonce": nonce_as_base64url,
    "proposed_iat": int(time.time()),
    "disclosed_claims": disclosed_claims,
  }

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.post(url, json=body, headers=auth_headers)
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to {url}: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"SD-JWT request timed out: {error}") from error

  if response.status_code == 401:
    raise AuthenticationError("Bearer token rejected by SD-JWT endpoint.")
  if response.status_code != 200:
    logger.error(
      "SD-JWT request failed (HTTP %d): %s  -- Hardware-Trust-Proof header will be MISSING from this message",
      response.status_code, response.text[:300],
    )
    return None, {}

  data = response.json()
  if "data" in data:
    data = data["data"]
  return data.get("sd_jwt"), data.get("disclosures", {})


def _fetch_contact_token(
  api_base_url: str,
  auth_headers: Dict[str, str],
) -> tuple:
  """Fetch a contact token from 1id.com."""
  url = f"{api_base_url}/api/v1/contact-token"

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.get(url, headers=auth_headers)
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to {url}: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"Contact token request timed out: {error}") from error

  if response.status_code != 200:
    logger.warning("Contact token request failed (HTTP %d)", response.status_code)
    return None, None

  data = response.json().get("data", {})
  return data.get("token"), data.get("contact_address")

