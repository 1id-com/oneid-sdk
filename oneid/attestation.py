"""
Protocol-agnostic attestation primitive for the 1id.com SDK.

    proof = oneid.prepare_attestation(content_digest="sha256:abc123...")
    proof = oneid.prepare_attestation(content=b"raw email bytes")

Returns an AttestationProof containing:
  - sd_jwt: The SD-JWT from 1id.com (selective disclosure of trust tier)
  - contact_token: The X-1ID-Contact-Token header value
  - tpm_signature: (if sovereign tier) CMS-wrapped TPM attestation signature

Design: 110_mailpal_sprint_to_go-live.md Section 7.3.1
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from .auth import get_token
from .credentials import DEFAULT_API_BASE_URL, load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.attestation")

_HTTP_TIMEOUT_SECONDS = 15.0
_USER_AGENT = "oneid-sdk-python/0.2.0"


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
  audience: Optional[str] = None,
  sd_jwt_ttl_seconds: int = 86400,
  include_contact_token: bool = True,
  include_sd_jwt: bool = True,
  api_base_url: Optional[str] = None,
) -> AttestationProof:
  """
  Prepare a protocol-agnostic attestation proof.

  This is the core primitive that all attestation workflows use.
  It gathers the SD-JWT proof and contact token in one call.

  For email attestation, use oneid.mailpal.send() which calls this
  internally and adds the appropriate email headers.

  Args:
    content: Raw content bytes to attest. Will be hashed to SHA-256.
             Mutually exclusive with content_digest.
    content_digest: Pre-computed content digest ("sha256:hex...").
                    Mutually exclusive with content.
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["1id_trust_tier"].
    audience: Optional SD-JWT audience restriction.
    sd_jwt_ttl_seconds: SD-JWT validity in seconds (default 24h).
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
    disclosed_claims = ["1id_trust_tier"]

  creds = load_credentials()
  if api_base_url is None:
    api_base_url = creds.api_base_url or DEFAULT_API_BASE_URL

  token = get_token()
  auth_headers = {
    "Authorization": f"Bearer {token.access_token}",
    "User-Agent": _USER_AGENT,
  }

  proof = AttestationProof(content_digest=content_digest)

  if include_sd_jwt:
    proof.sd_jwt, proof.sd_jwt_disclosures = _fetch_sd_jwt_proof(
      api_base_url=api_base_url,
      auth_headers=auth_headers,
      claims=disclosed_claims,
      audience=audience,
      ttl_seconds=sd_jwt_ttl_seconds,
    )

  if include_contact_token:
    proof.contact_token, proof.contact_address = _fetch_contact_token(
      api_base_url=api_base_url,
      auth_headers=auth_headers,
    )

  return proof


def _fetch_sd_jwt_proof(
  api_base_url: str,
  auth_headers: Dict[str, str],
  claims: List[str],
  audience: Optional[str],
  ttl_seconds: int,
) -> tuple:
  """Fetch an SD-JWT proof from 1id.com."""
  url = f"{api_base_url}/api/v1/proof/sd-jwt"
  body: Dict[str, Any] = {
    "claims": claims,
    "ttl_seconds": ttl_seconds,
    "holder_binding": True,
  }
  if audience:
    body["audience"] = audience

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
    logger.warning("SD-JWT request failed (HTTP %d): %s", response.status_code, response.text[:200])
    return None, {}

  data = response.json().get("data", {})
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

