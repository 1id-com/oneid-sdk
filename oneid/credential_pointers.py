"""
Credential Pointer management for the 1id.com SDK.

Manages the lightweight pointer registry that links an agent's identity
to credentials held by external credential authorities. 1ID never stores
credential content -- only pointer metadata (issuer, type, verification URL).

Consent tokens enforce agent-initiated registration:
  1. Agent calls generate_consent_token(issuer_id, credential_type) -> token
  2. Agent gives the token to the credential authority
  3. Authority calls the server's register endpoint with the token
  4. Server validates: token is valid, not expired, not used, scopes match

SDK surface:
  generate_consent_token() -- create a scoped, single-use consent token
  list()                   -- list all or public-only pointers for an agent
  set_visibility()         -- toggle a pointer between public and private
  remove()                 -- soft-delete a pointer

Usage:
    import oneid
    from oneid import credential_pointers

    # Generate a consent token for a credential authority
    token = credential_pointers.generate_consent_token(
        issuer_id="did:web:university.example",
        credential_type="degree",
    )
    print(f"Send this to the CA: {token.consent_token_id}")

    # List your own credential pointers
    result = credential_pointers.list()
    for p in result.pointers:
        print(f"{p.issuer_name}: {p.credential_type} [{p.verification_url}]")

    # Make a pointer publicly visible
    credential_pointers.set_visibility(pointer_id="cp-abc123...", publicly_visible=True)

    # Remove a pointer
    credential_pointers.remove(pointer_id="cp-abc123...")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from .auth import get_token
from .client import OneIDAPIClient
from .credentials import StoredCredentials, load_credentials
from .exceptions import (
  AuthenticationError,
  NetworkError,
  NotEnrolledError,
  OneIDError,
)

logger = logging.getLogger("oneid.credential_pointers")


# =====================================================================
# Credential pointer exceptions
# =====================================================================

class CredentialPointerError(OneIDError):
  """Base exception for all credential pointer operations."""

  def __init__(self, message: str = "Credential pointer operation failed", error_code: str | None = None) -> None:
    super().__init__(message, error_code=error_code)


class ConsentTokenGenerationError(CredentialPointerError):
  """Server rejected the consent token generation request."""

  def __init__(self, message: str = "Failed to generate consent token") -> None:
    super().__init__(message, error_code="CONSENT_TOKEN_GENERATION_FAILED")


class PointerNotFoundError(CredentialPointerError):
  """The specified credential pointer does not exist or belongs to a different identity."""

  def __init__(self, message: str = "Credential pointer not found") -> None:
    super().__init__(message, error_code="POINTER_NOT_FOUND")


class PointerAlreadyRemovedError(CredentialPointerError):
  """The pointer has already been soft-deleted."""

  def __init__(self, message: str = "Credential pointer was already removed") -> None:
    super().__init__(message, error_code="POINTER_ALREADY_REMOVED")


# =====================================================================
# Data types
# =====================================================================

@dataclass(frozen=True)
class ConsentTokenResult:
  """Result of generating a credential pointer consent token.

  The token_id should be given to the credential authority, which
  then uses it in a single POST to register one pointer.

  Attributes:
      consent_token_id: The opaque token string (prefix: cpt-).
      issuer_id: The issuer this token is scoped to.
      credential_type: The credential type this token is scoped to.
      expires_at: ISO 8601 expiration timestamp (UTC).
  """
  consent_token_id: str
  issuer_id: str
  credential_type: str
  expires_at: str


@dataclass(frozen=True)
class CredentialPointerInfo:
  """A single credential pointer record.

  Attributes:
      pointer_id: Unique pointer identifier (prefix: cp-).
      issuer_id: DID or URI of the credential authority.
      issuer_name: Human-readable name of the issuer.
      credential_type: Type of credential (e.g., 'degree', 'license').
      credential_scope: Optional scope narrowing (e.g., 'computer-science').
      verification_url: URL where the credential can be verified.
      publicly_visible: Whether this pointer is visible to unauthenticated queries.
      valid_from: ISO 8601 timestamp when the credential becomes valid.
      valid_until: ISO 8601 timestamp when the credential expires, or None.
      registered_at: ISO 8601 timestamp when this pointer was registered.
      removed_at: ISO 8601 timestamp if the pointer has been removed, or None.
  """
  pointer_id: str
  issuer_id: str
  issuer_name: str
  credential_type: str
  credential_scope: str | None
  verification_url: str
  publicly_visible: bool
  valid_from: str | None
  valid_until: str | None
  registered_at: str | None
  removed_at: str | None = None


@dataclass(frozen=True)
class CredentialPointerListResult:
  """Result of listing credential pointers for an identity.

  Attributes:
      agent_id: The identity internal ID whose pointers were queried.
      pointers: List of pointer records.
      pointer_count: Total number of pointers returned.
      view: Either 'full' (agent's own view) or 'public_only' (external view).
  """
  agent_id: str
  pointers: List[CredentialPointerInfo]
  pointer_count: int
  view: str


# =====================================================================
# Internal helpers
# =====================================================================

def _get_authenticated_api_client_and_token(
  credentials: StoredCredentials | None = None,
) -> tuple[OneIDAPIClient, object, StoredCredentials]:
  """Load credentials, get a fresh token, and return (client, token, creds)."""
  if credentials is None:
    credentials = load_credentials()
  token = get_token(credentials=credentials)
  api_client = OneIDAPIClient(api_base_url=credentials.api_base_url)
  return api_client, token, credentials


def _make_authenticated_request(
  method: str,
  path: str,
  json_body: dict | None = None,
  credentials: StoredCredentials | None = None,
) -> dict:
  """Make an authenticated API request and return the response data dict.

  Handles the standard 1id.com envelope: {"ok": true, "data": {...}}.
  On error envelope, raises the appropriate CredentialPointerError.
  """
  api_client, token, creds = _get_authenticated_api_client_and_token(credentials)

  url = f"{api_client.api_base_url}{path}"
  headers = {
    "Authorization": token.authorization_header_value,
  }

  import httpx
  try:
    with httpx.Client(timeout=api_client.timeout_seconds) as http_client:
      response = http_client.request(
        method=method,
        url=url,
        json=json_body,
        headers={
          "User-Agent": "oneid-sdk-python",
          "Accept": "application/json",
          **headers,
        },
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(f"Could not connect to {url}: {connection_error}") from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(f"Request to {url} timed out: {timeout_error}") from timeout_error

  try:
    response_body = response.json()
  except Exception as json_error:
    raise NetworkError(f"Invalid JSON from {url} (HTTP {response.status_code}): {json_error}") from json_error

  if not response_body.get("ok", False):
    error_info = response_body.get("error", {})
    _raise_from_credential_pointer_api_error(error_info)

  return response_body.get("data", {})


def _make_unauthenticated_request(
  method: str,
  path: str,
  api_base_url: str | None = None,
) -> dict:
  """Make an unauthenticated GET request (for public pointer queries)."""
  if api_base_url is None:
    from .credentials import DEFAULT_API_BASE_URL
    api_base_url = DEFAULT_API_BASE_URL

  url = f"{api_base_url.rstrip('/')}{path}"

  import httpx
  try:
    with httpx.Client(timeout=30.0) as http_client:
      response = http_client.request(
        method=method,
        url=url,
        headers={
          "User-Agent": "oneid-sdk-python",
          "Accept": "application/json",
        },
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(f"Could not connect to {url}: {connection_error}") from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(f"Request to {url} timed out: {timeout_error}") from timeout_error

  try:
    response_body = response.json()
  except Exception as json_error:
    raise NetworkError(f"Invalid JSON from {url} (HTTP {response.status_code}): {json_error}") from json_error

  if not response_body.get("ok", False):
    error_info = response_body.get("error", {})
    _raise_from_credential_pointer_api_error(error_info)

  return response_body.get("data", {})


_ERROR_CODE_TO_EXCEPTION_MAP = {
  "POINTER_NOT_FOUND": PointerNotFoundError,
  "POINTER_ALREADY_REMOVED": PointerAlreadyRemovedError,
  "IDENTITY_NOT_FOUND": CredentialPointerError,
}


def _raise_from_credential_pointer_api_error(error_info: dict) -> None:
  """Map a server error envelope to the correct SDK exception."""
  code = error_info.get("code", "UNKNOWN_ERROR")
  message = error_info.get("message", "Unknown credential pointer error")

  exception_class = _ERROR_CODE_TO_EXCEPTION_MAP.get(code, CredentialPointerError)
  raise exception_class(message)


def _parse_pointer_from_api_response(raw: dict) -> CredentialPointerInfo:
  """Convert a raw API pointer dict into a CredentialPointerInfo."""
  return CredentialPointerInfo(
    pointer_id=raw.get("pointer_id", ""),
    issuer_id=raw.get("issuer_id", ""),
    issuer_name=raw.get("issuer_name", ""),
    credential_type=raw.get("credential_type", ""),
    credential_scope=raw.get("credential_scope"),
    verification_url=raw.get("verification_url", ""),
    publicly_visible=bool(raw.get("publicly_visible", False)),
    valid_from=raw.get("valid_from"),
    valid_until=raw.get("valid_until"),
    registered_at=raw.get("registered_at"),
    removed_at=raw.get("removed_at"),
  )


# =====================================================================
# generate_consent_token()
# =====================================================================

def generate_consent_token(
  issuer_id: str,
  credential_type: str,
  valid_for_seconds: int = 86400,
  credentials: StoredCredentials | None = None,
) -> ConsentTokenResult:
  """Generate a scoped, single-use consent token for a credential authority.

  The agent calls this to authorize a specific credential authority to
  register exactly one credential pointer of one credential type.

  Give the returned token_id to the credential authority. The authority
  uses it in a POST /api/v1/identity/credential-pointers call.

  Args:
      issuer_id: DID or URI of the credential authority
                 (e.g., 'did:web:university.example').
      credential_type: The type of credential being authorized
                       (e.g., 'degree', 'license', 'certification').
      valid_for_seconds: How long the token is valid (60..604800, default 86400).
      credentials: Optional pre-loaded credentials. If None, loaded from file.

  Returns:
      ConsentTokenResult with the token_id, scoped issuer/type, and expiry.

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token is invalid.
      NetworkError: If the server cannot be reached.
      ConsentTokenGenerationError: If the server rejected the request.
  """
  raw_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/credential-pointer-consent",
    json_body={
      "issuer_id": issuer_id,
      "credential_type": credential_type,
      "valid_for_seconds": valid_for_seconds,
    },
    credentials=credentials,
  )

  return ConsentTokenResult(
    consent_token_id=raw_data.get("token_id", ""),
    issuer_id=raw_data.get("issuer_id", issuer_id),
    credential_type=raw_data.get("credential_type", credential_type),
    expires_at=raw_data.get("expires_at", ""),
  )


# =====================================================================
# list()
# =====================================================================

def list(
  agent_id: str | None = None,
  credentials: StoredCredentials | None = None,
) -> CredentialPointerListResult:
  """List credential pointers for an identity.

  If agent_id is None or matches the current identity, makes an
  authenticated request returning all active pointers (full view).
  If agent_id is a different identity, makes an unauthenticated
  request returning only publicly visible pointers.

  Args:
      agent_id: Identity to query. None = query your own pointers.
      credentials: Optional pre-loaded credentials. If None, loaded from file.

  Returns:
      CredentialPointerListResult with the list of pointers and metadata.

  Raises:
      NotEnrolledError: If no credentials file exists and agent_id is None.
      AuthenticationError: If the token is invalid (own pointers).
      NetworkError: If the server cannot be reached.
      CredentialPointerError: If the agent_id does not exist.
  """
  if agent_id is None:
    if credentials is None:
      credentials = load_credentials()
    agent_id = credentials.client_id

  this_request_is_for_own_identity = False
  try:
    if credentials is None:
      credentials = load_credentials()
    this_request_is_for_own_identity = (credentials.client_id == agent_id)
  except Exception:
    this_request_is_for_own_identity = False

  path = f"/api/v1/identity/{agent_id}/credential-pointers"

  if this_request_is_for_own_identity:
    raw_data = _make_authenticated_request("GET", path, credentials=credentials)
  else:
    api_base_url = None
    if credentials is not None:
      api_base_url = credentials.api_base_url
    raw_data = _make_unauthenticated_request("GET", path, api_base_url=api_base_url)

  raw_pointers = raw_data.get("pointers", [])
  pointers = [_parse_pointer_from_api_response(p) for p in raw_pointers]

  return CredentialPointerListResult(
    agent_id=raw_data.get("agent_id", agent_id),
    pointers=pointers,
    pointer_count=raw_data.get("pointer_count", len(pointers)),
    view=raw_data.get("view", "public_only"),
  )


# =====================================================================
# set_visibility()
# =====================================================================

def set_visibility(
  pointer_id: str,
  publicly_visible: bool,
  credentials: StoredCredentials | None = None,
) -> CredentialPointerInfo:
  """Toggle a credential pointer between public and private visibility.

  Public pointers are visible to anyone querying the agent's identity.
  Private pointers are only visible to the agent itself.

  Args:
      pointer_id: The pointer to update (prefix: cp-).
      publicly_visible: True to make public, False to make private.
      credentials: Optional pre-loaded credentials. If None, loaded from file.

  Returns:
      The updated CredentialPointerInfo.

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token is invalid.
      NetworkError: If the server cannot be reached.
      PointerNotFoundError: If the pointer does not exist or belongs to another identity.
      PointerAlreadyRemovedError: If the pointer has been soft-deleted.
  """
  raw_data = _make_authenticated_request(
    "PUT",
    f"/api/v1/identity/credential-pointers/{pointer_id}/visibility",
    json_body={"publicly_visible": publicly_visible},
    credentials=credentials,
  )

  return _parse_pointer_from_api_response(raw_data)


# =====================================================================
# remove()
# =====================================================================

def remove(
  pointer_id: str,
  credentials: StoredCredentials | None = None,
) -> CredentialPointerInfo:
  """Soft-delete a credential pointer.

  The pointer is marked as removed and no longer appears in list results
  (unless the agent specifically requests removed pointers). The pointer
  is never hard-deleted, preserving the audit trail.

  Args:
      pointer_id: The pointer to remove (prefix: cp-).
      credentials: Optional pre-loaded credentials. If None, loaded from file.

  Returns:
      The removed CredentialPointerInfo (with removed_at set).

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token is invalid.
      NetworkError: If the server cannot be reached.
      PointerNotFoundError: If the pointer does not exist or belongs to another identity.
      PointerAlreadyRemovedError: If the pointer was already removed.
  """
  raw_data = _make_authenticated_request(
    "DELETE",
    f"/api/v1/identity/credential-pointers/{pointer_id}",
    credentials=credentials,
  )

  return _parse_pointer_from_api_response(raw_data)
