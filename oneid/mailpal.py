"""
MailPal convenience functions for the 1id.com SDK.

    # One-call attested email sending
    result = oneid.mailpal.send(
        to=["recipient@example.com"],
        subject="Hello from my AI agent",
        text_body="Message body",
    )

    # Account activation
    account = oneid.mailpal.activate()

    # Read inbox
    messages = oneid.mailpal.inbox()

    # Get contact token for email headers
    token = oneid.mailpal.get_contact_token()

These are convenience wrappers around the MailPal REST API that handle
authentication, attestation header injection, and error mapping.

Design: 110_mailpal_sprint_to_go-live.md Section 7.3.1 & 7.4
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from .auth import get_token
from .attestation import prepare_attestation, AttestationProof
from .credentials import load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.mailpal")

_MAILPAL_API_BASE_URL = "https://mailpal.com"
_HTTP_TIMEOUT_SECONDS = 30.0
_USER_AGENT = "oneid-sdk-python/0.2.0"


@dataclass
class SendResult:
  """Result of a mailpal.send() call."""
  message_id: Optional[str] = None
  from_address: Optional[str] = None
  attestation_headers_included: bool = False
  contact_token_header_included: bool = False
  sd_jwt_header_included: bool = False


@dataclass
class MailpalAccount:
  """Result of a mailpal.activate() call."""
  primary_email: str = ""
  vanity_email: Optional[str] = None
  app_password: Optional[str] = None
  already_existed: bool = False


@dataclass
class InboxMessage:
  """A message summary from the inbox."""
  message_id: str = ""
  from_address: str = ""
  subject: str = ""
  received_at: str = ""
  is_unread: bool = True


def _get_auth_headers() -> Dict[str, str]:
  """Get authorization headers using the current 1id token."""
  token = get_token()
  return {
    "Authorization": f"Bearer {token.access_token}",
    "User-Agent": _USER_AGENT,
  }


def activate(
  mailpal_api_url: Optional[str] = None,
) -> MailpalAccount:
  """
  Activate a MailPal account for the current 1id identity.

  Creates the Stalwart mail account if it doesn't exist, or returns
  the existing account info if it does. Idempotent.

  Returns:
    MailpalAccount with primary email, optional vanity, and app password (if new).
  """
  url = f"{mailpal_api_url or _MAILPAL_API_BASE_URL}/api/v1/activate"

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.post(url, headers=_get_auth_headers())
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to MailPal: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"MailPal activate request timed out: {error}") from error

  if response.status_code == 401:
    raise AuthenticationError("Bearer token rejected by MailPal.")
  if response.status_code != 200:
    raise NetworkError(f"MailPal activate failed (HTTP {response.status_code}): {response.text[:200]}")

  data = response.json().get("data", {})
  return MailpalAccount(
    primary_email=data.get("primary_email", ""),
    vanity_email=data.get("vanity_email"),
    app_password=data.get("app_password"),
    already_existed=data.get("already_existed", False),
  )


def send(
  to: List[str],
  subject: str,
  text_body: Optional[str] = None,
  html_body: Optional[str] = None,
  from_address: Optional[str] = None,
  include_attestation: bool = True,
  disclosed_claims: Optional[List[str]] = None,
  mailpal_api_url: Optional[str] = None,
  oneid_api_url: Optional[str] = None,
) -> SendResult:
  """
  Send an attested email via MailPal.

  This is the "one-call easy mode" that:
  1. Prepares attestation proof (SD-JWT + contact token) from 1id.com
  2. Sends the email via MailPal with proof headers attached

  Args:
    to: List of recipient email addresses.
    subject: Email subject line.
    text_body: Plain text body (at least one of text_body/html_body required).
    html_body: HTML body.
    from_address: Sender address. If None, MailPal uses the agent's primary address.
    include_attestation: Whether to include attestation headers (default True).
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["1id_trust_tier"].
    mailpal_api_url: Override the MailPal API URL.
    oneid_api_url: Override the 1id.com API URL.

  Returns:
    SendResult with message_id and attestation details.
  """
  proof = None
  if include_attestation:
    email_content_for_digest = (text_body or html_body or "").encode("utf-8")
    proof = prepare_attestation(
      content=email_content_for_digest,
      disclosed_claims=disclosed_claims,
      api_base_url=oneid_api_url,
    )

  send_body: Dict[str, Any] = {
    "to": to,
    "subject": subject,
  }
  if text_body:
    send_body["text_body"] = text_body
  if html_body:
    send_body["html_body"] = html_body
  if from_address:
    send_body["from"] = from_address

  if proof:
    custom_headers = {}
    if proof.sd_jwt:
      custom_headers["X-1ID-Proof"] = proof.sd_jwt
    if proof.contact_token:
      custom_headers["X-1ID-Contact-Token"] = proof.contact_token
    if proof.content_digest:
      custom_headers["X-1ID-Content-Digest"] = proof.content_digest
    if custom_headers:
      send_body["custom_headers"] = custom_headers

  url = f"{mailpal_api_url or _MAILPAL_API_BASE_URL}/api/v1/send"

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.post(url, json=send_body, headers=_get_auth_headers())
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to MailPal: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"MailPal send timed out: {error}") from error

  if response.status_code == 401:
    raise AuthenticationError("Bearer token rejected by MailPal.")
  if response.status_code != 200:
    raise NetworkError(f"MailPal send failed (HTTP {response.status_code}): {response.text[:200]}")

  data = response.json().get("data", {})

  return SendResult(
    message_id=data.get("message_id"),
    from_address=data.get("from"),
    attestation_headers_included=proof is not None,
    contact_token_header_included=proof is not None and proof.contact_token is not None,
    sd_jwt_header_included=proof is not None and proof.sd_jwt is not None,
  )


def inbox(
  limit: int = 20,
  offset: int = 0,
  unread_only: bool = False,
  mailpal_api_url: Optional[str] = None,
) -> List[InboxMessage]:
  """
  Fetch inbox messages from MailPal.

  Args:
    limit: Max messages to return (default 20).
    offset: Pagination offset.
    unread_only: If True, only return unread messages.
    mailpal_api_url: Override the MailPal API URL.

  Returns:
    List of InboxMessage objects.
  """
  url = f"{mailpal_api_url or _MAILPAL_API_BASE_URL}/api/v1/inbox"
  params = {"limit": limit, "offset": offset}
  if unread_only:
    params["unread_only"] = "true"

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.get(url, params=params, headers=_get_auth_headers())
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to MailPal: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"MailPal inbox request timed out: {error}") from error

  if response.status_code == 401:
    raise AuthenticationError("Bearer token rejected by MailPal.")
  if response.status_code != 200:
    raise NetworkError(f"MailPal inbox failed (HTTP {response.status_code}): {response.text[:200]}")

  data = response.json().get("data", {})
  messages_raw = data.get("messages", [])

  return [
    InboxMessage(
      message_id=msg.get("id", ""),
      from_address=msg.get("from", ""),
      subject=msg.get("subject", ""),
      received_at=msg.get("received_at", ""),
      is_unread=msg.get("is_unread", True),
    )
    for msg in messages_raw
  ]


def get_contact_token(
  oneid_api_url: Optional[str] = None,
) -> Optional[str]:
  """
  Get the current contact token for use in email headers.

  Returns the bare token string (e.g. "a1b2c3d4") or None if unavailable.
  """
  from .attestation import _fetch_contact_token

  creds = load_credentials()
  api_base_url = oneid_api_url or creds.api_base_url or "https://1id.com"

  token = get_token()
  auth_headers = {
    "Authorization": f"Bearer {token.access_token}",
    "User-Agent": _USER_AGENT,
  }

  contact_token_value, _ = _fetch_contact_token(api_base_url, auth_headers)
  return contact_token_value

