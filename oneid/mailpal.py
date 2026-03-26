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

Architecture (v2 -- local MIME assembly + direct SMTP):

  send() builds the MIME message locally using Python's email.message module,
  extracts the exact wire-format bytes (including RFC 2047 encoding), computes
  attestation nonces and signatures from those bytes, injects attestation
  headers, then submits the fully-assembled message directly to
  smtp.mailpal.com via SMTP with app_password AUTH.

  This guarantees the SDK signs the same byte-for-byte header values that the
  receiving milter will verify, eliminating the canonicalization mismatch that
  occurred when the old REST API returned decoded-Unicode headers while
  Stalwart transmitted RFC 2047-encoded headers on the wire.

Design: 110_mailpal_sprint_to_go-live.md Section 7.3.1 & 7.4
"""

from __future__ import annotations

import email as email_stdlib
import email.message
import email.policy
import email.utils
import logging
import smtplib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from ._version import USER_AGENT
from .auth import get_token
from .attestation import prepare_attestation, AttestationProof
from .credentials import load_credentials, save_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.mailpal")

_MAILPAL_API_BASE_URL = "https://mailpal.com"
_HTTP_TIMEOUT_SECONDS = 30.0
_SMTP_HOST = "smtp.mailpal.com"
_SMTP_PORT_STARTTLS = 587
_SMTP_TIMEOUT_SECONDS = 30


@dataclass
class SendResult:
  """Result of a mailpal.send() call."""
  message_id: Optional[str] = None
  from_address: Optional[str] = None
  attestation_headers_included: bool = False
  contact_token_header_included: bool = False
  sd_jwt_header_included: bool = False
  direct_attestation_header_included: bool = False


@dataclass
class MailpalAccount:
  """Result of a mailpal.activate() call when activation succeeds or account already exists."""
  primary_email: str = ""
  vanity_email: Optional[str] = None
  app_password: Optional[str] = None
  already_existed: bool = False
  smtp: Optional[Dict[str, Any]] = None
  imap: Optional[Dict[str, Any]] = None


@dataclass
class MailpalActivationChallenge:
  """Returned by activate() when a Proof-of-Intelligence challenge must be solved.

  The agent (LLM) must read the prompt, produce an answer, then call
  activate(challenge_token=..., challenge_answer=...) to complete activation.
  """
  challenge_token: str = ""
  prompt: str = ""
  difficulty: str = "easy"
  expires_in_seconds: int = 300
  attempt_limit: int = 3


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
    "User-Agent": USER_AGENT,
  }


def activate(
  challenge_token: Optional[str] = None,
  challenge_answer: Optional[str] = None,
  display_name: Optional[str] = None,
  mailpal_api_url: Optional[str] = None,
) -> "MailpalAccount | MailpalActivationChallenge":
  """
  Activate a MailPal account for the current 1id identity.

  Two-phase flow:

    # Phase 1: request activation (returns a challenge to prove you're an AI)
    result = oneid.mailpal.activate()
    if isinstance(result, oneid.mailpal.MailpalActivationChallenge):
        # Read result.prompt, think about it, produce an answer
        answer = "..."  # your answer to the challenge prompt
        account = oneid.mailpal.activate(
            challenge_token=result.challenge_token,
            challenge_answer=answer,
        )

    # If already activated, Phase 1 returns MailpalAccount directly (idempotent).

  Args:
    challenge_token: Token from a previous challenge response (Phase 2 only).
    challenge_answer: Your answer to the challenge prompt (Phase 2 only).
    display_name: Optional friendly name for the account (e.g. "Clawdia").
    mailpal_api_url: Override the MailPal API base URL.

  Returns:
    MailpalAccount if activation succeeded or account already exists.
    MailpalActivationChallenge if a POI challenge must be solved first.
  """
  url = f"{mailpal_api_url or _MAILPAL_API_BASE_URL}/api/v1/activate"

  request_body: Dict[str, Any] = {}
  if challenge_token and challenge_answer:
    request_body["challenge_token"] = challenge_token
    request_body["challenge_answer"] = challenge_answer
  if display_name:
    request_body["display_name"] = display_name

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.post(
        url,
        json=request_body if request_body else None,
        headers=_get_auth_headers(),
      )
  except httpx.ConnectError as error:
    raise NetworkError(f"Could not connect to MailPal: {error}") from error
  except httpx.TimeoutException as error:
    raise NetworkError(f"MailPal activate request timed out: {error}") from error

  if response.status_code == 401:
    raise AuthenticationError("Bearer token rejected by MailPal.")
  if response.status_code == 403:
    error_info = response.json().get("error", {})
    raise AuthenticationError(
      f"Challenge failed: {error_info.get('message', response.text[:200])}. "
      "Call activate() again with no arguments to get a new challenge."
    )
  if response.status_code == 429:
    error_info = response.json().get("error", {})
    raise NetworkError(f"Rate limited: {error_info.get('message', response.text[:200])}")

  if response.status_code not in (200, 201):
    raise NetworkError(f"MailPal activate failed (HTTP {response.status_code}): {response.text[:200]}")

  data = response.json().get("data", {})

  if data.get("phase") == "challenge":
    return MailpalActivationChallenge(
      challenge_token=data.get("challenge_token", ""),
      prompt=data.get("prompt", ""),
      difficulty=data.get("difficulty", "easy"),
      expires_in_seconds=data.get("expires_in_seconds", 300),
      attempt_limit=data.get("attempt_limit", 3),
    )

  account = MailpalAccount(
    primary_email=data.get("primary_email", ""),
    vanity_email=data.get("vanity_email"),
    app_password=data.get("app_password"),
    already_existed=data.get("already_activated", False),
    smtp=data.get("smtp"),
    imap=data.get("imap"),
  )

  if account.primary_email:
    try:
      creds = load_credentials()
      mailpal_credentials_changed = False
      if creds.mailpal_email != account.primary_email:
        creds.mailpal_email = account.primary_email
        mailpal_credentials_changed = True
      if account.app_password and creds.mailpal_app_password != account.app_password:
        creds.mailpal_app_password = account.app_password
        mailpal_credentials_changed = True
      if mailpal_credentials_changed:
        save_credentials(creds)
        logger.info("Persisted MailPal SMTP credentials to credentials.json")
    except Exception as persist_error:
      logger.warning("Could not persist MailPal credentials: %s", persist_error)

  return account


def _fold_long_header_value_for_smtp_transmission(header_name: str, header_value: str) -> str:
  """Fold a header into continuation lines per RFC 5322 Section 2.2.3.

  Long attestation headers (SD-JWT, CMS chain) can exceed the 998-character
  hard limit. This function folds at 76-char boundaries using CRLF + HTAB
  continuation, which the milter unfolds before verification.
  """
  full_line = f"{header_name}: {header_value}"
  if len(full_line) <= 76:
    return full_line
  first_line = full_line[:76]
  remaining = full_line[76:]
  lines = [first_line]
  while remaining:
    chunk = remaining[:75]
    lines.append("\t" + chunk)
    remaining = remaining[75:]
  return "\r\n".join(lines)


def _extract_all_envelope_recipient_addresses(
  to_list: List[str],
  cc_list: Optional[List[str]],
  bcc_list: Optional[List[str]],
) -> List[str]:
  """Parse all recipient lists and extract bare email addresses for RCPT TO."""
  all_recipients: List[str] = []
  for address_list in [to_list, cc_list or [], bcc_list or []]:
    for _, email_address in email.utils.getaddresses(address_list):
      if email_address:
        all_recipients.append(email_address)
  return all_recipients


def send(
  to: List[str],
  subject: str,
  text_body: Optional[str] = None,
  html_body: Optional[str] = None,
  from_address: Optional[str] = None,
  from_display_name: Optional[str] = None,
  cc: Optional[List[str]] = None,
  bcc: Optional[List[str]] = None,
  include_attestation: bool = True,
  attestation_mode: str = "both",
  disclosed_claims: Optional[List[str]] = None,
  oneid_api_url: Optional[str] = None,
  smtp_host: Optional[str] = None,
  smtp_port: Optional[int] = None,
  smtp_username: Optional[str] = None,
  smtp_password: Optional[str] = None,
) -> SendResult:
  """
  Send an attested email via direct SMTP submission to smtp.mailpal.com.

  Builds the MIME message locally, computes attestation from the exact
  wire-format bytes (guaranteeing the milter verifies the same bytes),
  injects attestation headers, and submits via SMTP with STARTTLS.

  All address fields accept any format an agent might produce:
    - "user@domain"
    - '"Display Name" <user@domain>'
    - "Display Name <user@domain>"
    - Comma-separated combinations of the above

  Args:
    to: List of recipient addresses (To header, visible to all recipients).
    subject: Email subject line.
    text_body: Plain text body (at least one of text_body/html_body required).
    html_body: HTML body.
    from_address: Sender email address (bare email or "Name <addr>" format).
        If None, uses the stored mailpal_email or {client_id}@mailpal.com.
        The agent may use any @mailpal.com alias it owns.
    from_display_name: Override display name for the From header. Takes
        precedence over any name parsed from from_address or the account
        default. Supports full Unicode (emoji, CJK, accented characters).
    cc: List of Cc recipient addresses (visible to all recipients).
    bcc: List of Bcc recipient addresses (receive the message but are
        hidden from all other recipients -- not placed in any header).
    include_attestation: Whether to include attestation headers (default True).
    attestation_mode: Which RFC attestation mode(s) to use:
      "both"    -- Combined Mode (Section 7: both headers, default).
                   Mode 1 is silently skipped if the identity lacks a cert chain.
      "sd-jwt"  -- Mode 2 only (Hardware-Trust-Proof header)
      "direct"  -- Mode 1 only (Hardware-Attestation header with CMS bundle)
      "none"    -- No attestation headers (overrides include_attestation)
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["trust_tier"].
    oneid_api_url: Override the 1id.com API URL.
    smtp_host: Override SMTP host (default: smtp.mailpal.com).
    smtp_port: Override SMTP port (default: 587/STARTTLS).
    smtp_username: Override SMTP auth username (default: stored mailpal_email).
        Use this to send from a different Stalwart account (e.g.
        alice@example.un.ag) while still using the agent's 1id identity
        for attestation signing.
    smtp_password: Override SMTP auth password. Required when smtp_username
        is set. This is the Stalwart app_password for the account being
        sent from.

  Returns:
    SendResult with message_id and attestation details.
  """
  creds = load_credentials()

  effective_smtp_auth_username = smtp_username or creds.mailpal_email or f"{creds.client_id}@mailpal.com"
  effective_smtp_auth_password = smtp_password or creds.mailpal_app_password
  if not effective_smtp_auth_password:
    raise NotEnrolledError(
      "No SMTP password available. Either pass smtp_password explicitly, "
      "or call oneid.mailpal.activate() first to store SMTP credentials, "
      "or manually add mailpal_app_password to credentials.json."
    )

  parsed_from_display_name, parsed_from_email = email.utils.parseaddr(from_address or "")
  effective_from_email = parsed_from_email or effective_smtp_auth_username
  effective_from_display_name = from_display_name or parsed_from_display_name or creds.display_name or ""

  if attestation_mode == "none":
    include_attestation = False

  # -- Phase 1: Build MIME message locally --
  mime_message = email.message.EmailMessage(policy=email.policy.SMTP)
  mime_message["From"] = email.utils.formataddr((effective_from_display_name, effective_from_email))
  mime_message["To"] = ", ".join(to)
  mime_message["Subject"] = subject
  mime_message["Date"] = email.utils.formatdate(localtime=True)
  mime_message["Message-ID"] = email.utils.make_msgid(domain="mailpal.com")
  if cc:
    mime_message["Cc"] = ", ".join(cc)

  if text_body and html_body:
    mime_message.set_content(text_body)
    mime_message.add_alternative(html_body, subtype="html")
  elif html_body:
    mime_message.set_content(html_body, subtype="html")
  else:
    mime_message.set_content(text_body or "")

  wire_format_message_bytes = mime_message.as_bytes()

  # -- Phase 2: Parse wire bytes to extract headers identically to milter --
  parsed_wire_message = email_stdlib.message_from_bytes(
    wire_format_message_bytes, policy=email.policy.compat32,
  )

  _MODE2_REQUIRED_HEADER_NAMES = {"from", "to", "subject", "date", "message-id"}
  wire_format_headers_for_mode2_nonce = {}
  for header_name_key in _MODE2_REQUIRED_HEADER_NAMES:
    header_value_from_wire = parsed_wire_message[header_name_key]
    if header_value_from_wire is not None:
      wire_format_headers_for_mode2_nonce[header_name_key] = header_value_from_wire

  wire_format_all_headers_for_mode1 = {}
  for raw_header_name in parsed_wire_message.keys():
    lowered_header_name = raw_header_name.strip().lower()
    if lowered_header_name not in wire_format_all_headers_for_mode1:
      wire_format_all_headers_for_mode1[lowered_header_name] = parsed_wire_message[raw_header_name]

  header_body_separator_position = wire_format_message_bytes.find(b"\r\n\r\n")
  wire_format_body_bytes = (
    wire_format_message_bytes[header_body_separator_position + 4:]
    if header_body_separator_position >= 0 else b""
  )

  # -- Phase 3: Compute attestation from wire-format bytes --
  mode2_sd_jwt_proof = None
  mode1_direct_attestation_proof = None

  if include_attestation:
    include_sd_jwt_mode = attestation_mode in ("sd-jwt", "both")
    include_direct_mode = attestation_mode in ("direct", "both")

    if include_sd_jwt_mode:
      try:
        mode2_sd_jwt_proof = prepare_attestation(
          email_headers=wire_format_headers_for_mode2_nonce,
          body=wire_format_body_bytes,
          disclosed_claims=disclosed_claims,
          api_base_url=oneid_api_url,
        )
      except Exception as mode2_error:
        logger.warning("Mode 2 (SD-JWT) attestation failed: %s", mode2_error)

    if include_direct_mode:
      try:
        from .attestation import prepare_direct_hardware_attestation
        mode1_direct_attestation_proof = prepare_direct_hardware_attestation(
          email_headers=wire_format_all_headers_for_mode1,
          body=wire_format_body_bytes,
        )
      except Exception as mode1_error:
        logger.warning("Mode 1 (direct) attestation failed: %s", mode1_error)

  # -- Phase 4: Build attestation header lines for injection --
  attestation_header_lines_to_inject: List[str] = []

  if mode2_sd_jwt_proof:
    if mode2_sd_jwt_proof.sd_jwt:
      sd_jwt_presentation_value = mode2_sd_jwt_proof.sd_jwt
      if mode2_sd_jwt_proof.sd_jwt_disclosures:
        for disclosure_b64url in mode2_sd_jwt_proof.sd_jwt_disclosures.values():
          sd_jwt_presentation_value += "~" + disclosure_b64url
        sd_jwt_presentation_value += "~"
      attestation_header_lines_to_inject.append(
        _fold_long_header_value_for_smtp_transmission("Hardware-Trust-Proof", sd_jwt_presentation_value)
      )
    if mode2_sd_jwt_proof.contact_token:
      attestation_header_lines_to_inject.append(
        f"X-1ID-Contact-Token: {mode2_sd_jwt_proof.contact_token}"
      )

  if mode1_direct_attestation_proof and mode1_direct_attestation_proof.hardware_attestation_header_value:
    attestation_header_lines_to_inject.append(
      _fold_long_header_value_for_smtp_transmission(
        "Hardware-Attestation", mode1_direct_attestation_proof.hardware_attestation_header_value,
      )
    )

  # -- Phase 5: Inject attestation headers into wire bytes --
  if attestation_header_lines_to_inject and header_body_separator_position >= 0:
    headers_section = wire_format_message_bytes[:header_body_separator_position]
    body_and_separator_tail = wire_format_message_bytes[header_body_separator_position:]
    injected_header_bytes = ("\r\n".join(attestation_header_lines_to_inject)).encode("utf-8")
    final_message_bytes = headers_section + b"\r\n" + injected_header_bytes + body_and_separator_tail
  else:
    final_message_bytes = wire_format_message_bytes

  # -- Phase 6: Submit via SMTP with STARTTLS + app_password auth --
  effective_smtp_host = smtp_host or _SMTP_HOST
  effective_smtp_port = smtp_port or _SMTP_PORT_STARTTLS

  envelope_recipients = _extract_all_envelope_recipient_addresses(to, cc, bcc)
  if not envelope_recipients:
    raise ValueError("No valid recipient email addresses found in to/cc/bcc.")

  try:
    with smtplib.SMTP(effective_smtp_host, effective_smtp_port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp_connection:
      smtp_connection.ehlo()
      smtp_connection.starttls()
      smtp_connection.ehlo()
      smtp_connection.login(effective_smtp_auth_username, effective_smtp_auth_password)
      smtp_connection.sendmail(effective_from_email, envelope_recipients, final_message_bytes)
  except smtplib.SMTPAuthenticationError as smtp_auth_error:
    raise AuthenticationError(
      f"SMTP authentication failed for {effective_smtp_auth_username}: {smtp_auth_error}"
    ) from smtp_auth_error
  except (smtplib.SMTPException, OSError) as smtp_error:
    raise NetworkError(f"SMTP submission failed: {smtp_error}") from smtp_error

  generated_message_id = mime_message["Message-ID"]

  return SendResult(
    message_id=generated_message_id,
    from_address=effective_from_email,
    attestation_headers_included=mode2_sd_jwt_proof is not None or mode1_direct_attestation_proof is not None,
    contact_token_header_included=mode2_sd_jwt_proof is not None and mode2_sd_jwt_proof.contact_token is not None,
    sd_jwt_header_included=mode2_sd_jwt_proof is not None and mode2_sd_jwt_proof.sd_jwt is not None,
    direct_attestation_header_included=(
      mode1_direct_attestation_proof is not None
      and mode1_direct_attestation_proof.hardware_attestation_header_value is not None
    ),
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
    "User-Agent": USER_AGENT,
  }

  contact_token_value, _ = _fetch_contact_token(api_base_url, auth_headers)
  return contact_token_value

