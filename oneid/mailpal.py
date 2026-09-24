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
import os
import smtplib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from . import _http as httpx  # stdlib-backed drop-in (no httpx dependency)

from ._version import USER_AGENT
from .auth import get_token
from .attestation import prepare_attestation, AttestationProof
from .credentials import load_credentials, save_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.mailpal")

_MAILPAL_API_BASE_URL = "https://mailpal.com"
# ONEID_HTTP_TIMEOUT_SECONDS lets slow/proxied hosts widen the window
# (REAL_USER_ROADBLOCKS R-U 3); default unchanged at 30s.
_HTTP_TIMEOUT_SECONDS = float(os.environ.get("ONEID_HTTP_TIMEOUT_SECONDS", "30.0"))
_SMTP_HOST = "smtp.mailpal.com"
_SMTP_PORT_STARTTLS = 587
_SMTP_TIMEOUT_SECONDS = float(os.environ.get("ONEID_HTTP_TIMEOUT_SECONDS", "30.0"))
_SMTP_SECURITY_MODE_TO_DEFAULT_PORT = {"starttls": 587, "tls": 465, "none": 25}


def _discover_smtp_submission_host_via_mx_lookup(domain_name: str) -> str:
  """Discover SMTP submission host for a domain via DNS MX lookup.

  Returns the lowest-preference MX hostname for the domain.
  Falls back to smtp.{domain} if MX lookup fails or dnspython is not installed.
  Install the optional dependency with: pip install oneid[mx]
  """
  try:
    import dns.resolver
    mx_records = dns.resolver.resolve(domain_name, "MX")
    lowest_preference_mx_record = min(mx_records, key=lambda r: r.preference)
    return str(lowest_preference_mx_record.exchange).rstrip(".")
  except Exception:
    return f"smtp.{domain_name}"


@dataclass
class SendResult:
  """Result of a mailpal.send() call."""
  message_id: Optional[str] = None
  from_address: Optional[str] = None
  attestation_headers_included: bool = False
  contact_token_header_included: bool = False
  sd_jwt_header_included: bool = False
  direct_attestation_header_included: bool = False
  rfc5322_message_bytes: Optional[bytes] = None


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


def _extract_public_key_jwk_from_certificate_chain_pem(
  certificate_chain_pem: str,
) -> Optional[Dict[str, Any]]:
  """Extract a JWK dict from the leaf certificate in a PEM chain.

  The leaf cert is the first cert in the chain. Its public key is
  converted to JWK format for use in the Registrar Binding JWS request.
  """
  import base64 as _b64
  try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_types, ec as _ec_types
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    leaf_pem_start = certificate_chain_pem.find("-----BEGIN CERTIFICATE-----")
    leaf_pem_end = certificate_chain_pem.find("-----END CERTIFICATE-----")
    if leaf_pem_start < 0 or leaf_pem_end < 0:
      return None
    leaf_pem = certificate_chain_pem[leaf_pem_start:leaf_pem_end + len("-----END CERTIFICATE-----")]
    cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))
    pub = cert.public_key()

    if isinstance(pub, _rsa_types.RSAPublicKey):
      numbers = pub.public_numbers()
      n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
      e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
      return {
        "kty": "RSA",
        "n": _b64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii"),
        "e": _b64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode("ascii"),
      }
    elif isinstance(pub, _ec_types.EllipticCurvePublicKey):
      numbers = pub.public_numbers()
      key_size = (pub.key_size + 7) // 8
      x_bytes = numbers.x.to_bytes(key_size, "big")
      y_bytes = numbers.y.to_bytes(key_size, "big")
      crv = "P-256" if pub.key_size == 256 else "P-384" if pub.key_size == 384 else "P-521"
      return {
        "kty": "EC",
        "crv": crv,
        "x": _b64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode("ascii"),
        "y": _b64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode("ascii"),
      }
    return None
  except Exception as extraction_error:
    logger.warning("Could not extract JWK from certificate chain: %s", extraction_error)
    return None


def _fold_long_header_value_for_smtp_transmission(header_name: str, header_value: str) -> str:
  """Fold AIRS fields only at locations their individual ABNF permits."""
  preferred_physical_line_length = 78
  hard_maximum_physical_line_length = 998
  lowercase_header_name = header_name.lower()

  if lowercase_header_name == "hardware-trust-proof":
    # The Hardware-Trust-Proof ABNF explicitly permits transport FWS at any
    # position in the SD-JWT serialization, so fixed-size chunks are legal.
    first_line_prefix = f"{header_name}: "
    folded_physical_lines = []
    remaining_encoded_value = header_value
    next_line_prefix = first_line_prefix
    while remaining_encoded_value:
      available_character_count = preferred_physical_line_length - len(next_line_prefix)
      encoded_value_chunk = remaining_encoded_value[:available_character_count]
      folded_physical_lines.append(next_line_prefix + encoded_value_chunk)
      remaining_encoded_value = remaining_encoded_value[len(encoded_value_chunk):]
      next_line_prefix = " "
    if not folded_physical_lines:
      folded_physical_lines = [first_line_prefix]
  elif lowercase_header_name == "hardware-attestation":
    # Structured fields are split at semicolon tag boundaries. Only h= colon
    # separators and the chain=/bind= encoded values permit internal FWS.
    parameter_segments = [segment.strip(" \t") for segment in header_value.split(";")]
    if any(not segment or "=" not in segment for segment in parameter_segments):
      raise ValueError("Hardware-Attestation contains an invalid parameter segment")
    folded_physical_lines = []
    for parameter_segment_index, parameter_segment in enumerate(parameter_segments):
      parameter_name, parameter_value = parameter_segment.split("=", 1)
      physical_line_prefix = f"{header_name}: " if parameter_segment_index == 0 else " "
      parameter_physical_lines = []
      if parameter_name == "h":
        signed_header_names = parameter_value.split(":")
        if any(not signed_header_name for signed_header_name in signed_header_names):
          raise ValueError("Hardware-Attestation h parameter contains an empty field name")
        current_physical_line = physical_line_prefix + "h=" + signed_header_names[0]
        for signed_header_name in signed_header_names[1:]:
          next_header_name_with_separator = ":" + signed_header_name
          if len(current_physical_line) + len(next_header_name_with_separator) <= preferred_physical_line_length:
            current_physical_line += next_header_name_with_separator
          else:
            parameter_physical_lines.append(current_physical_line + ":")
            current_physical_line = " " + signed_header_name
        parameter_physical_lines.append(current_physical_line)
      elif parameter_name in ("chain", "bind"):
        first_encoded_line_prefix = physical_line_prefix + parameter_name + "="
        remaining_encoded_value = parameter_value
        next_encoded_line_prefix = first_encoded_line_prefix
        while remaining_encoded_value:
          available_character_count = preferred_physical_line_length - len(next_encoded_line_prefix)
          encoded_value_chunk = remaining_encoded_value[:available_character_count]
          parameter_physical_lines.append(next_encoded_line_prefix + encoded_value_chunk)
          remaining_encoded_value = remaining_encoded_value[len(encoded_value_chunk):]
          next_encoded_line_prefix = " "
        if not parameter_physical_lines:
          parameter_physical_lines = [first_encoded_line_prefix]
      else:
        parameter_physical_lines = [physical_line_prefix + parameter_segment]

      if parameter_segment_index < len(parameter_segments) - 1:
        parameter_physical_lines[-1] += ";"
      folded_physical_lines.extend(parameter_physical_lines)
  else:
    full_line = f"{header_name}: {header_value}"
    if len(full_line) > hard_maximum_physical_line_length:
      raise ValueError(f"No legal AIRS folding rule is defined for {header_name}")
    folded_physical_lines = [full_line]

  if any(
    len(physical_line) > hard_maximum_physical_line_length
    for physical_line in folded_physical_lines
  ):
    raise ValueError(
      f"Folded {header_name} contains a physical line longer than "
      f"{hard_maximum_physical_line_length} characters"
    )
  return "\r\n".join(folded_physical_lines)


def _assemble_hardware_trust_proof_presentation_value(
  mode2_sd_jwt_proof: AttestationProof,
) -> Optional[str]:
  """Assemble the exact Mode-2 value once so Combined Mode signs what is sent."""
  if not mode2_sd_jwt_proof.sd_jwt:
    return None
  sd_jwt_presentation_value = mode2_sd_jwt_proof.sd_jwt
  for disclosure_b64url in mode2_sd_jwt_proof.sd_jwt_disclosures.values():
    sd_jwt_presentation_value += "~" + disclosure_b64url
  if mode2_sd_jwt_proof.sd_jwt_disclosures:
    sd_jwt_presentation_value += "~"
  return sd_jwt_presentation_value


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
  reply_to: Optional[str] = None,
  in_reply_to: Optional[str] = None,
  references: Optional[str] = None,
  attachments: Optional[List[Dict[str, Any]]] = None,
  include_attestation: bool = True,
  attestation_mode: str = "both",
  disclosed_claims: Optional[List[str]] = None,
  oneid_api_url: Optional[str] = None,
  smtp_host: Optional[str] = None,
  smtp_port: Optional[int] = None,
  smtp_username: Optional[str] = None,
  smtp_password: Optional[str] = None,
  smtp_domain: Optional[str] = None,
  smtp_security: Optional[str] = None,
  smtp_envelope_from: Optional[str] = None,
  deliver: bool = True,
  signing_device_type: Optional[str] = None,
  piv_serial_number: Optional[int] = None,
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
    reply_to: Reply-To address (where replies should go, if different from sender).
    in_reply_to: Message-ID of the email being replied to (for threading).
    references: Space-separated Message-IDs of the thread (for threading).
    attachments: List of attachment dicts, each with keys:
        filename (str), content_base64 (str), content_type (str, optional),
        inline (bool, optional), content_id (str, optional for inline images).
    include_attestation: Whether to include attestation headers (default True).
    attestation_mode: Which RFC attestation mode(s) to use:
      "both"    -- Combined Mode (Section 7: both headers, default).
                   Mode 1 is silently skipped if the identity lacks a cert chain.
      "sd-jwt"  -- Mode 2 only (Hardware-Trust-Proof header)
      "direct"  -- Mode 1 only (Hardware-Attestation header with CMS bundle)
      "none"    -- No attestation headers (overrides include_attestation)
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["aid"].
    oneid_api_url: Override the 1id.com API URL.
    smtp_host: Override SMTP host (default: smtp.mailpal.com). Accepts
        hostname, IPv4, or IPv6 in brackets (e.g. "[2001:db8::1]").
    smtp_port: Override SMTP port. Default depends on smtp_security:
        587 for starttls, 465 for tls, 25 for none.
    smtp_username: Override SMTP auth username (default: stored mailpal_email).
        Use this to send from a different account while still using the
        agent's 1id identity for attestation signing. The SMTP envelope
        MAIL FROM uses this value (not from_address), so the authenticated
        account must match what the SMTP server permits.
    smtp_password: Override SMTP auth password. Required when smtp_username
        is set. This is the app_password for the SMTP account.
    smtp_domain: Domain name for MX auto-discovery (alternative to smtp_host).
        When provided and smtp_host is not, performs DNS MX lookup on this
        domain. Falls back to smtp.{domain} if MX lookup fails. Requires
        the optional dnspython dependency: pip install oneid[mx]
    smtp_security: TLS mode for SMTP connection. One of:
        "starttls" (default) - plain connect then upgrade via STARTTLS (port 587)
        "tls" - direct TLS/SMTPS connection (port 465)
        "none" - no encryption, plain SMTP (port 25, trusted relays only)
    smtp_envelope_from: Explicit SMTP envelope MAIL FROM override. When set,
        this address is used instead of smtp_username as the envelope sender.
        Use when the SMTP relay allows sending on behalf of arbitrary addresses.
    deliver: If True (default), submit the assembled message via SMTP.
        If False, skip SMTP delivery and return the complete RFC 5322
        message bytes in SendResult.rfc5322_message_bytes. Use this to
        get a fully signed and attested message for delivery through
        your own SMTP server, archival, or downstream processing.

  Returns:
    SendResult with message_id and attestation details.
    When deliver=False, rfc5322_message_bytes contains the complete
    RFC 5322 message including any attestation headers.
  """
  creds = load_credentials()

  effective_smtp_auth_username = smtp_username or creds.mailpal_email or f"{creds.client_id}@mailpal.com"
  effective_smtp_auth_password = smtp_password or creds.mailpal_app_password
  if deliver and not effective_smtp_auth_password:
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
  if reply_to:
    mime_message["Reply-To"] = reply_to
  if in_reply_to:
    mime_message["In-Reply-To"] = in_reply_to
  if references:
    mime_message["References"] = references

  _FORCED_CTE_FOR_STALWART_COMPAT = "quoted-printable"

  if text_body and html_body:
    mime_message.set_content(text_body, cte=_FORCED_CTE_FOR_STALWART_COMPAT)
    mime_message.add_alternative(html_body, subtype="html", cte=_FORCED_CTE_FOR_STALWART_COMPAT)
  elif html_body:
    mime_message.set_content(html_body, subtype="html", cte=_FORCED_CTE_FOR_STALWART_COMPAT)
  else:
    mime_message.set_content(text_body or "", cte=_FORCED_CTE_FOR_STALWART_COMPAT)

  if attachments:
    import base64 as _b64
    for attachment_spec in attachments:
      raw_bytes = _b64.b64decode(attachment_spec["content_base64"])
      mime_type = attachment_spec.get("content_type", "application/octet-stream")
      maintype, _, subtype = mime_type.partition("/")
      attachment_filename = attachment_spec.get("filename", "attachment")
      if attachment_spec.get("inline") and attachment_spec.get("content_id"):
        mime_message.add_attachment(
          raw_bytes,
          maintype=maintype,
          subtype=subtype or "octet-stream",
          filename=attachment_filename,
          disposition="inline",
          cid=attachment_spec["content_id"],
        )
      else:
        mime_message.add_attachment(
          raw_bytes,
          maintype=maintype,
          subtype=subtype or "octet-stream",
          filename=attachment_filename,
        )

  wire_format_message_bytes = mime_message.as_bytes()

  # -- Phase 2: Parse wire bytes to extract headers identically to milter --
  parsed_wire_message = email_stdlib.message_from_bytes(
    wire_format_message_bytes, policy=email.policy.compat32,
  )

  # Email draft: Mode 2 always covers the nine fields (REC-04); a five-field
  # subset here made every sent Mode 2 nonce mismatch the delivered message.
  from .attestation import _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING as _MODE2_REQUIRED_HEADER_NAMES
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
  folded_hardware_trust_proof_header_line = None

  if include_attestation:
    include_sd_jwt_mode = attestation_mode in ("sd-jwt", "both")
    include_direct_mode = attestation_mode in ("direct", "both")
    combined_mode_is_requested = include_sd_jwt_mode and include_direct_mode

    # Mode 1's proof key and Registrar binding come FIRST: in Combined mode the
    # Mode 2 issuance must carry that key as cnf.jwk (AUD-F47) and must disclose
    # sub whenever Mode 1 will carry aid (AUD-F48; email draft Combined mode).
    fetched_binding_jws = None
    proof_public_key_jwk = None
    if include_direct_mode:
      # Phase 3: Use the per-device cert chain if signing with a specific device
      cert_chain_for_binding_jws = creds.identity_certificate_chain_pem
      if signing_device_type and creds.device_certificate_chains:
        for _fp, _chain_data in creds.device_certificate_chains.items():
          if isinstance(_chain_data, dict) and _chain_data.get("device_type") == signing_device_type:
            cert_chain_for_binding_jws = _chain_data.get("certificate_chain_pem", cert_chain_for_binding_jws)
            break
      if cert_chain_for_binding_jws:
        proof_public_key_jwk = _extract_public_key_jwk_from_certificate_chain_pem(cert_chain_for_binding_jws)
      if proof_public_key_jwk and creds.agent_identity_urn:
        try:
          from .attestation import _fetch_binding_jws
          token_for_binding = get_token()
          binding_auth_headers = {
            "Authorization": f"Bearer {token_for_binding.access_token}",
            "User-Agent": USER_AGENT,
          }
          api_base = oneid_api_url or creds.api_base_url or "https://1id.com"
          fetched_binding_jws = _fetch_binding_jws(
            api_base, binding_auth_headers, proof_public_key_jwk)
          if fetched_binding_jws:
            logger.info("Fetched Registrar Binding JWS for Mode 1")
          else:
            logger.warning("Binding JWS not available; Mode 1 will lack aid and bind")
        except Exception as binding_error:
          logger.warning("Failed to fetch binding JWS: %s", binding_error)

    def _request_and_fold_mode2_proof(cnf_jwk_for_combined_mode, additional_disclosed_claims):
      requested_disclosed_claims = list(disclosed_claims) if disclosed_claims is not None else ["aid"]
      for claim_name in additional_disclosed_claims:
        if claim_name not in requested_disclosed_claims:
          requested_disclosed_claims.append(claim_name)
      issued_proof = prepare_attestation(
        email_headers=wire_format_headers_for_mode2_nonce,
        body=wire_format_body_bytes,
        disclosed_claims=requested_disclosed_claims,
        api_base_url=oneid_api_url,
        override_session_device_type=signing_device_type,
        cnf_jwk=cnf_jwk_for_combined_mode,
      )
      presentation_value = _assemble_hardware_trust_proof_presentation_value(issued_proof)
      folded_line = (
        _fold_long_header_value_for_smtp_transmission("Hardware-Trust-Proof", presentation_value)
        if presentation_value else None
      )
      return issued_proof, folded_line

    mode2_carries_combined_mode_cnf = False
    if include_sd_jwt_mode:
      try:
        if combined_mode_is_requested and proof_public_key_jwk:
          mode2_sd_jwt_proof, folded_hardware_trust_proof_header_line = _request_and_fold_mode2_proof(
            proof_public_key_jwk, ["sub"] if fetched_binding_jws else [])
          mode2_carries_combined_mode_cnf = True
        else:
          mode2_sd_jwt_proof, folded_hardware_trust_proof_header_line = _request_and_fold_mode2_proof(None, [])
      except Exception as mode2_error:
        logger.warning("Mode 2 (SD-JWT) attestation failed: %s", mode2_error)
        mode2_sd_jwt_proof, folded_hardware_trust_proof_header_line = None, None

    if folded_hardware_trust_proof_header_line:
      # Combined Mode must feed the exact emitted, folded Mode-2 value into
      # Mode 1 before the Hardware-Attestation signature is calculated.
      wire_format_all_headers_for_mode1["hardware-trust-proof"] = (
        folded_hardware_trust_proof_header_line.split(":", 1)[1]
      )

    if include_direct_mode:
      try:
        from .attestation import prepare_direct_hardware_attestation
        mode1_direct_attestation_proof = prepare_direct_hardware_attestation(
          email_headers=wire_format_all_headers_for_mode1,
          body=wire_format_body_bytes,
          binding_jws=fetched_binding_jws,
          override_signing_device_type=signing_device_type,
          piv_serial_number=piv_serial_number,
        )
      except Exception as mode1_error:
        logger.warning("Mode 1 (direct) attestation failed: %s", mode1_error)

    # INV-E3: a Mode 2 proof carrying the Combined-mode cnf must never travel
    # without its Mode 1 (verifiers must reject that rather than degrade), so
    # if Mode 1 failed, replace it with a standalone Mode 2 (cnf absent).
    if mode2_carries_combined_mode_cnf and mode1_direct_attestation_proof is None:
      try:
        mode2_sd_jwt_proof, folded_hardware_trust_proof_header_line = _request_and_fold_mode2_proof(None, [])
      except Exception as mode2_retry_error:
        logger.warning("Standalone Mode 2 fallback failed: %s", mode2_retry_error)
        mode2_sd_jwt_proof, folded_hardware_trust_proof_header_line = None, None

  # -- Phase 4: Build attestation header lines for injection --
  attestation_header_lines_to_inject: List[str] = []

  if mode2_sd_jwt_proof:
    if folded_hardware_trust_proof_header_line:
      # Mode 2 is emitted first because the following Mode-1 proof covers it.
      attestation_header_lines_to_inject.append(folded_hardware_trust_proof_header_line)
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

  generated_message_id = mime_message["Message-ID"]

  if not deliver:
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
      rfc5322_message_bytes=final_message_bytes,
    )

  # -- Phase 6: Submit via SMTP --
  if smtp_host:
    effective_smtp_host = smtp_host
  elif smtp_domain:
    effective_smtp_host = _discover_smtp_submission_host_via_mx_lookup(smtp_domain)
  else:
    effective_smtp_host = _SMTP_HOST

  effective_smtp_security = smtp_security or "starttls"
  if effective_smtp_security not in _SMTP_SECURITY_MODE_TO_DEFAULT_PORT:
    raise ValueError(
      f"Invalid smtp_security={effective_smtp_security!r}. "
      f"Must be 'starttls', 'tls', or 'none'."
    )
  effective_smtp_port = smtp_port or _SMTP_SECURITY_MODE_TO_DEFAULT_PORT[effective_smtp_security]
  effective_envelope_sender = smtp_envelope_from or effective_smtp_auth_username

  envelope_recipients = _extract_all_envelope_recipient_addresses(to, cc, bcc)
  if not envelope_recipients:
    raise ValueError("No valid recipient email addresses found in to/cc/bcc.")

  try:
    if effective_smtp_security == "tls":
      with smtplib.SMTP_SSL(effective_smtp_host, effective_smtp_port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp_connection:
        smtp_connection.ehlo()
        if effective_smtp_auth_username and effective_smtp_auth_password:
          smtp_connection.login(effective_smtp_auth_username, effective_smtp_auth_password)
        smtp_connection.sendmail(effective_envelope_sender, envelope_recipients, final_message_bytes)
    elif effective_smtp_security == "starttls":
      with smtplib.SMTP(effective_smtp_host, effective_smtp_port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp_connection:
        smtp_connection.ehlo()
        smtp_connection.starttls()
        smtp_connection.ehlo()
        if effective_smtp_auth_username and effective_smtp_auth_password:
          smtp_connection.login(effective_smtp_auth_username, effective_smtp_auth_password)
        smtp_connection.sendmail(effective_envelope_sender, envelope_recipients, final_message_bytes)
    else:
      with smtplib.SMTP(effective_smtp_host, effective_smtp_port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp_connection:
        smtp_connection.ehlo()
        if effective_smtp_auth_username and effective_smtp_auth_password:
          smtp_connection.login(effective_smtp_auth_username, effective_smtp_auth_password)
        smtp_connection.sendmail(effective_envelope_sender, envelope_recipients, final_message_bytes)
  except smtplib.SMTPAuthenticationError as smtp_auth_error:
    raise AuthenticationError(
      f"SMTP authentication failed for {effective_smtp_auth_username}: {smtp_auth_error}"
    ) from smtp_auth_error
  except (smtplib.SMTPException, OSError) as smtp_error:
    raise NetworkError(f"SMTP submission failed: {smtp_error}") from smtp_error

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
      received_at=msg.get("date", msg.get("received_at", "")),
      is_unread=not msg.get("is_read", False) if "is_read" in msg else msg.get("is_unread", True),
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
