"""
Protocol-agnostic attestation primitive for the 1id.com SDK.

Supports both RFC attestation modes:

  Mode 1 (Section 5): Direct Hardware Attestation -- Hardware-Attestation header
    CMS SignedData bundle with hardware signature + certificate chain.
    No issuer interaction needed; verifier validates the hardware cert chain directly.

  Mode 2 (Section 6): SD-JWT Trust Proof -- Hardware-Trust-Proof header
    Per-message SD-JWT from 1id.com issuer with selective disclosure.
    Privacy-preserving (no hardware fingerprint revealed).

  Combined (Section 7): Both headers in one message.

Usage:
    # Mode 2 (SD-JWT, default)
    proof = oneid.prepare_attestation(
        email_headers={...}, body=b"Message body",
    )

    # Mode 1 (Direct Hardware Attestation)
    proof = oneid.prepare_direct_hardware_attestation(
        email_headers={...}, body=b"Message body",
    )

RFC: draft-drake-email-hardware-attestation-00
"""

from __future__ import annotations

import base64
import email.header
import hashlib
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ._version import USER_AGENT
from .auth import get_token
from .credentials import DEFAULT_API_BASE_URL, load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.attestation")

_HTTP_TIMEOUT_SECONDS = 15.0

_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = [
  "from", "to", "subject", "date", "message-id",
]

_TRUST_TIER_TO_RFC_TYP_PARAMETER = {
  "sovereign": "TPM",
  "portable": "PIV",
  "enclave": "ENC",
  "virtual": "VRT",
  "declared": "SFT",
}


@dataclass
class AttestationProof:
  """Result of prepare_attestation() or prepare_direct_hardware_attestation()."""
  sd_jwt: Optional[str] = None
  sd_jwt_disclosures: Dict[str, str] = field(default_factory=dict)
  contact_token: Optional[str] = None
  contact_address: Optional[str] = None
  tpm_signature_b64: Optional[str] = None
  content_digest: Optional[str] = None
  hardware_attestation_header_value: Optional[str] = None


def canonicalise_headers_for_direct_attestation(
  email_headers: Dict[str, str],
  hardware_attestation_header_value_without_chain: str = "",
) -> bytes:
  """Canonicalise email headers for Mode 1 (Hardware-Attestation) h-hash.

  Same rules as canonicalise_headers_for_message_binding(), but appends
  hardware-attestation: (instead of hardware-trust-proof:) as the final
  self-referencing header per RFC Section 5.2.

  The hardware_attestation_header_value_without_chain parameter should
  contain all header parameters EXCEPT with chain= set to the empty
  string, matching the DKIM self-inclusion convention (RFC 6376 Section 3.7).
  """
  lowered_headers = {k.strip().lower(): v for k, v in email_headers.items()}

  for required_header_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
    if required_header_name not in lowered_headers:
      raise ValueError(
        f"Missing required email header '{required_header_name}' for Mode 1 attestation. "
        f"Required headers: {_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING}"
      )

  all_header_names = list(_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING)
  extra_names = sorted(
    h for h in lowered_headers
    if h not in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING
    and h not in ("hardware-attestation", "hardware-trust-proof")
  )
  all_header_names.extend(extra_names)
  all_header_names = all_header_names + list(all_header_names)

  message_header_pairs = list(lowered_headers.items())
  selected = _select_headers_bottom_up_per_dkim(all_header_names, message_header_pairs)

  canonicalised_header_lines = []
  for entry in selected:
    if entry is None:
      continue
    canon_name = canonicalise_header_name_using_dkim_relaxed(entry[0])
    canon_value = canonicalise_header_value_using_dkim_relaxed(entry[1])
    canonicalised_header_lines.append(f"{canon_name}:{canon_value}\r\n")

  self_referencing_attestation_line = f"hardware-attestation:{hardware_attestation_header_value_without_chain}"
  canonicalised_header_lines.append(self_referencing_attestation_line)

  return "".join(canonicalised_header_lines).encode("utf-8")


def compute_attestation_digest_for_direct_mode(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  attestation_timestamp_unix: int,
  hardware_attestation_header_value_without_chain: str = "",
) -> bytes:
  """Compute the attestation-digest for Mode 1 (RFC Section 5.2).

  attestation-input = h-hash || bh-raw || ts-bytes   (72 bytes)
  attestation-digest = SHA-256(attestation-input)     (32 bytes)

  The h-hash includes the Hardware-Attestation header itself with chain=""
  (self-referencing, per DKIM convention).
  """
  canonicalised_header_bytes = canonicalise_headers_for_direct_attestation(
    email_headers,
    hardware_attestation_header_value_without_chain,
  )
  h_hash = hashlib.sha256(canonicalised_header_bytes).digest()

  canonicalised_body = canonicalise_body_using_dkim_simple(body_bytes)
  bh_raw = hashlib.sha256(canonicalised_body).digest()

  ts_bytes = struct.pack(">Q", attestation_timestamp_unix)

  attestation_input = h_hash + bh_raw + ts_bytes
  return hashlib.sha256(attestation_input).digest()


def _der_encode_length(length_value: int) -> bytes:
  """Encode a length value in DER format (ASN.1 definite-length encoding)."""
  if length_value < 0x80:
    return bytes([length_value])
  elif length_value < 0x100:
    return bytes([0x81, length_value])
  elif length_value < 0x10000:
    return bytes([0x82, (length_value >> 8) & 0xFF, length_value & 0xFF])
  elif length_value < 0x1000000:
    return bytes([0x83, (length_value >> 16) & 0xFF, (length_value >> 8) & 0xFF, length_value & 0xFF])
  else:
    return bytes([0x84]) + length_value.to_bytes(4, "big")


def _der_encode_tag_length_value(tag_byte: int, content_bytes: bytes) -> bytes:
  """Encode a complete DER TLV (tag-length-value) element."""
  return bytes([tag_byte]) + _der_encode_length(len(content_bytes)) + content_bytes


def _der_encode_integer(integer_value: int) -> bytes:
  """Encode a non-negative integer in DER format."""
  if integer_value == 0:
    return _der_encode_tag_length_value(0x02, b"\x00")
  byte_length = (integer_value.bit_length() + 8) // 8
  integer_bytes = integer_value.to_bytes(byte_length, "big")
  return _der_encode_tag_length_value(0x02, integer_bytes)


def _der_encode_oid(oid_dotted_string: str) -> bytes:
  """Encode an OID in DER format."""
  components = [int(c) for c in oid_dotted_string.split(".")]
  if len(components) < 2:
    raise ValueError(f"OID must have at least 2 components: {oid_dotted_string}")
  first_octet = 40 * components[0] + components[1]
  encoded_body = bytes([first_octet])
  for component in components[2:]:
    if component < 0x80:
      encoded_body += bytes([component])
    else:
      base128_digits = []
      remaining = component
      while remaining > 0:
        base128_digits.append(remaining & 0x7F)
        remaining >>= 7
      base128_digits.reverse()
      for i, digit in enumerate(base128_digits):
        if i < len(base128_digits) - 1:
          encoded_body += bytes([digit | 0x80])
        else:
          encoded_body += bytes([digit])
  return _der_encode_tag_length_value(0x06, encoded_body)


_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_DATA = "1.2.840.113549.1.7.1"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
_OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
_OID_RSA_PSS = "1.2.840.113549.1.1.10"

_RFC_ALG_TO_SIGNATURE_OID = {
  "RS256": _OID_SHA256_WITH_RSA,
  "ES256": _OID_ECDSA_WITH_SHA256,
  "PS256": _OID_RSA_PSS,
}


def build_cms_signed_data_for_direct_attestation(
  signature_bytes: bytes,
  certificate_chain_pem: str,
  signature_algorithm_rfc_name: str,
) -> bytes:
  """Build a CMS SignedData (RFC 5652) DER structure for Mode 1.

  Creates a detached-signature CMS bundle containing:
  - The hardware AK signature over the attestation-digest
  - The full certificate chain (leaf/AK cert first, then intermediates, then root)
  - DigestAlgorithm: SHA-256
  - SignatureAlgorithm: per the signature_algorithm_rfc_name parameter

  Returns raw DER bytes (caller base64-encodes for the header).
  """
  leaf_certificate = None
  certificate_der_list = []
  for pem_block in certificate_chain_pem.split("-----END CERTIFICATE-----"):
    pem_block = pem_block.strip()
    if pem_block and "-----BEGIN CERTIFICATE-----" in pem_block:
      full_pem = pem_block + "\n-----END CERTIFICATE-----\n"
      cert_object = x509.load_pem_x509_certificate(full_pem.encode("ascii"))
      certificate_der_list.append(cert_object.public_bytes(Encoding.DER))
      if leaf_certificate is None:
        leaf_certificate = cert_object

  if leaf_certificate is None:
    raise ValueError("Certificate chain PEM contains no parseable certificates")

  signature_oid_string = _RFC_ALG_TO_SIGNATURE_OID.get(signature_algorithm_rfc_name)
  if signature_oid_string is None:
    raise ValueError(f"Unsupported signature algorithm: {signature_algorithm_rfc_name}")

  sha256_algorithm_identifier = _der_encode_tag_length_value(
    0x30,
    _der_encode_oid(_OID_SHA256) + _der_encode_tag_length_value(0x05, b""),
  )

  digest_algorithms_set = _der_encode_tag_length_value(0x31, sha256_algorithm_identifier)

  encap_content_info = _der_encode_tag_length_value(
    0x30,
    _der_encode_oid(_OID_DATA),
  )

  all_certs_content = b"".join(certificate_der_list)
  certificates_implicit_set = _der_encode_tag_length_value(0xA0, all_certs_content)

  issuer_der_bytes = leaf_certificate.issuer.public_bytes()
  serial_number_der = _der_encode_integer(leaf_certificate.serial_number)
  issuer_and_serial_number = _der_encode_tag_length_value(
    0x30,
    issuer_der_bytes + serial_number_der,
  )

  signature_algorithm_identifier = _der_encode_tag_length_value(
    0x30,
    _der_encode_oid(signature_oid_string),
  )

  signature_octet_string = _der_encode_tag_length_value(0x04, signature_bytes)

  signer_info = _der_encode_tag_length_value(
    0x30,
    _der_encode_integer(1)
    + issuer_and_serial_number
    + sha256_algorithm_identifier
    + signature_algorithm_identifier
    + signature_octet_string,
  )

  signer_infos_set = _der_encode_tag_length_value(0x31, signer_info)

  signed_data = _der_encode_tag_length_value(
    0x30,
    _der_encode_integer(1)
    + digest_algorithms_set
    + encap_content_info
    + certificates_implicit_set
    + signer_infos_set,
  )

  content_info = _der_encode_tag_length_value(
    0x30,
    _der_encode_oid(_OID_SIGNED_DATA)
    + _der_encode_tag_length_value(0xA0, signed_data),
  )

  return content_info


def prepare_direct_hardware_attestation(
  email_headers: Dict[str, str],
  body: bytes,
  agent_identity_urn: Optional[str] = None,
) -> AttestationProof:
  """Prepare a Mode 1 (Direct Hardware Attestation) proof.

  Signs the email content with the enrolled hardware key and assembles
  the Hardware-Attestation header per RFC Section 5.

  This function:
  1. Determines the hardware type and signing algorithm from credentials
  2. Builds the header template (all params except chain)
  3. Computes the attestation-digest (h-hash || bh-raw || ts-bytes)
  4. Signs the digest with the hardware key
  5. Builds the CMS SignedData envelope
  6. Assembles the final Hardware-Attestation header value

  Args:
    email_headers: Dict of email header name -> value.
    body: Raw email body bytes.
    agent_identity_urn: Optional URN override (default: from credentials).

  Returns:
    AttestationProof with hardware_attestation_header_value populated.
  """
  from .credentials import load_credentials as _load_creds
  from .verify import _sign_with_tpm, _sign_with_piv, _sign_with_enclave, _sign_with_software_key, _determine_signing_algorithm_name

  creds = _load_creds()
  trust_tier = creds.trust_tier or "declared"
  typ_parameter = _TRUST_TIER_TO_RFC_TYP_PARAMETER.get(trust_tier, "SFT")

  if not creds.identity_certificate_chain_pem:
    raise NotEnrolledError(
      "Mode 1 (Direct Hardware Attestation) requires a certificate chain. "
      "This identity was enrolled before certificate issuance was available. "
      "Re-enroll to obtain an identity certificate."
    )

  if agent_identity_urn is None:
    agent_identity_urn_from_credentials = getattr(creds, "agent_identity_urn", None)
    if agent_identity_urn_from_credentials:
      agent_identity_urn = agent_identity_urn_from_credentials

  attestation_timestamp = int(time.time())

  canonicalised_body = canonicalise_body_using_dkim_simple(body)
  bh_raw = hashlib.sha256(canonicalised_body).digest()
  bh_base64url = base64.urlsafe_b64encode(bh_raw).rstrip(b"=").decode("ascii")

  lowered_headers = {k.strip().lower(): v for k, v in email_headers.items()}
  all_signed_names = list(_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING)
  extra_header_names = sorted(
    h for h in lowered_headers
    if h not in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING
    and h not in ("hardware-attestation", "hardware-trust-proof")
  )
  all_signed_names.extend(extra_header_names)
  signed_header_names = ":".join(all_signed_names) + ":" + ":".join(all_signed_names)

  if trust_tier == "portable" or trust_tier == "enclave":
    algorithm_for_header = "ES256"
  elif trust_tier in ("sovereign", "virtual") or creds.key_algorithm == "tpm-ak":
    algorithm_for_header = "RS256"
  elif creds.private_key_pem:
    algo_name = _determine_signing_algorithm_name(creds)
    algorithm_for_header = algo_name
  else:
    raise NotEnrolledError("No signing key available for Mode 1 attestation.")

  header_template_without_chain = (
    f"v=1; typ={typ_parameter}; alg={algorithm_for_header}; "
    f"h={signed_header_names}; bh={bh_base64url}; ts={attestation_timestamp}; "
    f"chain="
  )
  if agent_identity_urn:
    header_template_without_chain_with_aid = header_template_without_chain + f"; aid={agent_identity_urn}"
  else:
    header_template_without_chain_with_aid = header_template_without_chain

  attestation_digest = compute_attestation_digest_for_direct_mode(
    email_headers=email_headers,
    body_bytes=body,
    attestation_timestamp_unix=attestation_timestamp,
    hardware_attestation_header_value_without_chain=header_template_without_chain_with_aid,
  )

  if trust_tier == "portable":
    signature_bytes, resolved_algorithm = _sign_with_piv(attestation_digest)
  elif trust_tier == "enclave":
    signature_bytes, resolved_algorithm = _sign_with_enclave(attestation_digest)
  elif trust_tier in ("sovereign", "virtual") or creds.key_algorithm == "tpm-ak":
    ak_handle = creds.hsm_key_reference or ""
    signature_bytes, resolved_algorithm = _sign_with_tpm(attestation_digest, ak_handle)
  elif creds.private_key_pem:
    signature_bytes = _sign_with_software_key(attestation_digest, creds.private_key_pem)
    resolved_algorithm = algorithm_for_header
  else:
    raise NotEnrolledError("No signing key available.")

  cms_der_bytes = build_cms_signed_data_for_direct_attestation(
    signature_bytes=signature_bytes,
    certificate_chain_pem=creds.identity_certificate_chain_pem,
    signature_algorithm_rfc_name=algorithm_for_header,
  )
  chain_base64 = base64.b64encode(cms_der_bytes).decode("ascii")

  final_header_value = (
    f"v=1; typ={typ_parameter}; alg={algorithm_for_header}; "
    f"h={signed_header_names}; bh={bh_base64url}; ts={attestation_timestamp}; "
    f"chain={chain_base64}"
  )
  if agent_identity_urn:
    final_header_value += f"; aid={agent_identity_urn}"

  body_digest_hex = hashlib.sha256(body).hexdigest()

  return AttestationProof(
    hardware_attestation_header_value=final_header_value,
    content_digest=f"sha256:{body_digest_hex}",
  )


def decode_rfc2047_encoded_words_to_unicode(raw_header_value: str) -> str:
  """Decode RFC 2047 encoded-words in a header value to plain Unicode.

  MTAs may re-encode RFC 2047 differently (e.g. splitting across fold points,
  or consolidating multiple encoded-words). Decoding before canonicalization
  ensures the attestation hash is independent of encoding representation.

  Pure-ASCII headers pass through unchanged. Only headers containing
  =?charset?encoding?text?= sequences are affected.
  """
  try:
    decoded_parts = email.header.decode_header(raw_header_value)
    decoded_unicode = str(email.header.make_header(decoded_parts))
    return decoded_unicode
  except Exception:
    return raw_header_value


def canonicalise_header_value_using_dkim_relaxed(raw_value: str) -> str:
  """RFC 6376 Section 3.4.2 relaxed header canonicalization (value part only).

  Pre-step: Decode RFC 2047 encoded-words to Unicode.
  Then standard DKIM relaxed:
  1. Normalize all line endings to CRLF.
  2. Unfold header continuation lines (CRLF followed by WSP).
  3. Compress each sequence of WSP to a single SP.
  4. Strip leading/trailing WSP.
  """
  import re
  decoded_value = decode_rfc2047_encoded_words_to_unicode(raw_value)
  normalized = decoded_value.replace("\r\n", "\n").replace("\n", "\r\n")
  unfolded = re.sub(r"\r\n[ \t]", " ", normalized)
  compressed = re.sub(r"[ \t]+", " ", unfolded)
  return compressed.strip()


def canonicalise_header_name_using_dkim_relaxed(raw_name: str) -> str:
  """RFC 6376 Section 3.4.2: header field names are lowercased."""
  return raw_name.strip().lower()


def _select_headers_bottom_up_per_dkim(
  header_names_from_h_tag: List[str],
  message_headers: List[tuple],
) -> List[Optional[tuple]]:
  """Select header instances per DKIM RFC 6376 Section 3.7 bottom-up rule.

  For each name in header_names_from_h_tag (left to right), scan
  message_headers from bottom to top and consume the bottommost unused
  instance. If no unused instance remains, return None for that slot
  (absent header -- contributes zero bytes to the hash).
  """
  consumed_indices: set = set()
  selected: List[Optional[tuple]] = []
  for requested_name in header_names_from_h_tag:
    target = requested_name.strip().lower()
    found_index = -1
    for i in range(len(message_headers) - 1, -1, -1):
      if i in consumed_indices:
        continue
      if message_headers[i][0].strip().lower() == target:
        found_index = i
        break
    if found_index >= 0:
      consumed_indices.add(found_index)
      selected.append(message_headers[found_index])
    else:
      selected.append(None)
  return selected


def canonicalise_headers_for_message_binding(
  email_headers: Dict[str, str],
  hardware_trust_proof_header_value_placeholder: str = "",
) -> bytes:
  """Canonicalise email headers per RFC 6376 Section 3.4.2 relaxed rules,
  as specified by draft-drake-email-hardware-attestation-00 Section 5.3.

  The required headers (From, To, Subject, Date, Message-ID at minimum) are
  each canonicalised and terminated with CRLF. Then the Hardware-Trust-Proof
  header is appended last with its value replaced by the empty string and
  WITHOUT a trailing CRLF.
  """
  lowered_headers = {k.strip().lower(): v for k, v in email_headers.items()}

  for required_header_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
    if required_header_name not in lowered_headers:
      raise ValueError(
        f"Missing required email header '{required_header_name}' for RFC message-binding nonce. "
        f"Required headers: {_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING}"
      )

  header_names_for_nonce = list(_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING)
  header_names_for_nonce = header_names_for_nonce + list(header_names_for_nonce)

  message_header_pairs = list(lowered_headers.items())
  selected = _select_headers_bottom_up_per_dkim(header_names_for_nonce, message_header_pairs)

  canonicalised_header_lines = []
  for entry in selected:
    if entry is None:
      continue
    canon_name = canonicalise_header_name_using_dkim_relaxed(entry[0])
    canon_value = canonicalise_header_value_using_dkim_relaxed(entry[1])
    canonicalised_header_lines.append(f"{canon_name}:{canon_value}\r\n")

  hardware_trust_proof_line = f"hardware-trust-proof:{hardware_trust_proof_header_value_placeholder}"
  canonicalised_header_lines.append(hardware_trust_proof_line)

  return "".join(canonicalised_header_lines).encode("utf-8")


def canonicalise_body_using_dkim_simple(body_bytes: bytes) -> bytes:
  """RFC 6376 Section 3.4.3 simple body canonicalization.

  Pre-step: Normalize all line endings to CRLF.
  Then: trailing empty lines (CRLF sequences at the very end) are removed.
  If the body is non-empty and does not end with CRLF, a single CRLF is appended.
  """
  if not body_bytes:
    return b"\r\n"
  body_bytes = body_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
  while body_bytes.endswith(b"\r\n\r\n"):
    body_bytes = body_bytes[:-2]
  if not body_bytes.endswith(b"\r\n"):
    body_bytes = body_bytes + b"\r\n"
  return body_bytes


def compute_rfc_message_binding_nonce(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  proposed_iat_unix_timestamp: int,
) -> str:
  """Compute the RFC Section 5.3 message-binding nonce.

  Algorithm:
    message-binding = h-hash || bh-raw || ts-bytes
    nonce = base64url(SHA-256(message-binding))

    h-hash   = SHA-256(canonicalised-headers)  ; 32 bytes
    bh-raw   = SHA-256(canonicalised body)     ; 32 bytes
    ts-bytes = big-endian uint64(iat)          ; 8 bytes

  Returns the nonce as a base64url string (no padding).
  """
  canonicalised_header_bytes = canonicalise_headers_for_message_binding(email_headers)
  h_hash = hashlib.sha256(canonicalised_header_bytes).digest()

  canonicalised_body = canonicalise_body_using_dkim_simple(body_bytes)
  bh_raw = hashlib.sha256(canonicalised_body).digest()

  ts_bytes = struct.pack(">Q", proposed_iat_unix_timestamp)

  message_binding = h_hash + bh_raw + ts_bytes
  nonce_raw = hashlib.sha256(message_binding).digest()

  return base64.urlsafe_b64encode(nonce_raw).rstrip(b"=").decode("ascii")


def prepare_attestation(
  content: Optional[bytes] = None,
  content_digest: Optional[str] = None,
  email_headers: Optional[Dict[str, str]] = None,
  body: Optional[bytes] = None,
  disclosed_claims: Optional[List[str]] = None,
  include_contact_token: bool = True,
  include_sd_jwt: bool = True,
  api_base_url: Optional[str] = None,
) -> AttestationProof:
  """
  Prepare a protocol-agnostic attestation proof.

  Two modes of operation:

  1. **Email attestation (RFC-compliant)**: pass email_headers + body.
     The nonce is computed per draft-drake-email-hardware-attestation-00
     Section 5.3 using DKIM relaxed header canonicalization and a
     header+body+timestamp binding.

  2. **Simple content attestation**: pass content or content_digest.
     The nonce is base64url(SHA-256(content)). Suitable for non-email
     protocols that just need a content binding.

  For email attestation, use oneid.mailpal.send() which calls this
  internally and adds the appropriate email headers.

  Args:
    content: Raw content bytes (simple mode). Will be hashed to SHA-256.
    content_digest: Pre-computed content digest "sha256:hex..." (simple mode).
    email_headers: Dict of email header name -> value (RFC mode).
                   Must include at least From, To, Subject, Date, Message-ID.
    body: Raw email body bytes (RFC mode). Used with email_headers.
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
    ValueError: If argument combinations are invalid.
  """
  rfc_email_mode_is_active = email_headers is not None
  simple_content_mode_is_active = content is not None or content_digest is not None

  if rfc_email_mode_is_active and simple_content_mode_is_active:
    raise ValueError(
      "Cannot mix email_headers/body with content/content_digest. "
      "Use email_headers+body for RFC email attestation, OR content/content_digest for simple mode."
    )

  if rfc_email_mode_is_active and body is None:
    raise ValueError("body is required when email_headers is provided.")

  if content is not None and content_digest is not None:
    raise ValueError("Provide content OR content_digest, not both.")

  if content is not None:
    digest_hex = hashlib.sha256(content).hexdigest()
    content_digest = f"sha256:{digest_hex}"

  if rfc_email_mode_is_active:
    body_digest_hex = hashlib.sha256(body).hexdigest()
    content_digest = f"sha256:{body_digest_hex}"

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
    proposed_iat = int(time.time())

    if rfc_email_mode_is_active:
      nonce_value = compute_rfc_message_binding_nonce(
        email_headers=email_headers,
        body_bytes=body,
        proposed_iat_unix_timestamp=proposed_iat,
      )
    else:
      message_hash = content_digest.split(":", 1)[1] if content_digest and ":" in content_digest else (content_digest or "")
      nonce_value = base64.urlsafe_b64encode(
        bytes.fromhex(message_hash)
      ).rstrip(b"=").decode("ascii")

    hsm_ref = getattr(creds, "hsm_key_reference", None) or ""
    if hsm_ref.startswith("piv-"):
      session_device_type_for_dynamic_trust_tiering = "piv"
    elif hsm_ref == "secure-enclave":
      session_device_type_for_dynamic_trust_tiering = "enclave"
    elif creds.trust_tier == "virtual":
      session_device_type_for_dynamic_trust_tiering = "vtpm"
    elif creds.key_algorithm == "tpm-ak":
      session_device_type_for_dynamic_trust_tiering = "tpm"
    else:
      session_device_type_for_dynamic_trust_tiering = None

    proof.sd_jwt, proof.sd_jwt_disclosures = _fetch_sd_jwt_proof_for_message(
      api_base_url=api_base_url,
      auth_headers=auth_headers,
      precomputed_nonce=nonce_value,
      proposed_iat=proposed_iat,
      disclosed_claims=disclosed_claims,
      session_device_type=session_device_type_for_dynamic_trust_tiering,
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
  precomputed_nonce: str,
  proposed_iat: int,
  disclosed_claims: List[str],
  session_device_type: Optional[str] = None,
) -> tuple:
  """Fetch a per-message SD-JWT proof from the issuer.

  Endpoint: POST /api/v1/proof/sd-jwt/message
  Algorithm: ES256 (server-side, 300s fixed TTL)

  The nonce is pre-computed by the caller (either RFC message-binding
  or simple content hash) and passed as a base64url string.

  When session_device_type is provided, the server uses it for dynamic
  trust tiering -- the SD-JWT trust_tier claim reflects the device used
  for this specific session rather than the identity's enrolled tier.
  """
  url = f"{api_base_url}/api/v1/proof/sd-jwt/message"
  body: Dict[str, Any] = {
    "nonce": precomputed_nonce,
    "proposed_iat": proposed_iat,
    "disclosed_claims": disclosed_claims,
  }
  if session_device_type:
    body["device_type"] = session_device_type

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

