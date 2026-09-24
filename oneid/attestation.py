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

RFC: draft-drake-email-hardware-attestation-03
"""

from __future__ import annotations

import base64
import hashlib
import re
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import _http as httpx  # stdlib-backed drop-in (no httpx dependency)
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ._version import USER_AGENT
from .auth import get_token
from .credentials import DEFAULT_API_BASE_URL, load_credentials
from .exceptions import AuthenticationError, NetworkError, NotEnrolledError

logger = logging.getLogger("oneid.attestation")

_HTTP_TIMEOUT_SECONDS = 15.0

# Email draft (2026-09-24): both modes ALWAYS cover these nine fields; a
# listed field that is absent is fine (DKIM rule: protects against addition).
_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = [
  "from", "to", "subject", "date", "message-id",
  "reply-to", "mime-version", "content-type", "content-transfer-encoding",
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

  all_header_names = list(_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING)
  extra_names = sorted(
    h for h in lowered_headers
    if h not in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING
    and h != "hardware-attestation"
  )
  all_header_names.extend(extra_names)
  all_header_names = all_header_names + list(all_header_names)

  message_header_pairs = list(lowered_headers.items())
  selected = _select_headers_bottom_up_per_dkim(all_header_names, message_header_pairs)

  canonicalised_header_lines = []
  for entry in selected:
    if entry is None:
      continue
    canonicalised_header_lines.append(
      canonicalise_selected_header_field_using_dkim2_header_hash_rules(
        entry[0], entry[1]
      )
    )

  canonicalised_header_lines.append(
    canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
      hardware_attestation_header_value_without_chain
    )
  )

  return "".join(canonicalised_header_lines).encode("utf-8")


def compute_attestation_input_for_direct_mode(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  attestation_timestamp_unix: int,
  hardware_attestation_header_value_without_chain: str = "",
) -> bytes:
  """Compute the 72-byte attestation-input for Mode 1 (RFC Section 5.2).

  attestation-input = h-hash || bh-raw || ts-bytes   (exactly 72 octets)

  Per RFC: "The externally supplied detached content is the exact 72-octet
  attestation-input; implementations MUST NOT pre-hash that value and then
  present the digest to CMS as though it were the content."

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

  return h_hash + bh_raw + ts_bytes


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
_OID_ED25519 = "1.3.101.112"

_RFC_ALG_TO_SIGNATURE_OID = {
  "RS256": _OID_SHA256_WITH_RSA,
  "ES256": _OID_ECDSA_WITH_SHA256,
  "PS256": _OID_RSA_PSS,
  "EdDSA": _OID_ED25519,
}

# Email draft "CMS Algorithm Mapping" (AUD-F23): the exact DER AlgorithmIdentifier
# generated for each Version 1 alg. SHA-256 parameters are absent (RFC 5754); RS256
# carries NULL; ES256 has none; PS256 encodes SHA-256, MGF1-SHA-256 and salt 32
# (trailerField 1 is the DER default, so omitted). Byte-identical to OpenSSL 3.2.
_DER_SHA256_DIGEST_ALGORITHM_IDENTIFIER_WITH_ABSENT_PARAMETERS = bytes.fromhex("300b0609608648016503040201")
_RFC_ALG_TO_DER_SIGNATURE_ALGORITHM_IDENTIFIER = {
  "RS256": bytes.fromhex("300d06092a864886f70d01010b0500"),
  "ES256": bytes.fromhex("300a06082a8648ce3d040302"),
  "PS256": bytes.fromhex(
    "304106092a864886f70d01010a3034a00f300d06096086480165030402010500"
    "a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120"
  ),
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
      try:
        pem_bytes = full_pem.encode("utf-8", errors="surrogateescape")
      except (UnicodeEncodeError, UnicodeDecodeError):
        pem_bytes = full_pem.encode("latin-1")
      try:
        cert_object = x509.load_pem_x509_certificate(pem_bytes)
      except (ValueError, Exception) as cert_parse_error:
        import logging
        logging.getLogger("oneid.attestation").warning(
          "Skipping unparseable certificate in chain: %s", cert_parse_error
        )
        continue
      certificate_der_list.append(cert_object.public_bytes(Encoding.DER))
      if leaf_certificate is None:
        leaf_certificate = cert_object

  if leaf_certificate is None:
    raise ValueError("Certificate chain PEM contains no parseable certificates")

  signature_oid_string = _RFC_ALG_TO_SIGNATURE_OID.get(signature_algorithm_rfc_name)
  if signature_oid_string is None:
    raise ValueError(f"Unsupported signature algorithm: {signature_algorithm_rfc_name}")

  # RFC 8419 s3.1: with Ed25519 the digestAlgorithm MUST be id-sha512, parameters
  # absent (OWN-022; EdDSA is outside Version 1). All other algorithms use SHA-256.
  if signature_algorithm_rfc_name == "EdDSA":
    digest_algorithm_identifier = _der_encode_tag_length_value(
      0x30,
      _der_encode_oid("2.16.840.1.101.3.4.2.3"),  # id-sha512
    )
  else:
    digest_algorithm_identifier = _DER_SHA256_DIGEST_ALGORITHM_IDENTIFIER_WITH_ABSENT_PARAMETERS

  digest_algorithms_set = _der_encode_tag_length_value(0x31, digest_algorithm_identifier)

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

  if signature_algorithm_rfc_name == "EdDSA":
    signature_algorithm_identifier = _der_encode_tag_length_value(
      0x30,
      _der_encode_oid(signature_oid_string),
    )
  else:
    signature_algorithm_identifier = _RFC_ALG_TO_DER_SIGNATURE_ALGORITHM_IDENTIFIER[signature_algorithm_rfc_name]

  signature_octet_string = _der_encode_tag_length_value(0x04, signature_bytes)

  signer_info = _der_encode_tag_length_value(
    0x30,
    _der_encode_integer(1)
    + issuer_and_serial_number
    + digest_algorithm_identifier
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


def _certificate_chain_leaf_key_verifies_mode1_signature(
  certificate_chain_pem: Optional[str],
  attestation_input_72_bytes: bytes,
  signature_bytes: bytes,
  rfc_alg: str,
) -> bool:
  """True when the chain's first (leaf) certificate holds the key that produced
  signature_bytes over the 72-octet attestation-input under rfc_alg."""
  from cryptography.exceptions import InvalidSignature
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
  end_marker = "-----END CERTIFICATE-----"
  leaf_start = certificate_chain_pem.find("-----BEGIN CERTIFICATE-----") if certificate_chain_pem else -1
  leaf_end = certificate_chain_pem.find(end_marker) if certificate_chain_pem else -1
  if leaf_start < 0 or leaf_end < 0:
    return False
  try:
    leaf_public_key = x509.load_pem_x509_certificate(
      certificate_chain_pem[leaf_start:leaf_end + len(end_marker)].encode("ascii")).public_key()
    if rfc_alg == "ES256" and isinstance(leaf_public_key, ec.EllipticCurvePublicKey):
      leaf_public_key.verify(signature_bytes, attestation_input_72_bytes, ec.ECDSA(hashes.SHA256()))
    elif rfc_alg == "RS256" and isinstance(leaf_public_key, rsa.RSAPublicKey):
      leaf_public_key.verify(signature_bytes, attestation_input_72_bytes, padding.PKCS1v15(), hashes.SHA256())
    elif rfc_alg == "PS256" and isinstance(leaf_public_key, rsa.RSAPublicKey):
      leaf_public_key.verify(signature_bytes, attestation_input_72_bytes,
                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif rfc_alg == "EdDSA" and isinstance(leaf_public_key, ed25519.Ed25519PublicKey):
      leaf_public_key.verify(signature_bytes, attestation_input_72_bytes)
    else:
      return False
    return True
  except (InvalidSignature, ValueError, TypeError):
    return False


def _registrar_binding_jws_confirms_certificate_leaf_key(binding_jws: str, certificate_chain_pem: str) -> bool:
  """True when the binding JWS cnf.jwk is the public key of the chain's leaf."""
  import json
  from .mailpal import _extract_public_key_jwk_from_certificate_chain_pem
  try:
    payload_segment = binding_jws.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))
    confirmed_jwk = (payload.get("cnf") or {}).get("jwk") or {}
  except (IndexError, ValueError, AttributeError):
    return False
  leaf_jwk = _extract_public_key_jwk_from_certificate_chain_pem(certificate_chain_pem) or {}
  compared_fields = ("kty", "crv", "x", "y") if leaf_jwk.get("kty") == "EC" else ("kty", "n", "e")
  return bool(leaf_jwk) and all(confirmed_jwk.get(field_name) == leaf_jwk.get(field_name) for field_name in compared_fields)


def _sign_attestation_input_with_software_key(
  attestation_input_72_bytes: bytes,
  private_key_pem: str,
) -> bytes:
  """Sign the 72-byte attestation-input with a software key.

  Uses the same convention as the Go helpers for TPM/PIV/enclave:
  the library's sign() method hashes the input internally via its
  algorithm parameter (SHA-256), producing a signature over
  SHA-256(attestation-input). This matches CMS verification where
  the verifier supplies the 72-byte attestation-input as detached
  content and CMS hashes it with digestAlgorithm (SHA-256).

  ECDSA P-256 -> ECDSA(SHA256) hashes input then signs.
  RSA         -> PKCS1v15+SHA256 hashes input then signs.
  Ed25519     -> PureEdDSA signs the raw bytes.
  """
  from cryptography.hazmat.primitives import serialization as _ser
  from cryptography.hazmat.primitives.asymmetric import (
    ec as _ec, rsa as _rsa, ed25519 as _ed25519, padding as _padding,
  )
  from cryptography.hazmat.primitives import hashes as _hashes

  private_key = _ser.load_pem_private_key(
    private_key_pem.encode() if isinstance(private_key_pem, str)
    else private_key_pem, password=None)

  if isinstance(private_key, _ec.EllipticCurvePrivateKey):
    return private_key.sign(
      attestation_input_72_bytes,
      _ec.ECDSA(_hashes.SHA256()))
  if isinstance(private_key, _rsa.RSAPrivateKey):
    return private_key.sign(
      attestation_input_72_bytes, _padding.PKCS1v15(), _hashes.SHA256())
  if isinstance(private_key, _ed25519.Ed25519PrivateKey):
    return private_key.sign(attestation_input_72_bytes)
  raise ValueError(
    "Unsupported software key type for Mode 1 attestation: %s"
    % type(private_key).__name__)


def prepare_direct_hardware_attestation(
  # CROSS_IMPL_SYNC: mode1_attestation
  # Implementations: py:oneid/attestation.py node:src/attestation.ts
  email_headers: Dict[str, str],
  body: bytes,
  agent_identity_urn: Optional[str] = None,
  binding_jws: Optional[str] = None,
  override_signing_device_type: Optional[str] = None,
  piv_serial_number: Optional[int] = None,
) -> AttestationProof:
  """Prepare a Mode 1 (Direct Hardware Attestation) proof.

  Signs the email content with the enrolled hardware key and assembles
  the Hardware-Attestation header per RFC Section 5.

  This function:
  1. Determines the hardware type and signing algorithm from credentials
  2. Builds the header template (all params except chain)
  3. Computes the 72-byte attestation-input (h-hash || bh-raw || ts-bytes)
  4. Signs the attestation-input with the hardware key
  5. Builds the CMS SignedData envelope
  6. Assembles the final Hardware-Attestation header value

  Args:
    email_headers: Dict of email header name -> value.
    body: Raw email body bytes.
    agent_identity_urn: Optional URN override (default: from credentials).
    override_signing_device_type: Phase 3 runtime device selection. When set
        to "piv" or "tpm", forces signing with that device regardless of the
        identity's trust tier. Use "piv" when a registered YubiKey is plugged
        in and you want to sign with it instead of the TPM. The per-device
        certificate chain (Phase 2) is automatically selected to match.
    piv_serial_number: Phase 4 multi-YubiKey selection. When set, forces
        signing with the YubiKey that has this serial number. When None and
        multiple YubiKeys are connected, the SDK picks the most-recently-plugged
        key that has a slot 9a signing key, or falls back to the registered key.

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

  if agent_identity_urn and not binding_jws:
    logger.info(
      "Omitting aid from Mode 1 header: sender MUST NOT place aid "
      "without Registrar binding (RFC Section 5.4)"
    )
    agent_identity_urn = None

  attestation_timestamp = int(time.time())

  canonicalised_body = canonicalise_body_using_dkim_simple(body)
  bh_raw = hashlib.sha256(canonicalised_body).digest()
  bh_base64url = base64.urlsafe_b64encode(bh_raw).rstrip(b"=").decode("ascii")

  lowered_headers = {k.strip().lower(): v for k, v in email_headers.items()}
  all_signed_names = list(_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING)
  extra_header_names = sorted(
    h for h in lowered_headers
    if h not in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING
    and h != "hardware-attestation"
  )
  all_signed_names.extend(extra_header_names)
  signed_header_names = ":".join(all_signed_names) + ":" + ":".join(all_signed_names)

  # Phase 3: Runtime device selection -- override_signing_device_type lets the
  # caller force signing with a specific device (e.g. "piv" when a YubiKey is
  # plugged in, even though the identity is sovereign-tier / TPM-enrolled).
  # The algorithm, typ parameter, and cert chain all adapt accordingly.
  effective_signing_device_type = override_signing_device_type
  if not effective_signing_device_type:
    # Default: derive from trust tier / credentials (pre-Phase-3 behavior)
    if trust_tier == "portable":
      effective_signing_device_type = "piv"
    elif trust_tier == "enclave":
      effective_signing_device_type = "enclave"
    elif trust_tier in ("sovereign", "virtual") or creds.key_algorithm == "tpm-ak":
      effective_signing_device_type = "tpm"
    elif creds.private_key_pem:
      effective_signing_device_type = "software"

  if effective_signing_device_type == "piv":
    algorithm_for_header = "ES256"
    typ_parameter = _TRUST_TIER_TO_RFC_TYP_PARAMETER.get("portable", "PIV")
  elif effective_signing_device_type == "enclave":
    algorithm_for_header = "ES256"
  elif effective_signing_device_type == "tpm":
    algorithm_for_header = "RS256"
  elif effective_signing_device_type == "software" and creds.private_key_pem:
    algo_name = _determine_signing_algorithm_name(creds)
    algorithm_for_header = algo_name
    if algorithm_for_header not in _RFC_ALG_TO_DER_SIGNATURE_ALGORITHM_IDENTIFIER:
      # AUD-F22/F60: Version 1 Mode 1 allows only RS256 / ES256 / PS256.
      raise ValueError(
        f"This identity's {creds.key_algorithm} key cannot sign a Version 1 Mode 1 "
        f"email proof ({algorithm_for_header} is not in the email draft's CMS table). "
        "Enroll a declared identity with key_algorithm='ecdsa-p256' (the default) "
        "or use a hardware tier."
      )
  else:
    raise NotEnrolledError("No signing key available for Mode 1 attestation.")

  header_template_without_chain = (
    f"v=1; typ={typ_parameter}; alg={algorithm_for_header}; "
    f"h={signed_header_names}; bh={bh_base64url}; ts={attestation_timestamp}; "
    f"chain="
  )
  if agent_identity_urn:
    header_template_without_chain += f"; aid={agent_identity_urn}"
  if binding_jws:
    header_template_without_chain += f"; bind={binding_jws}"

  attestation_input_72_bytes = compute_attestation_input_for_direct_mode(
    email_headers=email_headers,
    body_bytes=body,
    attestation_timestamp_unix=attestation_timestamp,
    hardware_attestation_header_value_without_chain=header_template_without_chain,
  )

  if effective_signing_device_type == "piv":
    signature_bytes, resolved_algorithm = _sign_with_piv(
      attestation_input_72_bytes, piv_serial_number=piv_serial_number)
  elif effective_signing_device_type == "enclave":
    signature_bytes, resolved_algorithm = _sign_with_enclave(attestation_input_72_bytes)
  elif effective_signing_device_type == "tpm":
    ak_handle = creds.hsm_key_reference or ""
    signature_bytes, resolved_algorithm = _sign_with_tpm(attestation_input_72_bytes, ak_handle)
  elif effective_signing_device_type == "software" and creds.private_key_pem:
    signature_bytes = _sign_attestation_input_with_software_key(
      attestation_input_72_bytes, creds.private_key_pem)
    resolved_algorithm = algorithm_for_header
  else:
    raise NotEnrolledError("No signing key available.")

  actual_algorithm_for_cms = resolved_algorithm if resolved_algorithm else algorithm_for_header

  # Phase 2+3: Select the per-device certificate chain that matches the signing device.
  # effective_signing_device_type (from Phase 3 runtime selection or default derivation)
  # tells us which device just signed, so we pick its matching cert chain.
  certificate_chain_pem_for_this_signing_device = creds.identity_certificate_chain_pem
  if creds.device_certificate_chains and effective_signing_device_type:
    for _device_fp, _chain_pem in creds.device_certificate_chains.items():
      if isinstance(_chain_pem, dict):
        if _chain_pem.get("device_type") == effective_signing_device_type:
          certificate_chain_pem_for_this_signing_device = _chain_pem.get(
            "certificate_chain_pem", certificate_chain_pem_for_this_signing_device)
          break
      elif isinstance(_chain_pem, str):
        certificate_chain_pem_for_this_signing_device = _chain_pem
        break

  # AUD-F81 (+F57): the CMS signer certificate must carry the key that produced
  # this signature. The device-type guess above is tried first, then every
  # stored chain; if none matches, fail closed instead of packaging another
  # device's certificate -- and any bind must confirm that same key.
  candidate_certificate_chains = [certificate_chain_pem_for_this_signing_device]
  for _chain_data in (creds.device_certificate_chains or {}).values():
    _candidate_chain = _chain_data.get("certificate_chain_pem") if isinstance(_chain_data, dict) else _chain_data
    if _candidate_chain and _candidate_chain not in candidate_certificate_chains:
      candidate_certificate_chains.append(_candidate_chain)
  if creds.identity_certificate_chain_pem not in candidate_certificate_chains:
    candidate_certificate_chains.append(creds.identity_certificate_chain_pem)
  certificate_chain_pem_for_this_signing_device = next(
    (candidate_chain for candidate_chain in candidate_certificate_chains
     if _certificate_chain_leaf_key_verifies_mode1_signature(
       candidate_chain, attestation_input_72_bytes, signature_bytes, actual_algorithm_for_cms)),
    None,
  )
  if certificate_chain_pem_for_this_signing_device is None:
    raise ValueError(
      "No stored certificate chain matches the key that signed this Mode 1 proof; "
      "re-sync device certificates (oneid.sync_device_certificate_chains_from_server) or re-enroll."
    )
  if binding_jws and not _registrar_binding_jws_confirms_certificate_leaf_key(
      binding_jws, certificate_chain_pem_for_this_signing_device):
    raise ValueError(
      "The Registrar binding was issued for a different key than the device that signed "
      "this Mode 1 proof; send again (the binding is fetched for the signing device's key)."
    )

  cms_der_bytes = build_cms_signed_data_for_direct_attestation(
    signature_bytes=signature_bytes,
    certificate_chain_pem=certificate_chain_pem_for_this_signing_device,
    signature_algorithm_rfc_name=actual_algorithm_for_cms,
  )
  chain_base64 = base64.b64encode(cms_der_bytes).decode("ascii")

  final_header_value = (
    f"v=1; typ={typ_parameter}; alg={algorithm_for_header}; "
    f"h={signed_header_names}; bh={bh_base64url}; ts={attestation_timestamp}; "
    f"chain={chain_base64}"
  )
  if agent_identity_urn:
    final_header_value += f"; aid={agent_identity_urn}"
  if binding_jws:
    final_header_value += f"; bind={binding_jws}"

  body_digest_hex = hashlib.sha256(body).hexdigest()

  return AttestationProof(
    hardware_attestation_header_value=final_header_value,
    content_digest=f"sha256:{body_digest_hex}",
  )


def canonicalise_header_value_using_dkim_relaxed(raw_value: str) -> str:
  """Apply DKIM2 -06 Section 6.2 value mechanics to one selected field.

  The established public function name is retained for SDK compatibility.
  Encoded words remain wire text; decoding them would change signed octets.
  """
  import re
  unfolded = re.sub(r"\r?\n(?=[ \t])", "", raw_value)
  compressed = re.sub(r"[ \t]+", " ", unfolded)
  return compressed.strip(" \t")


def canonicalise_header_name_using_dkim_relaxed(raw_name: str) -> str:
  """Apply DKIM2 -06 field-name lowercasing and colon-adjacent WSP removal."""
  return raw_name.strip(" \t").lower()


def canonicalise_selected_header_field_using_dkim2_header_hash_rules(
  raw_header_field_name: str,
  raw_header_field_value: str,
) -> str:
  """Return one CRLF-terminated selected field under DKIM2 Section 6.2."""
  canonical_header_field_name = canonicalise_header_name_using_dkim_relaxed(
    raw_header_field_name
  )
  canonical_header_field_value = canonicalise_header_value_using_dkim_relaxed(
    raw_header_field_value
  )
  return f"{canonical_header_field_name}:{canonical_header_field_value}\r\n"


def canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
  hardware_attestation_header_value_with_empty_chain: str,
) -> str:
  """Use DKIM2 -06 Section 9.6 for the actual field with chain emptied."""
  import re
  unfolded_header_value = re.sub(
    r"\r?\n(?=[ \t])", "", hardware_attestation_header_value_with_empty_chain
  )
  header_value_without_wsp = re.sub(r"[ \t]+", "", unfolded_header_value)
  return f"hardware-attestation:{header_value_without_wsp}\r\n"


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
  """Canonicalise email headers for the Mode 2 message-binding nonce, per
  draft-drake-email-hardware-attestation-03.

  Mode 2 covers a FIXED set: the nine always-covered fields
  (_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING), in THAT order, each once (no oversigning, no bottom-up selection, no
  negotiation -- a Mode 2 header carries no explicit covered-header list,
  so any variation would make the verifier unable to reconstruct the
  nonce). Each is DKIM-relaxed-canonicalised and CRLF-terminated; then
  the Hardware-Trust-Proof header is appended last with an empty value
  and WITHOUT a trailing CRLF.
  """
  lowered_headers = {k.strip().lower(): v for k, v in email_headers.items()}

  canonicalised_header_lines = []
  for required_header_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
    if required_header_name not in lowered_headers:
      continue  # absent field: contributes nothing (DKIM h= rule)
    canonicalised_header_lines.append(
      canonicalise_selected_header_field_using_dkim2_header_hash_rules(
        required_header_name, lowered_headers[required_header_name]
      )
    )

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
  # CROSS_IMPL_SYNC: mode2_attestation
  # Implementations: py:oneid/attestation.py node:src/attestation.ts
  content: Optional[bytes] = None,
  content_digest: Optional[str] = None,
  email_headers: Optional[Dict[str, str]] = None,
  body: Optional[bytes] = None,
  disclosed_claims: Optional[List[str]] = None,
  include_contact_token: bool = True,
  include_sd_jwt: bool = True,
  api_base_url: Optional[str] = None,
  override_session_device_type: Optional[str] = None,
  cnf_jwk: Optional[Dict[str, Any]] = None,
) -> AttestationProof:
  """
  Prepare a protocol-agnostic attestation proof.

  Two modes of operation:

  1. **Email attestation (RFC-compliant)**: pass email_headers + body.
     The nonce is computed per draft-drake-email-hardware-attestation-03
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
                   The nine always-covered fields (From, To, Subject, Date, Message-ID,
                   Reply-To, MIME-Version, Content-Type, Content-Transfer-Encoding) are
                   hashed when present; an absent one contributes nothing.
    body: Raw email body bytes (RFC mode). Used with email_headers.
    disclosed_claims: Which SD-JWT claims to disclose. Default: ["aid"].
    include_contact_token: Whether to fetch a contact token (default True).
    include_sd_jwt: Whether to fetch an SD-JWT proof (default True).
    cnf_jwk: Combined mode only -- the Mode 1 proof public key (JWK); the
             issuer places it in the signed payload as non-selective cnf.jwk.
             Leave None for standalone Mode 2 (cnf MUST then be absent).
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

  # AUD-F83: an SD-JWT attestation must be bound to something (as Node does).
  if include_sd_jwt and not rfc_email_mode_is_active and not simple_content_mode_is_active:
    raise ValueError(
      "SD-JWT attestation requires content to bind to: email_headers + body, "
      "content, or content_digest."
    )
  if content_digest is not None and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", content_digest):
    raise ValueError("content_digest must be 'sha256:' followed by 64 hex digits.")

  if content is not None:
    digest_hex = hashlib.sha256(content).hexdigest()
    content_digest = f"sha256:{digest_hex}"

  if rfc_email_mode_is_active:
    body_digest_hex = hashlib.sha256(body).hexdigest()
    content_digest = f"sha256:{body_digest_hex}"

  if disclosed_claims is None:
    disclosed_claims = ["aid"]

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

    # Phase 3: Use the override device type if provided, otherwise derive
    # from the credentials' HSM reference (pre-Phase-3 behavior).
    if override_session_device_type:
      session_device_type_for_dynamic_trust_tiering = override_session_device_type
    else:
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
      cnf_jwk=cnf_jwk,
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
  cnf_jwk: Optional[Dict[str, Any]] = None,
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
  if cnf_jwk is not None:
    body["cnf_jwk"] = cnf_jwk  # Combined mode (AUD-F47)
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


def _fetch_binding_jws(
  api_base_url: str,
  auth_headers: Dict[str, str],
  proof_public_key_jwk: Dict[str, Any],
) -> Optional[str]:
  """Fetch a Registrar Binding JWS from the server (RFC Section 5.4).

  The binding JWS proves the Registrar attests this operational proof key
  belongs to this canonical identity. Used in Combined mode (Mode 1 + Mode 2).

  Returns the compact JWS string, or None on failure.
  """
  url = f"{api_base_url}/api/v1/proof/binding"
  body = {"proof_public_key_jwk": proof_public_key_jwk}

  try:
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
      response = client.post(url, json=body, headers=auth_headers)
  except (httpx.ConnectError, httpx.TimeoutException) as error:
    logger.warning("Binding JWS request failed: %s", error)
    return None

  if response.status_code != 200:
    logger.warning("Binding JWS request failed (HTTP %d)", response.status_code)
    return None

  data = response.json()
  if "data" in data:
    data = data["data"]
  return data.get("binding_jws")


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

