"""
Tests for the attestation primitives (Mode 1 + Mode 2)
and the mailpal convenience module (oneid.mailpal).

All network calls are mocked -- these are SDK unit tests,
not integration tests.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from unittest.mock import patch, MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_credentials():
  """Return a mock StoredCredentials object."""
  creds = MagicMock()
  creds.client_id = "id-tsthj-zhshb-sqpck-bghgw"
  creds.client_secret = "mock-secret"
  creds.api_base_url = "https://1id.com"
  creds.token_endpoint = "https://1id.com/realms/agents/protocol/openid-connect/token"
  # send() reads these; a bare MagicMock breaks email.utils.formataddr
  creds.display_name = "Test Agent"
  creds.mailpal_email = "id-tsthj-zhshb-sqpck-bghgw@mailpal.com"
  creds.mailpal_app_password = "mock-smtp-password"
  return creds


def _mock_token():
  """Return a mock Token object."""
  from datetime import datetime, timezone, timedelta
  token = MagicMock()
  token.access_token = "mock-access-token-xyz"
  token.token_type = "Bearer"
  token.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
  return token


_SAMPLE_EMAIL_HEADERS = {
  "From": "agent@mailpal.com",
  "To": "bob@example.com",
  "Subject": "Test Subject",
  "Date": "Thu, 19 Mar 2026 12:00:00 +0000",
  "Message-ID": "<test-001@mailpal.com>",
}


# ---------------------------------------------------------------------------
# Tests: RFC Section 5.3 message-binding nonce computation
# ---------------------------------------------------------------------------

# Email draft (2026-09-24): Mode 1 h= always names these nine fields; the
# second copy oversigns them so an added instance breaks verification.
_NINE_ALWAYS_COVERED_FIELDS_LISTED_TWICE_FOR_OVERSIGNED_H_TAG = (
  "from:to:subject:date:message-id:reply-to:mime-version:content-type:content-transfer-encoding:"
  "from:to:subject:date:message-id:reply-to:mime-version:content-type:content-transfer-encoding"
)


class TestDkimRelaxedHeaderCanonicalization:
  """Verify DKIM relaxed header canonicalization per RFC 6376 Section 3.4.2."""

  def test_lowercases_header_names(self):
    from oneid.attestation import canonicalise_header_name_using_dkim_relaxed
    assert canonicalise_header_name_using_dkim_relaxed("From") == "from"
    assert canonicalise_header_name_using_dkim_relaxed("MESSAGE-ID") == "message-id"

  def test_strips_header_name_whitespace(self):
    from oneid.attestation import canonicalise_header_name_using_dkim_relaxed
    assert canonicalise_header_name_using_dkim_relaxed("  Subject  ") == "subject"

  def test_compresses_whitespace_in_value(self):
    from oneid.attestation import canonicalise_header_value_using_dkim_relaxed
    assert canonicalise_header_value_using_dkim_relaxed("hello   world") == "hello world"
    assert canonicalise_header_value_using_dkim_relaxed("a\t\tb") == "a b"

  def test_strips_trailing_whitespace_in_value(self):
    from oneid.attestation import canonicalise_header_value_using_dkim_relaxed
    assert canonicalise_header_value_using_dkim_relaxed("value   ") == "value"

  def test_unfolds_continuation_lines_in_value(self):
    from oneid.attestation import canonicalise_header_value_using_dkim_relaxed
    assert canonicalise_header_value_using_dkim_relaxed("line1\r\n continuation") == "line1 continuation"


class TestDkimSimpleBodyCanonicalization:
  """Verify DKIM simple body canonicalization per RFC 6376 Section 3.4.3."""

  def test_empty_body_becomes_single_crlf(self):
    from oneid.attestation import canonicalise_body_using_dkim_simple
    assert canonicalise_body_using_dkim_simple(b"") == b"\r\n"

  def test_strips_trailing_empty_lines(self):
    from oneid.attestation import canonicalise_body_using_dkim_simple
    assert canonicalise_body_using_dkim_simple(b"text\r\n\r\n\r\n") == b"text\r\n"

  def test_appends_crlf_if_missing(self):
    from oneid.attestation import canonicalise_body_using_dkim_simple
    assert canonicalise_body_using_dkim_simple(b"text") == b"text\r\n"

  def test_preserves_body_ending_with_single_crlf(self):
    from oneid.attestation import canonicalise_body_using_dkim_simple
    assert canonicalise_body_using_dkim_simple(b"body text\r\n") == b"body text\r\n"


class TestCanonicaliseHeadersForMessageBinding:
  """Verify the full header canonicalization for message-binding nonce."""

  def test_absent_always_covered_fields_contribute_nothing_and_do_not_raise(self):
    # Email draft: all nine fields are always covered; an absent one is fine.
    from oneid.attestation import canonicalise_headers_for_message_binding
    result = canonicalise_headers_for_message_binding({"From": "a@b.com"})
    assert result == b"from:a@b.com\r\nhardware-trust-proof:"

  def test_produces_bytes_with_required_headers(self):
    from oneid.attestation import canonicalise_headers_for_message_binding
    result = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS)
    assert isinstance(result, bytes)
    decoded = result.decode("utf-8")
    assert "from:agent@mailpal.com\r\n" in decoded
    assert "to:bob@example.com\r\n" in decoded
    assert "subject:Test Subject\r\n" in decoded
    assert decoded.endswith("hardware-trust-proof:")

  def test_hardware_trust_proof_header_is_last_without_trailing_crlf(self):
    from oneid.attestation import canonicalise_headers_for_message_binding
    result = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS)
    decoded = result.decode("utf-8")
    assert decoded.endswith("hardware-trust-proof:")
    assert not decoded.endswith("hardware-trust-proof:\r\n")


class TestComputeRfcMessageBindingNonce:
  """Verify the full RFC Section 5.3 nonce algorithm."""

  def test_produces_base64url_string_without_padding(self):
    from oneid.attestation import compute_rfc_message_binding_nonce
    nonce = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Hello, world!\r\n",
      proposed_iat_unix_timestamp=1711022400,
    )
    assert isinstance(nonce, str)
    assert "=" not in nonce
    assert "+" not in nonce
    assert "/" not in nonce

  def test_deterministic_for_same_inputs(self):
    from oneid.attestation import compute_rfc_message_binding_nonce
    nonce_first = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022400,
    )
    nonce_second = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022400,
    )
    assert nonce_first == nonce_second

  def test_differs_when_body_changes(self):
    from oneid.attestation import compute_rfc_message_binding_nonce
    nonce_a = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body A",
      proposed_iat_unix_timestamp=1711022400,
    )
    nonce_b = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body B",
      proposed_iat_unix_timestamp=1711022400,
    )
    assert nonce_a != nonce_b

  def test_differs_when_headers_change(self):
    from oneid.attestation import compute_rfc_message_binding_nonce
    headers_a = dict(_SAMPLE_EMAIL_HEADERS, Subject="Subject A")
    headers_b = dict(_SAMPLE_EMAIL_HEADERS, Subject="Subject B")
    nonce_a = compute_rfc_message_binding_nonce(
      email_headers=headers_a,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022400,
    )
    nonce_b = compute_rfc_message_binding_nonce(
      email_headers=headers_b,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022400,
    )
    assert nonce_a != nonce_b

  def test_differs_when_timestamp_changes(self):
    from oneid.attestation import compute_rfc_message_binding_nonce
    nonce_a = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022400,
    )
    nonce_b = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      proposed_iat_unix_timestamp=1711022401,
    )
    assert nonce_a != nonce_b

  def test_matches_manual_rfc_computation(self):
    """Manually compute the nonce per the RFC algorithm and compare."""
    from oneid.attestation import (
      compute_rfc_message_binding_nonce,
      canonicalise_headers_for_message_binding,
      canonicalise_body_using_dkim_simple,
    )
    body_bytes = b"Hello, world!\r\n"
    iat = 1711022400

    canon_headers = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS)
    h_hash = hashlib.sha256(canon_headers).digest()
    bh_raw = hashlib.sha256(canonicalise_body_using_dkim_simple(body_bytes)).digest()
    ts_bytes = struct.pack(">Q", iat)
    message_binding = h_hash + bh_raw + ts_bytes
    expected_nonce = base64.urlsafe_b64encode(
      hashlib.sha256(message_binding).digest()
    ).rstrip(b"=").decode("ascii")

    actual_nonce = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=body_bytes,
      proposed_iat_unix_timestamp=iat,
    )
    assert actual_nonce == expected_nonce

  def test_nonce_is_43_chars_base64url_of_sha256(self):
    """SHA-256 = 32 bytes. base64url(32 bytes) without padding = 43 chars."""
    from oneid.attestation import compute_rfc_message_binding_nonce
    nonce = compute_rfc_message_binding_nonce(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"test body",
      proposed_iat_unix_timestamp=1711022400,
    )
    assert len(nonce) == 43


# ---------------------------------------------------------------------------
# Tests: Mode 1 -- Direct Hardware Attestation (RFC Section 5)
# ---------------------------------------------------------------------------

def _generate_test_certificate_chain_pem():
  """Generate a self-signed CA + leaf cert pair for testing CMS construction."""
  ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  ca_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
    .public_key(ca_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_private_key, hashes.SHA256())
  )

  leaf_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test AK Cert")]))
    .issuer_name(ca_cert.subject)
    .public_key(leaf_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .sign(ca_private_key, hashes.SHA256())
  )

  chain_pem = (
    leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    + ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
  )
  return chain_pem, leaf_cert, ca_cert


class TestCanonicaliseHeadersForDirectAttestation:
  """Verify header canonicalization for Mode 1 (Hardware-Attestation self-reference)."""

  def test_absent_always_covered_fields_contribute_nothing_and_do_not_raise(self):
    # Email draft: all nine fields are always covered; an absent one is fine.
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation({"From": "a@b.com"})
    assert result == b"from:a@b.com\r\nhardware-attestation:\r\n"

  def test_self_references_hardware_attestation_not_trust_proof(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(_SAMPLE_EMAIL_HEADERS)
    decoded = result.decode("utf-8")
    assert "hardware-attestation:" in decoded
    assert "hardware-trust-proof" not in decoded

  def test_hardware_attestation_header_is_last_with_dkim2_required_trailing_crlf(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(_SAMPLE_EMAIL_HEADERS)
    decoded = result.decode("utf-8")
    # DKIM2 -06 Section 9.6 retains the signature field's final CRLF.
    assert decoded.endswith("hardware-attestation:\r\n")

  def test_includes_header_value_in_self_reference(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(
      _SAMPLE_EMAIL_HEADERS,
      hardware_attestation_header_value_without_chain="v=1; typ=TPM; alg=RS256; chain=",
    )
    decoded = result.decode("utf-8")
    # DKIM2 signature-field canonicalization deletes every WSP character.
    assert decoded.endswith("hardware-attestation:v=1;typ=TPM;alg=RS256;chain=\r\n")

  def test_self_reference_folded_and_unfolded_forms_are_identical(self):
    from oneid.attestation import (
      canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules,
    )
    unfolded_value = "v=1; typ=TPM; alg=RS256; chain=; future=alpha"
    folded_value = "v=1;\r\n typ=TPM; alg=RS256;\r\n chain=; future=alpha"
    # DKIM2 Section 9.6 deletes the continuation WSP after unfolding.
    assert canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
      folded_value
    ) == canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
      unfolded_value
    )

  def test_unknown_extension_tag_is_cryptographically_covered(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    without_extension = canonicalise_headers_for_direct_attestation(
      _SAMPLE_EMAIL_HEADERS,
      hardware_attestation_header_value_without_chain="v=1; typ=TPM; chain=",
    )
    with_extension = canonicalise_headers_for_direct_attestation(
      _SAMPLE_EMAIL_HEADERS,
      hardware_attestation_header_value_without_chain=(
        "v=1; typ=TPM; chain=; future=alpha"
      ),
    )
    assert without_extension != with_extension

  def test_combined_mode_hardware_trust_proof_is_selected_and_oversigned(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    combined_headers = dict(_SAMPLE_EMAIL_HEADERS)
    combined_headers["Hardware-Trust-Proof"] = "token~disclosure~"
    canonicalised = canonicalise_headers_for_direct_attestation(combined_headers).decode("utf-8")
    # Deliberate duplicate h= entries oversign singleton fields so later
    # insertion of a second instance is detectable by bottom-up selection.
    assert canonicalised.count("hardware-trust-proof:token~disclosure~\r\n") == 1

  def test_repeated_header_instances_are_selected_bottom_up_and_consumed_once(self):
    from oneid.attestation import _select_headers_bottom_up_per_dkim
    ordered_header_pairs = [
      ("X-Trace", "top-added"),
      ("Subject", "example"),
      ("X-Trace", "bottom-added"),
    ]
    selected = _select_headers_bottom_up_per_dkim(
      ["x-trace", "x-trace", "x-trace"], ordered_header_pairs
    )
    assert selected == [
      ("X-Trace", "bottom-added"),
      ("X-Trace", "top-added"),
      None,
    ]


class TestProductionAirsHeaderFolding:
  def test_long_chain_folds_only_inside_permitted_encoded_value(self):
    from oneid.mailpal import _fold_long_header_value_for_smtp_transmission
    header_value = (
      "v=1; typ=TPM; alg=RS256; h=from:to:subject:date:message-id; "
      "bh=abc123; ts=1710849600; chain=" + "A" * 2400
    )
    folded_header = _fold_long_header_value_for_smtp_transmission(
      "Hardware-Attestation", header_value
    )
    physical_lines = folded_header.split("\r\n")
    assert all(len(physical_line) <= 998 for physical_line in physical_lines)
    assert all(
      physical_line.startswith(("Hardware-Attestation:", " "))
      for physical_line in physical_lines
    )
    assert "messag\r\n e-id" not in folded_header
    assert "chain=" in folded_header

  def test_h_list_folds_at_colon_separator_without_splitting_names(self):
    from oneid.mailpal import _fold_long_header_value_for_smtp_transmission
    signed_names = ":".join(["x-complete-header-name-" + str(index) for index in range(20)])
    folded_header = _fold_long_header_value_for_smtp_transmission(
      "Hardware-Attestation",
      f"v=1; typ=TPM; alg=RS256; h={signed_names}; bh=abc; ts=1; chain=QUJD",
    )
    assert ":\r\n " in folded_header
    assert all(len(physical_line) <= 998 for physical_line in folded_header.split("\r\n"))

  def test_long_mode2_value_uses_its_explicit_transport_fws_rule(self):
    from oneid.mailpal import _fold_long_header_value_for_smtp_transmission
    presentation = "a" * 1500 + "~" + "b" * 300
    folded_header = _fold_long_header_value_for_smtp_transmission(
      "Hardware-Trust-Proof", presentation
    )
    assert "\r\n " in folded_header
    assert all(len(physical_line) <= 998 for physical_line in folded_header.split("\r\n"))


class TestComputeAttestationInputForDirectMode:
  """Verify the Mode 1 72-byte attestation-input computation (RFC Section 5.2)."""

  def test_produces_exactly_72_byte_attestation_input(self):
    from oneid.attestation import compute_attestation_input_for_direct_mode
    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Hello, world!\r\n",
      attestation_timestamp_unix=1711022400,
    )
    assert isinstance(attestation_input, bytes)
    assert len(attestation_input) == 72

  def test_deterministic_for_same_inputs(self):
    from oneid.attestation import compute_attestation_input_for_direct_mode
    first = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    second = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    assert first == second

  def test_differs_when_body_changes(self):
    from oneid.attestation import compute_attestation_input_for_direct_mode
    input_a = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body A",
      attestation_timestamp_unix=1711022400,
    )
    input_b = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body B",
      attestation_timestamp_unix=1711022400,
    )
    assert input_a != input_b

  def test_differs_when_timestamp_changes(self):
    from oneid.attestation import compute_attestation_input_for_direct_mode
    input_a = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    input_b = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022401,
    )
    assert input_a != input_b

  def test_differs_when_self_reference_header_changes(self):
    from oneid.attestation import compute_attestation_input_for_direct_mode
    input_a = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"body",
      attestation_timestamp_unix=1711022400,
      hardware_attestation_header_value_without_chain="v=1; typ=TPM; chain=",
    )
    input_b = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"body",
      attestation_timestamp_unix=1711022400,
      hardware_attestation_header_value_without_chain="v=1; typ=PIV; chain=",
    )
    assert input_a != input_b

  def test_matches_manual_rfc_computation(self):
    """Manually compute attestation-input per RFC and compare."""
    from oneid.attestation import (
      compute_attestation_input_for_direct_mode,
      canonicalise_headers_for_direct_attestation,
      canonicalise_body_using_dkim_simple,
    )
    body_bytes = b"Hello, world!\r\n"
    timestamp = 1711022400
    header_template = "v=1; typ=TPM; alg=RS256; chain="

    canon_headers = canonicalise_headers_for_direct_attestation(
      _SAMPLE_EMAIL_HEADERS, header_template,
    )
    h_hash = hashlib.sha256(canon_headers).digest()
    bh_raw = hashlib.sha256(canonicalise_body_using_dkim_simple(body_bytes)).digest()
    ts_bytes = struct.pack(">Q", timestamp)
    expected_attestation_input = h_hash + bh_raw + ts_bytes

    actual = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=body_bytes,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=header_template,
    )
    assert actual == expected_attestation_input
    assert len(actual) == 72

  def test_structure_is_h_hash_then_bh_raw_then_ts_bytes(self):
    """Verify the internal structure: first 32 bytes = h-hash, next 32 = bh-raw, last 8 = ts."""
    from oneid.attestation import (
      compute_attestation_input_for_direct_mode,
      canonicalise_headers_for_direct_attestation,
      canonicalise_body_using_dkim_simple,
    )
    body_bytes = b"Test body\r\n"
    timestamp = 1711022400

    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=body_bytes,
      attestation_timestamp_unix=timestamp,
    )

    canon_headers = canonicalise_headers_for_direct_attestation(_SAMPLE_EMAIL_HEADERS)
    expected_h_hash = hashlib.sha256(canon_headers).digest()
    expected_bh_raw = hashlib.sha256(canonicalise_body_using_dkim_simple(body_bytes)).digest()
    expected_ts = struct.pack(">Q", timestamp)

    assert attestation_input[:32] == expected_h_hash
    assert attestation_input[32:64] == expected_bh_raw
    assert attestation_input[64:] == expected_ts


class TestDerEncodingHelpers:
  """Test the low-level DER encoding functions used for CMS construction."""

  def test_length_encoding_short_form(self):
    from oneid.attestation import _der_encode_length
    assert _der_encode_length(0) == b"\x00"
    assert _der_encode_length(127) == b"\x7f"

  def test_length_encoding_long_form_one_byte(self):
    from oneid.attestation import _der_encode_length
    assert _der_encode_length(128) == b"\x81\x80"
    assert _der_encode_length(255) == b"\x81\xff"

  def test_length_encoding_long_form_two_bytes(self):
    from oneid.attestation import _der_encode_length
    assert _der_encode_length(256) == b"\x82\x01\x00"
    assert _der_encode_length(65535) == b"\x82\xff\xff"

  def test_integer_encoding_zero(self):
    from oneid.attestation import _der_encode_integer
    result = _der_encode_integer(0)
    assert result == b"\x02\x01\x00"

  def test_integer_encoding_one(self):
    from oneid.attestation import _der_encode_integer
    result = _der_encode_integer(1)
    assert result == b"\x02\x01\x01"

  def test_oid_encoding_sha256(self):
    from oneid.attestation import _der_encode_oid
    result = _der_encode_oid("2.16.840.1.101.3.4.2.1")
    assert result[0] == 0x06
    assert len(result) > 2

  def test_oid_encoding_signed_data(self):
    from oneid.attestation import _der_encode_oid
    result = _der_encode_oid("1.2.840.113549.1.7.2")
    assert result[0] == 0x06


class TestBuildCmsSignedData:
  """Test CMS SignedData construction for Mode 1."""

  @pytest.mark.parametrize(("rfc_alg", "expected_signature_algorithm_identifier_hex"), [
    ("RS256", "300d06092a864886f70d01010b0500"),
    ("ES256", "300a06082a8648ce3d040302"),
    ("PS256", "304106092a864886f70d01010a3034a00f300d06096086480165030402010500"
              "a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120"),
  ])
  def test_algorithm_identifiers_match_the_email_draft_cms_algorithm_mapping_aud_f23(
    self, rfc_alg, expected_signature_algorithm_identifier_hex,
  ):
    # RS256 NULL params, ES256 none, PS256 explicit PSS params; SHA-256 digest
    # AlgorithmIdentifier with absent params in digestAlgorithms and SignerInfo.
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=b"\x01" * 64,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name=rfc_alg,
    )
    assert bytes.fromhex(expected_signature_algorithm_identifier_hex) in cms_der
    assert cms_der.count(bytes.fromhex("300b0609608648016503040201")) == 2
    assert bytes.fromhex("300c06082a8648ce3d0403020500") not in cms_der

  def test_produces_valid_der_bytes(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    fake_signature = b"\x00" * 256

    result = build_cms_signed_data_for_direct_attestation(
      signature_bytes=fake_signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="RS256",
    )

    assert isinstance(result, bytes)
    assert len(result) > 100
    assert result[0] == 0x30

  def test_contains_oid_for_signed_data(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation, _der_encode_oid
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    fake_signature = b"\x00" * 256

    result = build_cms_signed_data_for_direct_attestation(
      signature_bytes=fake_signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="RS256",
    )

    signed_data_oid = _der_encode_oid("1.2.840.113549.1.7.2")
    oid_bytes = signed_data_oid[2:]
    assert oid_bytes in result

  def test_contains_certificate_der_bytes(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, leaf_cert, _ = _generate_test_certificate_chain_pem()
    fake_signature = b"\x00" * 256

    result = build_cms_signed_data_for_direct_attestation(
      signature_bytes=fake_signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="RS256",
    )

    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    assert leaf_der in result

  def test_contains_signature_bytes(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    fake_signature = b"\xDE\xAD\xBE\xEF" * 64

    result = build_cms_signed_data_for_direct_attestation(
      signature_bytes=fake_signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="RS256",
    )

    assert fake_signature in result

  def test_rejects_unsupported_algorithm(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    with pytest.raises(ValueError, match="Unsupported signature algorithm"):
      build_cms_signed_data_for_direct_attestation(
        signature_bytes=b"\x00" * 64,
        certificate_chain_pem=chain_pem,
        signature_algorithm_rfc_name="UNSUPPORTED",
      )

  def test_rejects_empty_certificate_chain(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    with pytest.raises(ValueError, match="no parseable certificates"):
      build_cms_signed_data_for_direct_attestation(
        signature_bytes=b"\x00" * 64,
        certificate_chain_pem="not a real PEM",
        signature_algorithm_rfc_name="RS256",
      )

  def test_supports_es256_algorithm(self):
    from oneid.attestation import build_cms_signed_data_for_direct_attestation
    chain_pem, _, _ = _generate_test_certificate_chain_pem()
    fake_signature = b"\x00" * 72

    result = build_cms_signed_data_for_direct_attestation(
      signature_bytes=fake_signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="ES256",
    )

    assert isinstance(result, bytes)
    assert len(result) > 100


# ---------------------------------------------------------------------------
# Tests: G2.2 End-to-end sign+verify and G2.3 signedAttrs absent
# ---------------------------------------------------------------------------


def _generate_ec_test_cert_chain_for_software_declared_tier():
  """Generate an EC P-256 self-signed CA + leaf cert for software declared-tier testing."""
  ca_key = ec.generate_private_key(ec.SECP256R1())
  ca_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SFT CA")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SFT CA")]))
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
  )

  leaf_key = ec.generate_private_key(ec.SECP256R1())
  leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SFT Leaf")]))
    .issuer_name(ca_cert.subject)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .sign(ca_key, hashes.SHA256())
  )

  from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
  chain_pem = (
    leaf_cert.public_bytes(Encoding.PEM).decode("ascii")
    + ca_cert.public_bytes(Encoding.PEM).decode("ascii")
  )
  private_key_pem = leaf_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
  return chain_pem, private_key_pem, leaf_cert, ca_cert


class TestEndToEndMode1SignThenVerify:
  """G2.2: Sign with the SDK, verify with the verifier, using software EC key."""

  def test_ec_software_sign_then_verify_round_trip(self):
    """Full Mode 1 round-trip: SDK signs, verifier verifies."""
    import sys, os
    sys.path.insert(0, os.path.join(
      os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

    from oneid.attestation import (
      compute_attestation_input_for_direct_mode,
      canonicalise_headers_for_direct_attestation,
      _sign_attestation_input_with_software_key,
      build_cms_signed_data_for_direct_attestation,
    )
    from hw_attest_verify.mode1 import verify_hardware_attestation

    chain_pem, private_key_pem, leaf_cert, ca_cert = (
      _generate_ec_test_cert_chain_for_software_declared_tier())

    body = b"Hello, this is an attested email.\r\n"
    headers = dict(_SAMPLE_EMAIL_HEADERS)
    timestamp = 1711022400

    signed_header_names = _NINE_ALWAYS_COVERED_FIELDS_LISTED_TWICE_FOR_OVERSIGNED_H_TAG
    bh_raw = hashlib.sha256(body).digest()
    bh_b64url = base64.urlsafe_b64encode(bh_raw).rstrip(b"=").decode("ascii")

    header_template = (
      f"v=1; typ=SFT; alg=ES256; "
      f"h={signed_header_names}; bh={bh_b64url}; ts={timestamp}; "
      f"chain="
    )

    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=headers,
      body_bytes=body,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=header_template,
    )
    assert len(attestation_input) == 72

    signature_bytes = _sign_attestation_input_with_software_key(
      attestation_input, private_key_pem)

    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=signature_bytes,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="ES256",
    )
    chain_b64 = base64.b64encode(cms_der).decode("ascii")

    full_header_value = (
      f"v=1; typ=SFT; alg=ES256; "
      f"h={signed_header_names}; bh={bh_b64url}; ts={timestamp}; "
      f"chain={chain_b64}"
    )

    result = verify_hardware_attestation(
      header_value=full_header_value,
      email_headers=headers,
      body=body,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )

    assert result.is_valid, f"Verification failed: {result.failure_reasons}"
    assert result.typ == "SFT"
    assert result.alg == "ES256"
    assert result.timestamp_unix == timestamp

  def test_rsa_software_sign_then_verify_round_trip(self):
    """Full Mode 1 round-trip with RSA key (validates double-hash bug is fixed)."""
    import sys, os
    sys.path.insert(0, os.path.join(
      os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

    from oneid.attestation import (
      compute_attestation_input_for_direct_mode,
      _sign_attestation_input_with_software_key,
      build_cms_signed_data_for_direct_attestation,
    )
    from hw_attest_verify.mode1 import verify_hardware_attestation
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (
      x509.CertificateBuilder()
      .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test RSA CA")]))
      .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test RSA CA")]))
      .public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.now(timezone.utc))
      .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
      x509.CertificateBuilder()
      .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test RSA Leaf")]))
      .issuer_name(ca_cert.subject)
      .public_key(leaf_key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.now(timezone.utc))
      .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
      .sign(ca_key, hashes.SHA256())
    )

    chain_pem = (
      leaf_cert.public_bytes(Encoding.PEM).decode("ascii")
      + ca_cert.public_bytes(Encoding.PEM).decode("ascii")
    )
    private_key_pem = leaf_key.private_bytes(
      Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")

    body = b"RSA test body\r\n"
    headers = dict(_SAMPLE_EMAIL_HEADERS)
    timestamp = 1711022400

    signed_header_names = _NINE_ALWAYS_COVERED_FIELDS_LISTED_TWICE_FOR_OVERSIGNED_H_TAG
    bh_raw = hashlib.sha256(body).digest()
    bh_b64url = base64.urlsafe_b64encode(bh_raw).rstrip(b"=").decode("ascii")

    header_template = (
      f"v=1; typ=SFT; alg=RS256; "
      f"h={signed_header_names}; bh={bh_b64url}; ts={timestamp}; "
      f"chain="
    )

    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=headers,
      body_bytes=body,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=header_template,
    )
    assert len(attestation_input) == 72

    signature_bytes = _sign_attestation_input_with_software_key(
      attestation_input, private_key_pem)

    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=signature_bytes,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="RS256",
    )
    chain_b64 = base64.b64encode(cms_der).decode("ascii")

    full_header_value = (
      f"v=1; typ=SFT; alg=RS256; "
      f"h={signed_header_names}; bh={bh_b64url}; ts={timestamp}; "
      f"chain={chain_b64}"
    )

    result = verify_hardware_attestation(
      header_value=full_header_value,
      email_headers=headers,
      body=body,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )

    assert result.is_valid, f"RSA verification failed: {result.failure_reasons}"
    assert result.alg == "RS256"

  def test_folded_chain_round_trips_then_unknown_tag_or_reordered_tags_are_rejected(self):
    """Legal chain FWS is transport-only; unknown tags and reordering are malformed (AUD-F25/F74)."""
    import os
    import sys
    sys.path.insert(0, os.path.join(
      os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

    from oneid.attestation import (
      _sign_attestation_input_with_software_key,
      build_cms_signed_data_for_direct_attestation,
      compute_attestation_input_for_direct_mode,
    )
    from oneid.mailpal import _fold_long_header_value_for_smtp_transmission
    from hw_attest_verify.mode1 import verify_hardware_attestation

    chain_pem, private_key_pem, _, _ = (
      _generate_ec_test_cert_chain_for_software_declared_tier())
    body = b"Folded Mode 1 body.\r\n"
    headers = dict(_SAMPLE_EMAIL_HEADERS)
    timestamp = 1711022400
    signed_header_names = _NINE_ALWAYS_COVERED_FIELDS_LISTED_TWICE_FOR_OVERSIGNED_H_TAG
    body_hash_base64url = base64.urlsafe_b64encode(
      hashlib.sha256(body).digest()
    ).rstrip(b"=").decode("ascii")
    header_template_with_empty_chain = (
      f"v=1; typ=SFT; alg=ES256; h={signed_header_names}; "
      f"bh={body_hash_base64url}; ts={timestamp}; chain="
    )
    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=headers,
      body_bytes=body,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=header_template_with_empty_chain,
    )
    signature_bytes = _sign_attestation_input_with_software_key(
      attestation_input, private_key_pem
    )
    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=signature_bytes,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="ES256",
    )
    emitted_header_value = header_template_with_empty_chain + base64.b64encode(
      cms_der
    ).decode("ascii")
    folded_header_field = _fold_long_header_value_for_smtp_transmission(
      "Hardware-Attestation", emitted_header_value
    )
    folded_header_value = folded_header_field.split(":", 1)[1]

    valid_result = verify_hardware_attestation(
      header_value=folded_header_value,
      email_headers=headers,
      body=body,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert valid_result.is_valid, valid_result.failure_reasons

    modified_extension_result = verify_hardware_attestation(
      header_value=folded_header_value + "; future=alpha",
      email_headers=headers,
      body=body,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert not modified_extension_result.is_valid
    assert any(
      "Unrecognized tag 'future'" in failure_reason
      for failure_reason in modified_extension_result.failure_reasons
    )

    reordered_tag_result = verify_hardware_attestation(
      header_value=emitted_header_value.replace(
        "typ=SFT; alg=ES256", "alg=ES256; typ=SFT"
      ),
      email_headers=headers,
      body=body,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert not reordered_tag_result.is_valid
    assert any(
      "required order" in failure_reason
      for failure_reason in reordered_tag_result.failure_reasons
    )

  def test_combined_mode_removing_or_changing_hardware_trust_proof_breaks_mode1(self):
    """Mode 1 covers the complete Mode-2 field in Combined Mode."""
    import os
    import sys
    sys.path.insert(0, os.path.join(
      os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

    from oneid.attestation import (
      _sign_attestation_input_with_software_key,
      build_cms_signed_data_for_direct_attestation,
      compute_attestation_input_for_direct_mode,
    )
    from hw_attest_verify.mode1 import verify_hardware_attestation

    chain_pem, private_key_pem, _, _ = (
      _generate_ec_test_cert_chain_for_software_declared_tier())
    body = b"Combined Mode body.\r\n"
    headers = dict(_SAMPLE_EMAIL_HEADERS)
    headers["Hardware-Trust-Proof"] = "header.payload.signature~disclosure~"
    timestamp = 1711022400
    signed_header_names = (
      "from:to:subject:date:message-id:reply-to:mime-version:content-type:content-transfer-encoding:hardware-trust-proof:"
      "from:to:subject:date:message-id:reply-to:mime-version:content-type:content-transfer-encoding:hardware-trust-proof"
    )
    body_hash_base64url = base64.urlsafe_b64encode(
      hashlib.sha256(body).digest()
    ).rstrip(b"=").decode("ascii")
    empty_chain_header_value = (
      f"v=1; typ=SFT; alg=ES256; h={signed_header_names}; "
      f"bh={body_hash_base64url}; ts={timestamp}; chain="
    )
    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=headers,
      body_bytes=body,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=empty_chain_header_value,
    )
    signature_bytes = _sign_attestation_input_with_software_key(
      attestation_input, private_key_pem
    )
    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=signature_bytes,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="ES256",
    )
    full_header_value = empty_chain_header_value + base64.b64encode(cms_der).decode("ascii")
    ordered_header_pairs = list(headers.items())

    initial_result = verify_hardware_attestation(
      header_value=full_header_value,
      email_headers=headers,
      body=body,
      ordered_header_pairs=ordered_header_pairs,
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert initial_result.is_valid, initial_result.failure_reasons

    changed_headers = dict(headers)
    changed_headers["Hardware-Trust-Proof"] = "header.payload.signature~changed~"
    changed_result = verify_hardware_attestation(
      header_value=full_header_value,
      email_headers=changed_headers,
      body=body,
      ordered_header_pairs=list(changed_headers.items()),
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert not changed_result.is_valid

    removed_headers = dict(_SAMPLE_EMAIL_HEADERS)
    removed_result = verify_hardware_attestation(
      header_value=full_header_value,
      email_headers=removed_headers,
      body=body,
      ordered_header_pairs=list(removed_headers.items()),
      allow_self_signed=True,
      reference_time_unix=timestamp,
    )
    assert not removed_result.is_valid


class TestCmsSignedDataHasNoSignedAttrs:
  """G2.3: Confirm signedAttrs is absent in the CMS SignedData we build."""

  def test_signer_info_has_no_signed_attrs_tag(self):
    """Per RFC: 'SignerInfo signedAttrs MUST be absent in version 1'.
    In CMS DER, signedAttrs would be an IMPLICIT [0] tag (0xA0) inside
    SignerInfo. Our CMS builder must NOT include it."""
    from oneid.attestation import (
      build_cms_signed_data_for_direct_attestation,
      _sign_attestation_input_with_software_key,
      compute_attestation_input_for_direct_mode,
    )

    chain_pem, private_key_pem, _, _ = (
      _generate_ec_test_cert_chain_for_software_declared_tier())

    attestation_input = compute_attestation_input_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"test body\r\n",
      attestation_timestamp_unix=1711022400,
    )

    signature = _sign_attestation_input_with_software_key(
      attestation_input, private_key_pem)

    cms_der = build_cms_signed_data_for_direct_attestation(
      signature_bytes=signature,
      certificate_chain_pem=chain_pem,
      signature_algorithm_rfc_name="ES256",
    )

    signer_info_bytes = _extract_signer_info_from_cms(cms_der)
    assert signer_info_bytes is not None, "Could not extract SignerInfo from CMS"

    _verify_no_signed_attrs_in_signer_info(signer_info_bytes)


def _extract_signer_info_from_cms(cms_der: bytes) -> bytes:
  """Extract the raw SignerInfo SEQUENCE bytes from CMS SignedData DER."""
  from hw_attest_verify.mode1 import _asn1_read_tag_length
  import sys, os
  sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

  offset = 0
  tag, length, value_offset = _asn1_read_tag_length(cms_der, offset)
  content_info = cms_der[value_offset:value_offset + length]

  inner_offset = 0
  _, oid_len, oid_val_offset = _asn1_read_tag_length(content_info, inner_offset)
  inner_offset = oid_val_offset + oid_len

  _, explicit_len, explicit_val_offset = _asn1_read_tag_length(content_info, inner_offset)
  signed_data_bytes = content_info[explicit_val_offset:explicit_val_offset + explicit_len]

  _, sd_len, sd_val_offset = _asn1_read_tag_length(signed_data_bytes, 0)
  sd_content = signed_data_bytes[sd_val_offset:sd_val_offset + sd_len]

  last_set_content = None
  pos = 0
  while pos < len(sd_content):
    elem_tag, elem_len, elem_val_offset = _asn1_read_tag_length(sd_content, pos)
    elem_end = elem_val_offset + elem_len
    if elem_tag == 0x31:
      last_set_content = sd_content[elem_val_offset:elem_end]
    pos = elem_end

  return last_set_content


def _verify_no_signed_attrs_in_signer_info(signer_info_set_content: bytes):
  """Walk the SignerInfo SEQUENCE and assert no IMPLICIT [0] (signedAttrs) tag."""
  from hw_attest_verify.mode1 import _asn1_read_tag_length

  si_tag, si_len, si_val_offset = _asn1_read_tag_length(signer_info_set_content, 0)
  assert si_tag == 0x30, f"Expected SEQUENCE (0x30) for SignerInfo, got 0x{si_tag:02x}"

  si_content = signer_info_set_content[si_val_offset:si_val_offset + si_len]
  pos = 0
  while pos < len(si_content):
    elem_tag, elem_len, elem_val_offset = _asn1_read_tag_length(si_content, pos)
    assert elem_tag != 0xA0, (
      "Found IMPLICIT [0] tag (signedAttrs) in SignerInfo -- "
      "RFC requires signedAttrs MUST be absent in version 1"
    )
    pos = elem_val_offset + elem_len


# ---------------------------------------------------------------------------
# Tests: prepare_attestation (Mode 2)
# ---------------------------------------------------------------------------

class TestPrepareAttestation:
  """Test the oneid.prepare_attestation() core primitive."""

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof_for_message")
  def test_simple_mode_returns_attestation_proof_with_all_artifacts(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("signed.jwt.here", {"1id_trust_tier": "disc123"})
    mock_fetch_contact.return_value = ("a1b2c3d4", "a1b2c3d4.testhandle@1id.com")

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(content=b"test content")

    assert proof.sd_jwt == "signed.jwt.here"
    assert proof.sd_jwt_disclosures == {"1id_trust_tier": "disc123"}
    assert proof.contact_token == "a1b2c3d4"
    assert proof.contact_address == "a1b2c3d4.testhandle@1id.com"

    expected_digest = "sha256:" + hashlib.sha256(b"test content").hexdigest()
    assert proof.content_digest == expected_digest

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof_for_message")
  def test_rfc_email_mode_calls_with_rfc_nonce(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("signed.jwt.here", {"1id_trust_tier": "disc123"})
    mock_fetch_contact.return_value = ("a1b2c3d4", "addr")

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body=b"email body text",
    )

    assert proof.sd_jwt == "signed.jwt.here"
    call_kwargs = mock_fetch_sd_jwt.call_args
    nonce_arg = call_kwargs[1].get("precomputed_nonce") or call_kwargs[0][2] if call_kwargs[0] else None
    if nonce_arg is None:
      nonce_arg = call_kwargs.kwargs.get("precomputed_nonce")
    assert nonce_arg is not None
    assert len(nonce_arg) == 43

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof_for_message")
  def test_accepts_pre_computed_content_digest(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("jwt", {})
    mock_fetch_contact.return_value = (None, None)

    from oneid.attestation import prepare_attestation
    # AUD-F83: a pre-computed digest must be a real SHA-256 value.
    proof = prepare_attestation(content_digest="sha256:abababababababababababababababababababababababababababababababab")

    assert proof.content_digest == "sha256:abababababababababababababababababababababababababababababababab"

  def test_rejects_both_content_and_digest(self):
    from oneid.attestation import prepare_attestation
    with pytest.raises(ValueError, match="not both"):
      prepare_attestation(content=b"data", content_digest="sha256:abc")

  def test_rejects_mixing_email_mode_with_simple_mode(self):
    from oneid.attestation import prepare_attestation
    with pytest.raises(ValueError, match="Cannot mix"):
      prepare_attestation(
        email_headers=_SAMPLE_EMAIL_HEADERS,
        body=b"body",
        content=b"also content",
      )

  def test_rejects_email_headers_without_body(self):
    from oneid.attestation import prepare_attestation
    with pytest.raises(ValueError, match="body is required"):
      prepare_attestation(email_headers=_SAMPLE_EMAIL_HEADERS)

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof_for_message")
  def test_skips_sd_jwt_when_disabled(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_contact.return_value = ("tok", "addr")

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(include_sd_jwt=False)

    mock_fetch_sd_jwt.assert_not_called()
    assert proof.sd_jwt is None

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof_for_message")
  def test_skips_contact_token_when_disabled(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("jwt", {})

    from oneid.attestation import prepare_attestation
    # AUD-F83: an SD-JWT request needs content to bind to.
    proof = prepare_attestation(content=b"data", include_contact_token=False)

    mock_fetch_contact.assert_not_called()
    assert proof.contact_token is None


# ---------------------------------------------------------------------------
# Tests: mailpal.send
# ---------------------------------------------------------------------------

class TestMailpalSend:
  """Test oneid.mailpal.send() convenience wrapper."""

  # send() submits via direct SMTP (smtplib), not the HTTP API -- these
  # tests mock smtplib.SMTP and inspect the transmitted message bytes.

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.prepare_attestation")
  @patch("oneid.mailpal.smtplib.SMTP")
  def test_sends_email_with_attestation_headers(
    self,
    mock_smtp_class,
    mock_prepare,
    mock_load_creds,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()
    mock_load_creds.return_value = _mock_credentials()

    mock_proof = MagicMock()
    mock_proof.sd_jwt = "signed.sd.jwt"
    mock_proof.sd_jwt_disclosures = {}
    mock_proof.contact_token = "a1b2c3d4"
    mock_proof.content_digest = "sha256:deadbeef"
    mock_prepare.return_value = mock_proof

    mock_smtp_connection = MagicMock()
    mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp_connection)
    mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="Test",
      text_body="Hello from test",
      attestation_mode="sd-jwt",
    )

    assert result.message_id  # generated Message-ID
    assert result.attestation_headers_included is True
    assert result.sd_jwt_header_included is True

    mock_smtp_connection.starttls.assert_called_once()
    mock_smtp_connection.login.assert_called_once()
    sent_bytes = mock_smtp_connection.sendmail.call_args[0][2]
    sent_text = sent_bytes.decode() if isinstance(sent_bytes, bytes) else sent_bytes
    assert "Hardware-Trust-Proof:" in sent_text
    assert "signed.sd.jwt" in sent_text
    assert "X-1ID-Contact-Token: a1b2c3d4" in sent_text

  @patch("oneid.attestation.prepare_direct_hardware_attestation")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.prepare_attestation")
  def test_combined_mode_generates_and_injects_mode2_before_mode1(
    self,
    mock_prepare_mode2,
    mock_load_creds,
    mock_prepare_mode1,
  ):
    credentials = _mock_credentials()
    credentials.identity_certificate_chain_pem = None
    credentials.agent_identity_urn = None
    mock_load_creds.return_value = credentials

    mode2_proof = MagicMock()
    mode2_proof.sd_jwt = "header.payload.signature"
    mode2_proof.sd_jwt_disclosures = {"tier": "disclosure"}
    mode2_proof.contact_token = None
    mock_prepare_mode2.return_value = mode2_proof

    def assert_mode2_is_present_before_returning_mode1_proof(
      email_headers,
      body,
      binding_jws=None,
      **other_keyword_arguments_passed_by_mailpal_send,
    ):
      assert "hardware-trust-proof" in email_headers
      assert "header.payload.signature" in email_headers["hardware-trust-proof"]
      mode1_proof = MagicMock()
      mode1_proof.hardware_attestation_header_value = (
        "v=1; typ=SFT; alg=ES256; "
        "h=from:to:subject:date:message-id:hardware-trust-proof; "
        "bh=abc; ts=1; chain=" + "A" * 1600
      )
      return mode1_proof

    mock_prepare_mode1.side_effect = assert_mode2_is_present_before_returning_mode1_proof

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="Combined",
      text_body="Combined body",
      attestation_mode="both",
      deliver=False,
    )
    raw_message = result.rfc5322_message_bytes
    assert raw_message is not None
    assert raw_message.index(b"Hardware-Trust-Proof:") < raw_message.index(
      b"Hardware-Attestation:"
    )
    assert b"\r\r\n" not in raw_message
    assert all(
      len(physical_line) <= 998
      for physical_line in raw_message.split(b"\r\n")
    )

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.smtplib.SMTP")
  def test_sends_email_without_attestation(
    self,
    mock_smtp_class,
    mock_load_creds,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()
    mock_load_creds.return_value = _mock_credentials()

    mock_smtp_connection = MagicMock()
    mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp_connection)
    mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="No attestation",
      text_body="Plain message",
      include_attestation=False,
    )

    assert result.message_id
    assert result.attestation_headers_included is False
    sent_bytes = mock_smtp_connection.sendmail.call_args[0][2]
    sent_text = sent_bytes.decode() if isinstance(sent_bytes, bytes) else sent_bytes
    assert "Hardware-Trust-Proof" not in sent_text


# ---------------------------------------------------------------------------
# Tests: mailpal.activate
# ---------------------------------------------------------------------------

class TestMailpalActivate:
  """Test oneid.mailpal.activate() wrapper."""

  # load_credentials/save_credentials MUST be mocked too: activate()
  # persists the returned mailpal_email/app_password, and without these
  # patches the test writes mock values into the REAL
  # ~/.config/oneid/credentials.json (observed corrupting live enclave
  # credentials before this fix).
  @patch("oneid.mailpal.save_credentials")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_returns_account_info(
    self,
    mock_httpx_client_class,
    mock_get_token,
    mock_load_credentials,
    mock_save_credentials,
  ):
    mock_get_token.return_value = _mock_token()
    mock_load_credentials.return_value = _mock_credentials()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
      "data": {
        "primary_email": "id-tsthj-zhshb-sqpck-bghgw@mailpal.com",
        "vanity_email": "clawdia@mailpal.com",
        "app_password": "generated-pw",
        "already_existed": False,
      }
    }

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import activate
    account = activate()

    assert account.primary_email == "id-tsthj-zhshb-sqpck-bghgw@mailpal.com"
    assert account.vanity_email == "clawdia@mailpal.com"
    assert account.app_password == "generated-pw"
    assert account.already_existed is False
    # persistence must go through the (mocked) save path, never the real file
    assert mock_save_credentials.called


# ---------------------------------------------------------------------------
# Tests: mailpal.inbox
# ---------------------------------------------------------------------------

class TestMailpalInbox:
  """Test oneid.mailpal.inbox() wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_returns_list_of_inbox_messages(
    self,
    mock_httpx_client_class,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
      "data": {
        "messages": [
          {"id": "m1", "from": "alice@example.com", "subject": "Hi", "received_at": "2026-02-20T10:00:00Z", "is_unread": True},
          {"id": "m2", "from": "bob@example.com", "subject": "Re: Hi", "received_at": "2026-02-20T11:00:00Z", "is_unread": False},
        ],
        "total_count": 2,
      }
    }

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.get.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import inbox
    messages = inbox()

    assert len(messages) == 2
    assert messages[0].message_id == "m1"
    assert messages[0].subject == "Hi"
    assert messages[0].is_unread is True
    assert messages[1].message_id == "m2"
    assert messages[1].is_unread is False

