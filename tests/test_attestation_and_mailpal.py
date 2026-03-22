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
  creds.client_id = "1id-TESTMOCK"
  creds.client_secret = "mock-secret"
  creds.api_base_url = "https://1id.com"
  creds.token_endpoint = "https://1id.com/realms/agents/protocol/openid-connect/token"
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

  def test_requires_minimum_headers(self):
    from oneid.attestation import canonicalise_headers_for_message_binding
    with pytest.raises(ValueError, match="Missing required email header"):
      canonicalise_headers_for_message_binding({"From": "a@b.com"})

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

  def test_requires_minimum_headers(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    with pytest.raises(ValueError, match="Missing required email header"):
      canonicalise_headers_for_direct_attestation({"From": "a@b.com"})

  def test_self_references_hardware_attestation_not_trust_proof(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(_SAMPLE_EMAIL_HEADERS)
    decoded = result.decode("utf-8")
    assert "hardware-attestation:" in decoded
    assert "hardware-trust-proof" not in decoded

  def test_hardware_attestation_header_is_last_without_trailing_crlf(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(_SAMPLE_EMAIL_HEADERS)
    decoded = result.decode("utf-8")
    assert decoded.endswith("hardware-attestation:")
    assert not decoded.endswith("hardware-attestation:\r\n")

  def test_includes_header_value_in_self_reference(self):
    from oneid.attestation import canonicalise_headers_for_direct_attestation
    result = canonicalise_headers_for_direct_attestation(
      _SAMPLE_EMAIL_HEADERS,
      hardware_attestation_header_value_without_chain="v=1; typ=TPM; alg=RS256; chain=",
    )
    decoded = result.decode("utf-8")
    assert decoded.endswith("hardware-attestation:v=1; typ=TPM; alg=RS256; chain=")


class TestComputeAttestationDigestForDirectMode:
  """Verify the Mode 1 attestation-digest computation."""

  def test_produces_32_byte_sha256_digest(self):
    from oneid.attestation import compute_attestation_digest_for_direct_mode
    digest = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Hello, world!\r\n",
      attestation_timestamp_unix=1711022400,
    )
    assert isinstance(digest, bytes)
    assert len(digest) == 32

  def test_deterministic_for_same_inputs(self):
    from oneid.attestation import compute_attestation_digest_for_direct_mode
    digest_first = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    digest_second = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    assert digest_first == digest_second

  def test_differs_when_body_changes(self):
    from oneid.attestation import compute_attestation_digest_for_direct_mode
    digest_a = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body A",
      attestation_timestamp_unix=1711022400,
    )
    digest_b = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Body B",
      attestation_timestamp_unix=1711022400,
    )
    assert digest_a != digest_b

  def test_differs_when_timestamp_changes(self):
    from oneid.attestation import compute_attestation_digest_for_direct_mode
    digest_a = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022400,
    )
    digest_b = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"Same body",
      attestation_timestamp_unix=1711022401,
    )
    assert digest_a != digest_b

  def test_differs_when_self_reference_header_changes(self):
    from oneid.attestation import compute_attestation_digest_for_direct_mode
    digest_a = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"body",
      attestation_timestamp_unix=1711022400,
      hardware_attestation_header_value_without_chain="v=1; typ=TPM; chain=",
    )
    digest_b = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=b"body",
      attestation_timestamp_unix=1711022400,
      hardware_attestation_header_value_without_chain="v=1; typ=PIV; chain=",
    )
    assert digest_a != digest_b

  def test_matches_manual_rfc_computation(self):
    """Manually compute attestation-digest per RFC and compare."""
    from oneid.attestation import (
      compute_attestation_digest_for_direct_mode,
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
    attestation_input = h_hash + bh_raw + ts_bytes
    expected_digest = hashlib.sha256(attestation_input).digest()

    actual_digest = compute_attestation_digest_for_direct_mode(
      email_headers=_SAMPLE_EMAIL_HEADERS,
      body_bytes=body_bytes,
      attestation_timestamp_unix=timestamp,
      hardware_attestation_header_value_without_chain=header_template,
    )
    assert actual_digest == expected_digest


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
    proof = prepare_attestation(content_digest="sha256:abc123")

    assert proof.content_digest == "sha256:abc123"

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
    proof = prepare_attestation(include_contact_token=False)

    mock_fetch_contact.assert_not_called()
    assert proof.contact_token is None


# ---------------------------------------------------------------------------
# Tests: mailpal.send
# ---------------------------------------------------------------------------

class TestMailpalSend:
  """Test oneid.mailpal.send() convenience wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.prepare_attestation")
  @patch("oneid.mailpal.httpx.Client")
  def test_sends_email_with_attestation_headers(
    self,
    mock_httpx_client_class,
    mock_prepare,
    mock_load_creds,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()
    mock_load_creds.return_value = _mock_credentials()

    mock_proof = MagicMock()
    mock_proof.sd_jwt = "signed.sd.jwt"
    mock_proof.contact_token = "a1b2c3d4"
    mock_proof.content_digest = "sha256:deadbeef"
    mock_prepare.return_value = mock_proof

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"message_id": "msg-001", "from": "agent@mailpal.com"}}

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="Test",
      text_body="Hello from test",
    )

    assert result.message_id == "msg-001"
    assert result.attestation_headers_included is True
    assert result.sd_jwt_header_included is True
    assert result.contact_token_header_included is True

    call_args = mock_http_client.post.call_args
    sent_json = call_args.kwargs.get("json") or call_args[1].get("json")
    assert "custom_headers" in sent_json
    assert sent_json["custom_headers"]["Hardware-Trust-Proof"] == "signed.sd.jwt"
    assert sent_json["custom_headers"]["X-1ID-Contact-Token"] == "a1b2c3d4"

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.load_credentials")
  @patch("oneid.mailpal.httpx.Client")
  def test_sends_email_without_attestation(
    self,
    mock_httpx_client_class,
    mock_load_creds,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()
    mock_load_creds.return_value = _mock_credentials()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"message_id": "msg-002"}}

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="No attestation",
      text_body="Plain message",
      include_attestation=False,
    )

    assert result.message_id == "msg-002"
    assert result.attestation_headers_included is False


# ---------------------------------------------------------------------------
# Tests: mailpal.activate
# ---------------------------------------------------------------------------

class TestMailpalActivate:
  """Test oneid.mailpal.activate() wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_returns_account_info(
    self,
    mock_httpx_client_class,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
      "data": {
        "primary_email": "1id-TESTMOCK@mailpal.com",
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

    assert account.primary_email == "1id-TESTMOCK@mailpal.com"
    assert account.vanity_email == "clawdia@mailpal.com"
    assert account.app_password == "generated-pw"
    assert account.already_existed is False


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

