"""Combined mode sender rules (email draft; AUD-F47, AUD-F48, INV-E3) and the
AUD-F83 content rule. Offline: all network calls are mocked.

- Combined mode: Mode 2 is requested with the Mode 1 proof key as cnf_jwk, and
  with sub disclosed whenever a Registrar binding (hence aid) is available.
- If Mode 1 then fails, the cnf-bearing Mode 2 is replaced by a standalone
  Mode 2 (no cnf): verifiers must reject a cnf-bearing Mode 2 on its own.
- An SD-JWT request needs content to bind to."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _certificate_pem_for_new_p256_key():
  key = ec.generate_private_key(ec.SECP256R1())
  name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "combined mode test")])
  now = datetime.now(timezone.utc)
  certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                 .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
  return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _credentials_with_certificate_chain(agent_identity_urn):
  credentials = MagicMock()
  credentials.client_id = "id-tsthj-zhshb-sqpck-bghgw"
  credentials.api_base_url = "https://1id.com"
  credentials.display_name = "Test Agent"
  credentials.mailpal_email = "id-tsthj-zhshb-sqpck-bghgw@mailpal.com"
  credentials.mailpal_app_password = "unused"
  credentials.identity_certificate_chain_pem = _certificate_pem_for_new_p256_key()
  credentials.device_certificate_chains = None
  credentials.agent_identity_urn = agent_identity_urn
  return credentials


def _mode2_proof(sd_jwt):
  proof = MagicMock()
  proof.sd_jwt = sd_jwt
  proof.sd_jwt_disclosures = {"aid": "disclosure"}
  proof.contact_token = None
  return proof


def _mode1_proof():
  proof = MagicMock()
  proof.hardware_attestation_header_value = "v=1; typ=SFT; alg=ES256; h=from; bh=abc; ts=1; chain=QUJD"
  return proof


@patch("oneid.mailpal.get_token")
@patch("oneid.attestation._fetch_binding_jws")
@patch("oneid.attestation.prepare_direct_hardware_attestation")
@patch("oneid.mailpal.prepare_attestation")
@patch("oneid.mailpal.load_credentials")
def test_combined_mode_requests_cnf_and_sub_then_signs_mode1_with_the_binding(
  mock_load_credentials, mock_prepare_mode2, mock_prepare_mode1, mock_fetch_binding, mock_get_token,
):
  mock_load_credentials.return_value = _credentials_with_certificate_chain("urn:aid:global:id-tsthj-zhshb-sqpck-bghgw")
  mock_get_token.return_value = MagicMock(access_token="token")
  mock_fetch_binding.return_value = "binding.jws.value"
  mock_prepare_mode2.return_value = _mode2_proof("combined.sd.jwt")
  mock_prepare_mode1.return_value = _mode1_proof()

  from oneid.mailpal import send
  result = send(to=["r@example.com"], subject="Combined", text_body="Body", attestation_mode="both", deliver=False)

  mode2_call = mock_prepare_mode2.call_args
  assert mode2_call.kwargs["cnf_jwk"]["kty"] == "EC"
  assert "sub" in mode2_call.kwargs["disclosed_claims"] and "aid" in mode2_call.kwargs["disclosed_claims"]
  assert mock_prepare_mode1.call_args.kwargs["binding_jws"] == "binding.jws.value"
  assert b"combined.sd.jwt" in result.rfc5322_message_bytes
  assert b"Hardware-Attestation:" in result.rfc5322_message_bytes


@patch("oneid.mailpal.get_token")
@patch("oneid.attestation._fetch_binding_jws")
@patch("oneid.attestation.prepare_direct_hardware_attestation")
@patch("oneid.mailpal.prepare_attestation")
@patch("oneid.mailpal.load_credentials")
def test_combined_mode_without_binding_requests_cnf_but_not_sub(
  mock_load_credentials, mock_prepare_mode2, mock_prepare_mode1, mock_fetch_binding, mock_get_token,
):
  mock_load_credentials.return_value = _credentials_with_certificate_chain(None)
  mock_prepare_mode2.return_value = _mode2_proof("combined.sd.jwt")
  mock_prepare_mode1.return_value = _mode1_proof()

  from oneid.mailpal import send
  send(to=["r@example.com"], subject="Combined", text_body="Body", attestation_mode="both", deliver=False)

  mock_fetch_binding.assert_not_called()
  assert mock_prepare_mode2.call_args.kwargs["cnf_jwk"] is not None
  assert "sub" not in mock_prepare_mode2.call_args.kwargs["disclosed_claims"]


@patch("oneid.mailpal.get_token")
@patch("oneid.attestation._fetch_binding_jws")
@patch("oneid.attestation.prepare_direct_hardware_attestation")
@patch("oneid.mailpal.prepare_attestation")
@patch("oneid.mailpal.load_credentials")
def test_failed_mode1_replaces_the_cnf_bearing_mode2_with_a_standalone_one(
  mock_load_credentials, mock_prepare_mode2, mock_prepare_mode1, mock_fetch_binding, mock_get_token,
):
  mock_load_credentials.return_value = _credentials_with_certificate_chain(None)
  mock_prepare_mode2.side_effect = [_mode2_proof("combined.sd.jwt"), _mode2_proof("standalone.sd.jwt")]
  mock_prepare_mode1.side_effect = RuntimeError("TPM unavailable")

  from oneid.mailpal import send
  result = send(to=["r@example.com"], subject="Combined", text_body="Body", attestation_mode="both", deliver=False,
                require_requested_attestation=False)

  first_call, second_call = mock_prepare_mode2.call_args_list
  assert first_call.kwargs["cnf_jwk"] is not None
  assert second_call.kwargs["cnf_jwk"] is None
  assert b"standalone.sd.jwt" in result.rfc5322_message_bytes
  assert b"combined.sd.jwt" not in result.rfc5322_message_bytes
  assert b"Hardware-Attestation:" not in result.rfc5322_message_bytes


@patch("oneid.mailpal.get_token")
@patch("oneid.attestation._fetch_binding_jws")
@patch("oneid.attestation.prepare_direct_hardware_attestation")
@patch("oneid.mailpal.prepare_attestation")
@patch("oneid.mailpal.load_credentials")
def test_failed_mode1_refuses_to_send_by_default(
  mock_load_credentials, mock_prepare_mode2, mock_prepare_mode1, mock_fetch_binding, mock_get_token,
):
  """AUD-F28: the caller asked for both proofs; without Mode 1 nothing is sent."""
  mock_load_credentials.return_value = _credentials_with_certificate_chain(None)
  mock_prepare_mode2.side_effect = [_mode2_proof("combined.sd.jwt"), _mode2_proof("standalone.sd.jwt")]
  mock_prepare_mode1.side_effect = RuntimeError("TPM unavailable")

  from oneid.exceptions import AttestationGenerationError
  from oneid.mailpal import send
  with pytest.raises(AttestationGenerationError, match=r"Mode 1 \(Hardware-Attestation\) failed: TPM unavailable"):
    send(to=["r@example.com"], subject="Combined", text_body="Body", attestation_mode="both", deliver=False)


@patch("oneid.attestation.get_token")
@patch("oneid.attestation.load_credentials")
def test_sd_jwt_request_without_content_or_with_a_malformed_digest_is_refused(mock_load_credentials, mock_get_token):
  from oneid.attestation import prepare_attestation
  with pytest.raises(ValueError, match="requires content to bind to"):
    prepare_attestation()
  with pytest.raises(ValueError, match="64 hex digits"):
    prepare_attestation(content_digest="sha256:abc")
