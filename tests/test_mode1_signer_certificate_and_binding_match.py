"""AUD-F81 (+F57 parity): the Mode 1 CMS signer certificate must carry the key
that produced the signature, and a Registrar binding must confirm that same key.
The device-type guess is only a first try: a stored chain for another key is
never packaged. Offline: credentials in a temporary directory, no network."""

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "hw-attest-verify"))

_HEADERS = {"From": "a@example.com", "To": "b@example.com", "Subject": "s",
            "Date": "Thu, 24 Sep 2026 12:00:00 +0000", "Message-ID": "<m@example.com>"}


def _new_key_and_self_signed_certificate_pem(common_name):
  key = ec.generate_private_key(ec.SECP256R1())
  name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
  now = datetime.now(timezone.utc)
  certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                 .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
  private_key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()).decode()
  return key, private_key_pem, certificate.public_bytes(serialization.Encoding.PEM).decode()


def _write_credentials(tmp_path, monkeypatch, private_key_pem, identity_chain_pem, device_chains):
  (tmp_path / "oneid").mkdir()
  (tmp_path / "oneid" / "credentials.json").write_text(json.dumps({
    "client_id": "offline-test", "client_secret": "unused",
    "token_endpoint": "https://invalid.example/token", "api_base_url": "https://invalid.example",
    "trust_tier": "declared", "key_algorithm": "ecdsa-p256", "private_key_pem": private_key_pem,
    "identity_certificate_chain_pem": identity_chain_pem, "device_certificate_chains": device_chains,
  }))
  monkeypatch.setenv("APPDATA", str(tmp_path))
  monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))


def test_a_wrong_device_type_guess_falls_back_to_the_chain_whose_key_signed(tmp_path, monkeypatch):
  _, signing_private_key_pem, signing_certificate_pem = _new_key_and_self_signed_certificate_pem("signing key")
  _, _, other_certificate_pem = _new_key_and_self_signed_certificate_pem("other device")
  _write_credentials(tmp_path, monkeypatch, signing_private_key_pem, signing_certificate_pem,
                     {"other-device": {"device_type": "software", "certificate_chain_pem": other_certificate_pem}})
  from oneid.attestation import prepare_direct_hardware_attestation
  from hw_attest_verify.mode1 import verify_hardware_attestation
  proof = prepare_direct_hardware_attestation(dict(_HEADERS), b"body\r\n")
  result = verify_hardware_attestation(proof.hardware_attestation_header_value, dict(_HEADERS), b"body\r\n",
                                       allow_self_signed=True)
  assert result.is_valid, result.failure_reasons


def test_no_stored_chain_for_the_signing_key_fails_closed(tmp_path, monkeypatch):
  _, signing_private_key_pem, _ = _new_key_and_self_signed_certificate_pem("signing key")
  _, _, other_certificate_pem = _new_key_and_self_signed_certificate_pem("other device")
  _write_credentials(tmp_path, monkeypatch, signing_private_key_pem, other_certificate_pem, {})
  from oneid.attestation import prepare_direct_hardware_attestation
  with pytest.raises(ValueError, match="No stored certificate chain matches"):
    prepare_direct_hardware_attestation(dict(_HEADERS), b"body\r\n")


def test_a_binding_for_another_key_is_refused(tmp_path, monkeypatch):
  _, signing_private_key_pem, signing_certificate_pem = _new_key_and_self_signed_certificate_pem("signing key")
  other_key, _, _ = _new_key_and_self_signed_certificate_pem("other device")
  _write_credentials(tmp_path, monkeypatch, signing_private_key_pem, signing_certificate_pem, {})
  other_numbers = other_key.public_key().public_numbers()

  def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

  binding_payload = {"sub": "id-abcde-fghij-klmno-pqrst", "cnf": {"jwk": {
    "kty": "EC", "crv": "P-256", "x": b64url(other_numbers.x.to_bytes(32, "big")), "y": b64url(other_numbers.y.to_bytes(32, "big"))}}}
  binding_jws_for_other_key = "e30." + b64url(json.dumps(binding_payload).encode()) + ".c2ln"
  from oneid.attestation import prepare_direct_hardware_attestation
  with pytest.raises(ValueError, match="different key"):
    prepare_direct_hardware_attestation(dict(_HEADERS), b"body\r\n",
                                        agent_identity_urn="urn:aid:global:id-abcde-fghij-klmno-pqrst",
                                        binding_jws=binding_jws_for_other_key)
