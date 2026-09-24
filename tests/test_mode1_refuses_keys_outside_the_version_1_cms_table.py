"""AUD-F22/F60: Version 1 Mode 1 allows only RS256 / ES256 / PS256, so a
declared identity with an Ed25519 or P-384 key must get a clear error instead
of a Hardware-Attestation header a conforming verifier has to reject. The
default declared key (ECDSA P-256) signs normally. Offline: credentials come
from a temporary directory; nothing touches the network."""

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from oneid.keys import generate_keypair
from oneid.identity import KeyAlgorithm

_HEADERS = {"From": "a@example.com", "To": "b@example.com", "Subject": "s",
            "Date": "Thu, 24 Sep 2026 12:00:00 +0000", "Message-ID": "<m@example.com>"}


def _write_declared_credentials(tmp_path, monkeypatch, key_algorithm):
  private_key_pem, _ = generate_keypair(key_algorithm)
  from cryptography.hazmat.primitives.serialization import load_pem_private_key
  private_key = load_pem_private_key(private_key_pem if isinstance(private_key_pem, bytes) else private_key_pem.encode(), None)
  name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "declared test")])
  now = datetime.now(timezone.utc)
  signing_hash = None if key_algorithm == KeyAlgorithm.ED25519 else hashes.SHA256()
  certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                 .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                 .sign(private_key, signing_hash))
  credentials_directory = tmp_path / "oneid"
  credentials_directory.mkdir()
  (credentials_directory / "credentials.json").write_text(json.dumps({
    "client_id": "offline-test", "client_secret": "unused",
    "token_endpoint": "https://invalid.example/token", "api_base_url": "https://invalid.example",
    "trust_tier": "declared", "key_algorithm": key_algorithm.value,
    "private_key_pem": private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem,
    "identity_certificate_chain_pem": certificate.public_bytes(Encoding.PEM).decode(),
  }))
  monkeypatch.setenv("APPDATA", str(tmp_path))
  monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))


@pytest.mark.parametrize("key_algorithm", [KeyAlgorithm.ED25519, KeyAlgorithm.ECDSA_P384])
def test_mode1_refuses_a_declared_key_outside_the_version_1_cms_table(tmp_path, monkeypatch, key_algorithm):
  _write_declared_credentials(tmp_path, monkeypatch, key_algorithm)
  from oneid.attestation import prepare_direct_hardware_attestation
  with pytest.raises(ValueError, match="cannot sign a Version 1 Mode 1"):
    prepare_direct_hardware_attestation(dict(_HEADERS), b"body\r\n")


def test_mode1_signs_with_the_default_p256_declared_key(tmp_path, monkeypatch):
  _write_declared_credentials(tmp_path, monkeypatch, KeyAlgorithm.ECDSA_P256)
  from oneid.attestation import prepare_direct_hardware_attestation
  proof = prepare_direct_hardware_attestation(dict(_HEADERS), b"body\r\n")
  assert "alg=ES256" in proof.hardware_attestation_header_value
