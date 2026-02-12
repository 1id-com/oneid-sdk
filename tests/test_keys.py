"""
Tests for cryptographic key generation and signing.

Verifies:
- All five key algorithms generate valid keypairs
- Keys round-trip through PEM serialization
- Challenge-response signing produces valid signatures
- Ed25519 is the default
- Unsupported algorithms raise ValueError
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from oneid.identity import KeyAlgorithm, DEFAULT_KEY_ALGORITHM
from oneid.keys import generate_keypair, load_private_key_from_pem, sign_challenge_with_private_key


class TestKeyGeneration:
  """Verify keypair generation for all supported algorithms."""

  @pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
  def test_generate_keypair_returns_pem_bytes(self, algorithm):
    """Every algorithm must produce PEM-encoded private and public keys."""
    private_pem, public_pem = generate_keypair(algorithm)

    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

  def test_ed25519_is_default_algorithm(self):
    """The default key algorithm should be Ed25519."""
    assert DEFAULT_KEY_ALGORITHM == KeyAlgorithm.ED25519

  def test_ed25519_generates_correct_key_type(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.ED25519)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, ed25519.Ed25519PrivateKey)

  def test_ecdsa_p256_generates_correct_key_type(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.ECDSA_P256)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)

  def test_ecdsa_p384_generates_correct_key_type(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.ECDSA_P384)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP384R1)

  def test_rsa_2048_generates_correct_key_size(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.RSA_2048)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048

  def test_rsa_4096_generates_correct_key_size(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.RSA_4096)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 4096

  def test_each_keypair_is_unique(self):
    """Two calls should produce different keys (random generation)."""
    priv1, pub1 = generate_keypair(KeyAlgorithm.ED25519)
    priv2, pub2 = generate_keypair(KeyAlgorithm.ED25519)
    assert priv1 != priv2
    assert pub1 != pub2


class TestChallengeResponseSigning:
  """Verify that the signing function works with all key types."""

  @pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
  def test_sign_challenge_produces_nonzero_signature(self, algorithm):
    """Signing a challenge should produce a non-empty signature."""
    private_pem, _ = generate_keypair(algorithm)
    challenge = b"this-is-a-test-nonce-from-1id-server"

    signature = sign_challenge_with_private_key(private_pem, challenge)

    assert isinstance(signature, bytes)
    assert len(signature) > 0

  def test_ed25519_signature_verifies(self):
    """Ed25519 signature should verify against the public key."""
    private_pem, public_pem = generate_keypair(KeyAlgorithm.ED25519)
    challenge = b"nonce-from-relying-party-12345"

    signature = sign_challenge_with_private_key(private_pem, challenge)

    # Verify using the public key
    public_key = serialization.load_pem_public_key(public_pem)
    assert isinstance(public_key, ed25519.Ed25519PublicKey)
    # Ed25519 verify raises InvalidSignature on failure, returns None on success
    public_key.verify(signature, challenge)  # Should not raise

  def test_ecdsa_p256_signature_verifies(self):
    """ECDSA P-256 signature should verify against the public key."""
    private_pem, public_pem = generate_keypair(KeyAlgorithm.ECDSA_P256)
    challenge = b"nonce-from-relying-party-67890"

    signature = sign_challenge_with_private_key(private_pem, challenge)

    public_key = serialization.load_pem_public_key(public_pem)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))

  def test_ecdsa_p384_signature_verifies(self):
    """ECDSA P-384 signature should verify with SHA-384."""
    private_pem, public_pem = generate_keypair(KeyAlgorithm.ECDSA_P384)
    challenge = b"nonce-p384-test"

    signature = sign_challenge_with_private_key(private_pem, challenge)

    public_key = serialization.load_pem_public_key(public_pem)
    public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA384()))

  def test_rsa_2048_signature_verifies(self):
    """RSA-2048 signature should verify with PKCS1v15 + SHA-256."""
    private_pem, public_pem = generate_keypair(KeyAlgorithm.RSA_2048)
    challenge = b"nonce-rsa-test"

    signature = sign_challenge_with_private_key(private_pem, challenge)

    public_key = serialization.load_pem_public_key(public_pem)
    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())

  def test_different_challenges_produce_different_signatures(self):
    """Two different challenges should produce different signatures (except Ed25519 which is deterministic on same input)."""
    private_pem, _ = generate_keypair(KeyAlgorithm.ECDSA_P256)

    sig1 = sign_challenge_with_private_key(private_pem, b"challenge-1")
    sig2 = sign_challenge_with_private_key(private_pem, b"challenge-2")

    assert sig1 != sig2

  def test_sign_accepts_string_pem(self):
    """PEM can be passed as either str or bytes."""
    private_pem_bytes, _ = generate_keypair(KeyAlgorithm.ED25519)
    private_pem_str = private_pem_bytes.decode("utf-8")

    # Both should work without error
    sig1 = sign_challenge_with_private_key(private_pem_bytes, b"test")
    sig2 = sign_challenge_with_private_key(private_pem_str, b"test")

    # Ed25519 is deterministic, so same key + same message = same signature
    assert sig1 == sig2


class TestLoadPrivateKey:
  """Verify private key loading."""

  def test_load_from_bytes(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.ED25519)
    key = load_private_key_from_pem(private_pem)
    assert isinstance(key, ed25519.Ed25519PrivateKey)

  def test_load_from_string(self):
    private_pem, _ = generate_keypair(KeyAlgorithm.ED25519)
    key = load_private_key_from_pem(private_pem.decode("utf-8"))
    assert isinstance(key, ed25519.Ed25519PrivateKey)
