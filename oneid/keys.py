"""
Cryptographic key generation for the 1id.com SDK.

Supports multiple key algorithms for declared-tier software keys,
similar to how SSH supports multiple key types. Default is Ed25519.

Supported algorithms:
  - Ed25519:     128-bit security, smallest keys, fastest. Default.
  - ECDSA P-256: 128-bit security, widely compatible (NIST curve).
  - ECDSA P-384: 192-bit security, higher security NIST curve.
  - RSA-2048:    112-bit security, legacy compatibility.
  - RSA-4096:    128-bit security, higher security RSA.

For TPM tiers, key generation happens inside the TPM hardware via
the Go binary. This module is only used for declared-tier enrollment.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from .identity import KeyAlgorithm


def generate_keypair(algorithm: KeyAlgorithm = KeyAlgorithm.ED25519) -> tuple[bytes, bytes]:
  """Generate a new keypair for declared-tier enrollment.

  The private key is stored locally in the credentials file. The public
  key is sent to the 1id.com server during enrollment. The private key
  is used later for challenge-response signing by relying parties.

  Args:
      algorithm: Which key algorithm to use. Default: Ed25519.

  Returns:
      Tuple of (private_key_pem_bytes, public_key_pem_bytes).
      Both are PEM-encoded byte strings.

  Raises:
      ValueError: If the algorithm is not supported.
  """
  private_key: PrivateKeyTypes

  if algorithm == KeyAlgorithm.ED25519:
    private_key = ed25519.Ed25519PrivateKey.generate()

  elif algorithm == KeyAlgorithm.ECDSA_P256:
    private_key = ec.generate_private_key(ec.SECP256R1())

  elif algorithm == KeyAlgorithm.ECDSA_P384:
    private_key = ec.generate_private_key(ec.SECP384R1())

  elif algorithm == KeyAlgorithm.RSA_2048:
    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
    )

  elif algorithm == KeyAlgorithm.RSA_4096:
    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=4096,
    )

  else:
    raise ValueError(
      f"Unsupported key algorithm: {algorithm}. "
      f"Supported: {', '.join(a.value for a in KeyAlgorithm)}"
    )

  private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
  )

  public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
  )

  return private_key_pem, public_key_pem


def load_private_key_from_pem(private_key_pem: str | bytes) -> PrivateKeyTypes:
  """Load a private key from PEM-encoded bytes or string.

  Used to reload the signing key from stored credentials for
  challenge-response operations.

  Args:
      private_key_pem: PEM-encoded private key (str or bytes).

  Returns:
      The loaded private key object.
  """
  if isinstance(private_key_pem, str):
    private_key_pem = private_key_pem.encode("utf-8")

  return serialization.load_pem_private_key(private_key_pem, password=None)


def sign_challenge_with_private_key(
  private_key_pem: str | bytes,
  challenge_bytes: bytes,
) -> bytes:
  """Sign a challenge nonce using the stored private key.

  Used for relying-party live re-verification: the relying party
  sends a nonce via 1id.com, the SDK signs it with the agent's
  private key, and 1id.com verifies the signature against the
  stored public key.

  The signing algorithm is determined automatically from the key type:
  - Ed25519: EdDSA (no hash selection needed)
  - ECDSA: SHA-256 (P-256) or SHA-384 (P-384) with ECDSA
  - RSA: SHA-256 with PKCS1v15

  Args:
      private_key_pem: PEM-encoded private key.
      challenge_bytes: The raw bytes of the challenge nonce to sign.

  Returns:
      The signature bytes.
  """
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding, utils

  private_key = load_private_key_from_pem(private_key_pem)

  if isinstance(private_key, ed25519.Ed25519PrivateKey):
    return private_key.sign(challenge_bytes)

  elif isinstance(private_key, ec.EllipticCurvePrivateKey):
    # Determine hash algorithm from curve size
    curve = private_key.curve
    if isinstance(curve, ec.SECP384R1):
      hash_algorithm = hashes.SHA384()
    else:
      hash_algorithm = hashes.SHA256()
    return private_key.sign(challenge_bytes, ec.ECDSA(hash_algorithm))

  elif isinstance(private_key, rsa.RSAPrivateKey):
    return private_key.sign(
      challenge_bytes,
      padding.PKCS1v15(),
      hashes.SHA256(),
    )

  else:
    raise ValueError(f"Unsupported key type for signing: {type(private_key)}")
