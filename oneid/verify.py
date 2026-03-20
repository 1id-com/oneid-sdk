"""
1id Peer Identity Verification

Assembles and validates proof bundles for offline, privacy-preserving
agent-to-agent identity verification.

Protocol:
  1. Verifier generates a random nonce (32+ bytes)
  2. Agent calls sign_challenge(nonce_bytes) -> IdentityProofBundle
  3. Verifier calls verify_peer_identity(nonce_bytes, proof_bundle)
     -> VerifiedPeerIdentity

No secrets are exchanged. The verifier never contacts 1ID. Once the
trust root is cached locally, verification is entirely offline.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from .credentials import StoredCredentials, load_credentials
from .exceptions import NotEnrolledError, OneIDError
from .trust_roots import get_trust_roots

logger = logging.getLogger("oneid.verify")

ONEID_OID_TRUST_TIER = x509.ObjectIdentifier("1.3.6.1.4.1.59999.1.1")
ONEID_OID_ENROLLED_AT = x509.ObjectIdentifier("1.3.6.1.4.1.59999.1.2")
ONEID_OID_HARDWARE_LOCKED = x509.ObjectIdentifier("1.3.6.1.4.1.59999.1.3")


class PeerVerificationError(OneIDError):
  """Raised when a proof bundle fails validation."""


class CertificateChainValidationError(PeerVerificationError):
  """Certificate chain does not terminate at a trusted 1ID root."""


class SignatureVerificationError(PeerVerificationError):
  """Nonce signature does not match the leaf certificate's public key."""


class MissingIdentityCertificateError(PeerVerificationError):
  """Agent has no identity certificate chain stored (re-enroll or recover to obtain one)."""


@dataclass
class IdentityProofBundle:
  """Assembled by the prover, sent to the verifier."""
  signature_bytes: bytes
  certificate_chain_pem: str
  agent_id: str
  trust_tier: str
  algorithm: str

  def to_dict(self) -> dict:
    return {
      "signature_b64": base64.b64encode(self.signature_bytes).decode("ascii"),
      "certificate_chain_pem": self.certificate_chain_pem,
      "agent_id": self.agent_id,
      "trust_tier": self.trust_tier,
      "algorithm": self.algorithm,
    }

  @classmethod
  def from_dict(cls, data: dict) -> IdentityProofBundle:
    return cls(
      signature_bytes=base64.b64decode(data["signature_b64"]),
      certificate_chain_pem=data["certificate_chain_pem"],
      agent_id=data["agent_id"],
      trust_tier=data["trust_tier"],
      algorithm=data["algorithm"],
    )


@dataclass
class VerifiedPeerIdentity:
  """Returned by the verifier after successful validation."""
  agent_id: str
  trust_tier: str
  enrolled_at: str
  hardware_locked: bool
  chain_valid: bool


def _determine_signing_algorithm_name(creds: StoredCredentials) -> str:
  """Map credential key algorithm to a compact algorithm identifier."""
  algo = (creds.key_algorithm or "").lower()
  if "ed25519" in algo:
    return "EdDSA"
  if "p-384" in algo or "p384" in algo or "ecdsa-p384" in algo:
    return "ES384"
  if "p-256" in algo or "p256" in algo or "ecdsa" in algo or "piv" in algo:
    return "ES256"
  if "rsa-4096" in algo or "rsa4096" in algo:
    return "RS256"
  if "rsa" in algo or "tpm-ak" in algo:
    return "RS256"
  return "RS256"


def _sign_with_software_key(nonce_bytes: bytes, private_key_pem: str) -> bytes:
  """Sign using the locally stored software private key."""
  from .keys import sign_challenge_with_private_key
  return sign_challenge_with_private_key(private_key_pem, nonce_bytes)


def _sign_with_tpm(nonce_bytes: bytes, ak_handle: str) -> tuple[bytes, str]:
  """Sign using the TPM AK via the Go binary. Returns (signature_bytes, algorithm)."""
  from .helper import sign_challenge_with_tpm
  nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
  result = sign_challenge_with_tpm(nonce_b64, ak_handle)
  signature_b64 = result.get("signature_b64", "")
  algorithm = result.get("algorithm", "RSASSA-SHA256")
  algo_name = "RS256" if "RSA" in algorithm.upper() else algorithm
  return base64.b64decode(signature_b64), algo_name


def _sign_with_piv(nonce_bytes: bytes) -> tuple[bytes, str]:
  """Sign using the YubiKey PIV key via the Go binary. Returns (signature_bytes, algorithm)."""
  from .helper import sign_challenge_with_piv
  nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
  result = sign_challenge_with_piv(nonce_b64)
  signature_b64 = result.get("signature_b64", "")
  algorithm = result.get("algorithm", "ECDSA-SHA256")
  algo_name = "ES256" if "ECDSA" in algorithm.upper() else algorithm
  return base64.b64decode(signature_b64), algo_name


def sign_challenge(nonce_bytes: bytes) -> IdentityProofBundle:
  """Sign a verifier-provided nonce and assemble a proof bundle.

  Dispatches to the appropriate signing mechanism based on trust tier:
    - sovereign (TPM): delegates to oneid-enroll sign
    - portable (YubiKey): delegates to oneid-enroll piv-sign
    - declared (software): signs with local private key

  The proof bundle contains the signature, the full certificate chain
  (leaf -> intermediate -> root), the agent_id, trust tier, and algorithm.

  Args:
    nonce_bytes: Raw bytes of the verifier-generated nonce.

  Returns:
    IdentityProofBundle ready to send to the verifier.

  Raises:
    NotEnrolledError: If no credentials exist.
    MissingIdentityCertificateError: If no identity certificate chain is stored.
    HSMAccessError: If hardware signing fails.
  """
  creds = load_credentials()

  if not creds.identity_certificate_chain_pem:
    raise MissingIdentityCertificateError(
      "No identity certificate chain found in credentials. "
      "This agent was enrolled before certificate issuance was available. "
      "Re-enroll or recover your identity to obtain a certificate."
    )

  trust_tier = creds.trust_tier or "declared"
  agent_id = creds.client_id

  if trust_tier in ("sovereign", "virtual") or creds.key_algorithm == "tpm-ak":
    ak_handle = creds.hsm_key_reference or ""
    signature_bytes, algorithm = _sign_with_tpm(nonce_bytes, ak_handle)

  elif trust_tier == "portable" or creds.hsm_key_reference == "piv-slot-9a":
    signature_bytes, algorithm = _sign_with_piv(nonce_bytes)

  elif creds.private_key_pem:
    signature_bytes = _sign_with_software_key(nonce_bytes, creds.private_key_pem)
    algorithm = _determine_signing_algorithm_name(creds)

  else:
    raise NotEnrolledError(
      "Cannot sign challenge: no signing key available. "
      "Credentials exist but contain neither a private key nor an HSM reference."
    )

  return IdentityProofBundle(
    signature_bytes=signature_bytes,
    certificate_chain_pem=creds.identity_certificate_chain_pem,
    agent_id=agent_id,
    trust_tier=trust_tier,
    algorithm=algorithm,
  )


def _parse_certificate_chain_from_pem(pem_bundle: str) -> list[x509.Certificate]:
  """Split a PEM bundle into individual certificates, preserving order (leaf first)."""
  certificates = []
  for block in pem_bundle.split("-----END CERTIFICATE-----"):
    block = block.strip()
    if block and "-----BEGIN CERTIFICATE-----" in block:
      try:
        full_pem = block + "\n-----END CERTIFICATE-----\n"
        cert = x509.load_pem_x509_certificate(full_pem.encode("utf-8"))
        certificates.append(cert)
      except Exception:
        continue
  return certificates


def _extract_custom_extension_value(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bytes | None:
  """Extract raw bytes from a custom (unrecognized) extension by OID."""
  for ext in cert.extensions:
    if ext.oid == oid:
      if isinstance(ext.value, x509.UnrecognizedExtension):
        return ext.value.value
  return None


def _verify_certificate_chain_to_trusted_root(
  chain: list[x509.Certificate],
  trusted_roots: list[x509.Certificate],
) -> bool:
  """Validate that each certificate is signed by the next, terminating at a trusted root.

  Chain order: [leaf, intermediate, ..., root].
  The root must match one of the trusted_roots by subject key identifier or subject name.
  """
  if not chain:
    raise CertificateChainValidationError("Certificate chain is empty")

  trusted_root_subjects = {root.subject for root in trusted_roots}
  trusted_root_public_key_bytes = set()
  for root in trusted_roots:
    try:
      pub_bytes = root.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
      )
      trusted_root_public_key_bytes.add(pub_bytes)
    except Exception:
      pass

  for i in range(len(chain) - 1):
    child_cert = chain[i]
    parent_cert = chain[i + 1]

    try:
      parent_public_key = parent_cert.public_key()
      if isinstance(parent_public_key, rsa.RSAPublicKey):
        parent_public_key.verify(
          child_cert.signature,
          child_cert.tbs_certificate_bytes,
          padding.PKCS1v15(),
          child_cert.signature_hash_algorithm,
        )
      elif isinstance(parent_public_key, ec.EllipticCurvePublicKey):
        parent_public_key.verify(
          child_cert.signature,
          child_cert.tbs_certificate_bytes,
          ec.ECDSA(child_cert.signature_hash_algorithm),
        )
      elif isinstance(parent_public_key, ed25519.Ed25519PublicKey):
        parent_public_key.verify(
          child_cert.signature,
          child_cert.tbs_certificate_bytes,
        )
      else:
        raise CertificateChainValidationError(
          f"Unsupported public key type in chain: {type(parent_public_key)}"
        )
    except InvalidSignature:
      raise CertificateChainValidationError(
        f"Certificate at position {i} is not signed by certificate at position {i+1}"
      )

  chain_root = chain[-1]
  chain_root_pub_bytes = chain_root.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
  )

  root_is_trusted = (
    chain_root.subject in trusted_root_subjects
    or chain_root_pub_bytes in trusted_root_public_key_bytes
  )

  if not root_is_trusted:
    raise CertificateChainValidationError(
      f"Chain root '{chain_root.subject}' is not in the set of trusted 1ID roots"
    )

  return True


def _verify_nonce_signature(
  nonce_bytes: bytes,
  signature_bytes: bytes,
  leaf_cert: x509.Certificate,
  algorithm_hint: str,
) -> bool:
  """Verify the nonce signature against the leaf certificate's public key."""
  public_key = leaf_cert.public_key()

  try:
    if isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(
        signature_bytes,
        nonce_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
      )

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
      curve = public_key.curve
      if isinstance(curve, ec.SECP384R1):
        hash_algo = hashes.SHA384()
      else:
        hash_algo = hashes.SHA256()
      public_key.verify(signature_bytes, nonce_bytes, ec.ECDSA(hash_algo))

    elif isinstance(public_key, ed25519.Ed25519PublicKey):
      public_key.verify(signature_bytes, nonce_bytes)

    else:
      raise SignatureVerificationError(f"Unsupported public key type: {type(public_key)}")

  except InvalidSignature:
    raise SignatureVerificationError(
      "Nonce signature does not match the leaf certificate's public key"
    )

  return True


def verify_peer_identity(
  nonce_bytes: bytes,
  proof_bundle: IdentityProofBundle | dict,
  api_base_url: str | None = None,
) -> VerifiedPeerIdentity:
  """Validate another agent's proof bundle. Entirely offline after first trust root fetch.

  Steps:
    1. Parse the certificate chain from the proof bundle
    2. Validate the chain (each cert signed by its parent)
    3. Verify the chain terminates at a locally cached 1ID root
    4. Verify the nonce signature against the leaf certificate's public key
    5. Extract identity claims (agent_id, trust_tier, enrolled_at) from the leaf cert

  Args:
    nonce_bytes: The original nonce bytes that the prover was asked to sign.
    proof_bundle: The IdentityProofBundle from the prover (or dict from to_dict()).
    api_base_url: Override for trust root server URL (only used on first call
                  if no local cache exists).

  Returns:
    VerifiedPeerIdentity with the verified agent_id, trust_tier, etc.

  Raises:
    CertificateChainValidationError: If chain validation fails.
    SignatureVerificationError: If the nonce signature is invalid.
    PeerVerificationError: For other verification failures.
  """
  if isinstance(proof_bundle, dict):
    proof_bundle = IdentityProofBundle.from_dict(proof_bundle)

  chain = _parse_certificate_chain_from_pem(proof_bundle.certificate_chain_pem)
  if not chain:
    raise CertificateChainValidationError("Proof bundle contains no parseable certificates")

  trusted_roots = get_trust_roots(api_base_url)
  _verify_certificate_chain_to_trusted_root(chain, trusted_roots)

  leaf_cert = chain[0]

  now = datetime.now(timezone.utc)
  if leaf_cert.not_valid_before_utc > now:
    raise CertificateChainValidationError(
      f"Leaf certificate is not yet valid (not_before: {leaf_cert.not_valid_before_utc})"
    )
  if leaf_cert.not_valid_after_utc < now:
    raise CertificateChainValidationError(
      f"Leaf certificate has expired (not_after: {leaf_cert.not_valid_after_utc})"
    )

  _verify_nonce_signature(
    nonce_bytes,
    proof_bundle.signature_bytes,
    leaf_cert,
    proof_bundle.algorithm,
  )

  trust_tier_bytes = _extract_custom_extension_value(leaf_cert, ONEID_OID_TRUST_TIER)
  enrolled_at_bytes = _extract_custom_extension_value(leaf_cert, ONEID_OID_ENROLLED_AT)
  hardware_locked_bytes = _extract_custom_extension_value(leaf_cert, ONEID_OID_HARDWARE_LOCKED)

  verified_trust_tier = trust_tier_bytes.decode("utf-8") if trust_tier_bytes else proof_bundle.trust_tier
  verified_enrolled_at = enrolled_at_bytes.decode("utf-8") if enrolled_at_bytes else ""
  verified_hardware_locked = (hardware_locked_bytes == b"\x01") if hardware_locked_bytes else False

  verified_agent_id = proof_bundle.agent_id
  try:
    san_ext = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    for uri in uris:
<<<<<<< HEAD
      if uri.startswith("urn:oneid:agent:"):
        verified_agent_id = uri.replace("urn:oneid:agent:", "")
=======
      if uri.startswith("urn:aid:"):
        last_colon_position = uri.rfind(":")
        if last_colon_position > len("urn:aid:"):
          verified_agent_id = uri[last_colon_position + 1:]
>>>>>>> b9853a2de3341111bf626d58cedbe42b087a1417
        break
  except x509.ExtensionNotFound:
    pass

  logger.info(
    "Peer identity verified: agent=%s, tier=%s, enrolled=%s",
    verified_agent_id, verified_trust_tier, verified_enrolled_at,
  )

  return VerifiedPeerIdentity(
    agent_id=verified_agent_id,
    trust_tier=verified_trust_tier,
    enrolled_at=verified_enrolled_at,
    hardware_locked=verified_hardware_locked,
    chain_valid=True,
  )
