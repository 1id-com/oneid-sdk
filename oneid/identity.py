"""
Identity and Token data models for the 1id.com SDK.

These dataclasses represent the agent's enrolled identity and
OAuth2 tokens. They are returned by enroll(), whoami(), and
get_token() respectively.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class TrustTier(str, Enum):
  """Trust tiers assigned by 1id.com based on hardware attestation.

  Ordered from highest to lowest Sybil resistance:
  - sovereign: Non-portable hardware (TPM), manufacturer-attested, current cert
  - sovereign_portable: Portable hardware (YubiKey/Nitrokey), manufacturer-attested
  - legacy: Was sovereign/sovereign-portable, but manufacturer cert expired
  - virtual: Virtual TPM (VMware/Hyper-V), hypervisor-attested
  - enclave: Apple Secure Enclave, TOFU (no attestation PKI)
  - declared: Software-only, no hardware proof, self-asserted
  """
  SOVEREIGN = "sovereign"
  SOVEREIGN_PORTABLE = "sovereign-portable"
  LEGACY = "legacy"
  VIRTUAL = "virtual"
  ENCLAVE = "enclave"
  DECLARED = "declared"


class KeyAlgorithm(str, Enum):
  """Supported key algorithms for declared-tier software keys.

  Agents can choose their preferred algorithm, similar to how SSH
  supports multiple key types. Default is Ed25519 (strongest, fastest).

  For TPM tiers, the key algorithm is determined by the TPM hardware
  (typically RSA-2048 for EK, RSA-2048 or ECC P-256 for AK).
  """
  ED25519 = "ed25519"
  ECDSA_P256 = "ecdsa-p256"
  ECDSA_P384 = "ecdsa-p384"
  RSA_2048 = "rsa-2048"
  RSA_4096 = "rsa-4096"


# -- The default key algorithm for declared-tier enrollment --
# Ed25519: 128-bit security, smallest keys, fastest signatures,
# widely supported (OpenSSH, TLS 1.3, libsodium, NaCl).
DEFAULT_KEY_ALGORITHM = KeyAlgorithm.ED25519


class HSMType(str, Enum):
  """Types of hardware security modules supported by 1id.com."""
  TPM = "tpm"
  YUBIKEY = "yubikey"
  NITROKEY = "nitrokey"
  FEITIAN = "feitian"
  SOLOKEYS = "solokeys"
  SECURE_ENCLAVE = "secure_enclave"
  SOFTWARE = "software"


@dataclass(frozen=True)
class Identity:
  """Represents an enrolled 1id.com agent identity.

  Returned by oneid.enroll() and oneid.whoami().
  All fields are read-only (frozen dataclass).

  Attributes:
      internal_id: Permanent unique identifier (e.g., '1id_a7b3c9d2').
                   This is the 'sub' claim in JWTs, the database primary key.
                   Format: '1id_' prefix + 8 characters of base36 (a-z, 0-9).
                   NEVER changes, NEVER reused even after revocation.
      handle: Display name (e.g., '@clawdia' or '@1id_a7b3c9d2').
              If no vanity handle is registered, this is '@' + first 8 chars of internal_id.
              Vanity handles are display-only; internal_id is the real identity.
      trust_tier: The trust level assigned based on hardware attestation.
      hsm_type: Type of HSM used for enrollment, or None for declared tier.
      hsm_manufacturer: Manufacturer code (e.g., 'INTC', 'Yubico'), or None.
      enrolled_at: When this identity was first created.
      device_count: Number of HSMs currently linked to this identity.
      key_algorithm: The key algorithm used for this identity's signing key.
  """
  internal_id: str
  handle: str
  trust_tier: TrustTier
  hsm_type: HSMType | None
  hsm_manufacturer: str | None
  enrolled_at: datetime
  device_count: int
  key_algorithm: KeyAlgorithm

  def __str__(self) -> str:
    return f"{self.handle} (tier: {self.trust_tier.value}, id: {self.internal_id})"


@dataclass(frozen=True)
class Token:
  """Represents an OAuth2 access token from 1id.com / Keycloak.

  Returned by oneid.get_token(). The access_token is a signed JWT
  containing the agent's identity claims (sub, handle, trust_tier, etc.).

  Attributes:
      access_token: The JWT access token string (Bearer token).
      token_type: Always 'Bearer'.
      expires_at: When this token expires (UTC).
      refresh_token: Refresh token for obtaining new access tokens, or None.
  """
  access_token: str
  token_type: str
  expires_at: datetime
  refresh_token: str | None

  @property
  def this_token_has_not_yet_expired(self) -> bool:
    """Check whether this token is still valid based on its expiry time.

    Returns True if the token's expiry time is in the future.
    Does NOT verify the JWT signature or check revocation.
    """
    from datetime import timezone as _tz
    now_utc = datetime.now(_tz.utc)
    # Handle both naive and aware datetimes for expires_at
    if self.expires_at.tzinfo is None:
      return datetime.utcnow() < self.expires_at
    return now_utc < self.expires_at

  @property
  def authorization_header_value(self) -> str:
    """Format this token for use in an HTTP Authorization header.

    Returns:
        String in the format 'Bearer <access_token>'.
    """
    return f"{self.token_type} {self.access_token}"
