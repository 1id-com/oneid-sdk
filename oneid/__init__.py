from __future__ import annotations

"""
1id.com SDK -- Hardware-anchored identity for AI agents.

Quick start:

    import oneid

    # Enroll at declared tier (no HSM, always works)
    identity = oneid.enroll(request_tier="declared")
    print(f"Enrolled as {identity.handle}")

    # Get an OAuth2 token for authentication
    token = oneid.get_token()
    print(f"Bearer {token.access_token}")

    # Check current identity
    identity = oneid.whoami()

Trust tiers (request_tier parameter):
    'sovereign'          -- TPM hardware, manufacturer-attested
    'sovereign-portable' -- YubiKey/Nitrokey, manufacturer-attested
    'declared'           -- Software keys, no hardware proof

CRITICAL: request_tier is a REQUIREMENT, not a preference.
You get exactly what you ask for, or an exception. No fallbacks.
"""

from .auth import clear_cached_token, get_token
from .credentials import credentials_exist, load_credentials
from .enroll import enroll
from .exceptions import (
  AlreadyEnrolledError,
  AuthenticationError,
  BinaryNotFoundError,
  EnrollmentError,
  HandleInvalidError,
  HandleRetiredError,
  HandleTakenError,
  HSMAccessError,
  NetworkError,
  NoHSMError,
  NotEnrolledError,
  OneIDError,
  UACDeniedError,
)
from .identity import (
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  Identity,
  KeyAlgorithm,
  Token,
  TrustTier,
)
from .keys import sign_challenge_with_private_key
from .attestation import prepare_attestation, AttestationProof
from . import mailpal
from ._version import __version__


def whoami() -> Identity:
  """Check the current enrolled identity.

  Reads the local credentials file and returns the identity information
  stored during enrollment. Does NOT make a network request.

  For a network-verified identity check, use the server API directly.

  Returns:
      Identity: The enrolled identity.

  Raises:
      NotEnrolledError: If no credentials exist (call enroll() first).
  """
  from datetime import datetime, timezone

  creds = load_credentials()

  try:
    trust_tier = TrustTier(creds.trust_tier)
  except ValueError:
    trust_tier = TrustTier.DECLARED

  try:
    key_algorithm = KeyAlgorithm(creds.key_algorithm)
  except ValueError:
    key_algorithm = DEFAULT_KEY_ALGORITHM

  try:
    enrolled_at = datetime.fromisoformat(creds.enrolled_at.replace("Z", "+00:00")) if creds.enrolled_at else datetime.now(timezone.utc)
  except (ValueError, AttributeError):
    enrolled_at = datetime.now(timezone.utc)

  internal_id = creds.client_id
  handle = f"@{internal_id}" if not internal_id.startswith("@") else internal_id

  # Determine HSM type from credentials
  hsm_type: HSMType | None = None
  if creds.private_key_pem is not None:
    hsm_type = HSMType.SOFTWARE
  elif creds.hsm_key_reference is not None:
    hsm_type = HSMType.TPM  # Could also be YubiKey, but we'd need more info

  return Identity(
    internal_id=internal_id,
    handle=handle,
    trust_tier=trust_tier,
    hsm_type=hsm_type,
    hsm_manufacturer=None,
    enrolled_at=enrolled_at,
    device_count=1 if creds.hsm_key_reference else 0,
    key_algorithm=key_algorithm,
  )


def refresh() -> None:
  """Force-refresh the cached OAuth2 token.

  Discards the in-memory cached token and fetches a new one
  on the next get_token() call.
  """
  clear_cached_token()


# -- Public API --
__all__ = [
  # Core functions
  "enroll",
  "get_token",
  "whoami",
  "refresh",
  "credentials_exist",
  "sign_challenge_with_private_key",
  "prepare_attestation",
  "AttestationProof",
  "mailpal",
  # Data types
  "Identity",
  "Token",
  "TrustTier",
  "KeyAlgorithm",
  "HSMType",
  "DEFAULT_KEY_ALGORITHM",
  # Exceptions (all importable from oneid directly)
  "OneIDError",
  "EnrollmentError",
  "NoHSMError",
  "UACDeniedError",
  "HSMAccessError",
  "AlreadyEnrolledError",
  "HandleTakenError",
  "HandleInvalidError",
  "HandleRetiredError",
  "AuthenticationError",
  "NetworkError",
  "NotEnrolledError",
  "BinaryNotFoundError",
  # Version
  "__version__",
]
