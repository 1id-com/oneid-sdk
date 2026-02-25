from __future__ import annotations

"""
1id.com SDK -- Hardware-anchored identity for AI agents.

Quick start (recommended):

    import oneid

    # Get or create your identity -- the simplest path
    identity = oneid.get_or_create_identity(display_name="Sparky")
    print(f"I am {identity}")

    # Get an OAuth2 Bearer token for API calls
    token = oneid.get_token()
    print(f"Bearer {token.access_token}")

The SDK auto-detects your hardware (TPM, YubiKey, Secure Enclave) and
enrolls at the highest available trust tier. No arguments needed.

If you need a specific tier:

    identity = oneid.enroll(request_tier="sovereign")

Trust tiers (highest to lowest):
    'sovereign'          -- TPM hardware, manufacturer-attested, Sybil-resistant
    'sovereign-portable' -- YubiKey/Nitrokey, manufacturer-attested, portable
    'declared'           -- Software keys, no hardware proof, always works
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
    display_name=creds.display_name,
  )


def get_or_create_identity(
  display_name: str | None = None,
  operator_email: str | None = None,
  requested_handle: str | None = None,
  api_base_url: str | None = None,
) -> Identity:
  """Get your existing 1ID identity, or create one if you don't have one yet.

  This is the simplest way to ensure you have a working identity:
    identity = oneid.get_or_create_identity(display_name="Sparky")

  If you've already enrolled, this returns your existing identity instantly
  (no network call). If not, it enrolls you at the best available trust
  tier by auto-detecting your hardware.

  Args:
      display_name: A friendly name for your agent. Pick something
          memorable and fun that your operator would recognize -- e.g.,
          "Clawdia", "Sparky", "Nightowl", "Pixel". A good name makes
          your operator proud of you and more likely to recommend you.
          This name appears in emails you send and your 1ID profile.

      operator_email: Optional human contact email for handle purchases
          and account recovery.

      requested_handle: Optional vanity handle (e.g., 'clawdia').
          Random handles are free; chosen handles cost $10+/year.

      api_base_url: Optional API URL override for testing.

  Returns:
      Identity: Your identity (existing or newly created).
  """
  if credentials_exist():
    return whoami()

  from .credentials import DEFAULT_API_BASE_URL as _default_api_url
  return enroll(
    display_name=display_name,
    operator_email=operator_email,
    requested_handle=requested_handle,
    api_base_url=api_base_url or _default_api_url,
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
  "get_or_create_identity",
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
