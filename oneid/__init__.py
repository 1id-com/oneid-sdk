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

Trust tiers (highest to lowest, RFC Section 3):
    'sovereign' -- Discrete/firmware TPM, manufacturer CA chain, Sybil-resistant
    'portable'  -- YubiKey/Nitrokey/Feitian PIV, manufacturer-attested, portable
    'virtual'   -- Hypervisor vTPM (VMware/Hyper-V/QEMU), hypervisor-attested
    'declared'  -- Software keys, no hardware proof, always works
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
  HardwareDeviceNotPresentError,
  HSMAccessError,
  NetworkError,
  NoHSMError,
  NotEnrolledError,
  OneIDError,
  TPMSetupRequiredError,
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
from .verify import (
  sign_challenge,
  verify_peer_identity,
  IdentityProofBundle,
  VerifiedPeerIdentity,
  PeerVerificationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  MissingIdentityCertificateError,
)
from .trust_roots import refresh_trust_roots, get_trust_roots
from .world import WorldStatus
from . import mailpal
from . import devices
from . import credential_pointers
from .devices import (
  DeviceManagementError,
  DowngradeRejectedError,
  ColocationRequiredError,
  ColocationBindingError,
  ColocationSessionExpiredError,
  ColocationTimingViolationError,
  DeviceAlreadyBoundError,
  LastDeviceBurnRejectedError,
  BurnConfirmationExpiredError,
  HardwareLockedError,
  IdentityAlreadyLockedError,
  DeclaredTierCannotBeLockedError,
  TooManyActiveDevicesForLockError,
  DeviceInfo,
  DeviceListResult,
  DeviceAddResult,
  BurnRequestResult,
  BurnConfirmResult,
  HardwareLockResult,
)
from .credential_pointers import (
  CredentialPointerError,
  ConsentTokenGenerationError,
  PointerNotFoundError as CredentialPointerNotFoundError,
  PointerAlreadyRemovedError as CredentialPointerAlreadyRemovedError,
  ConsentTokenResult,
  CredentialPointerInfo,
  CredentialPointerListResult,
)
from ._version import __version__


def whoami() -> Identity:
  """Check the current enrolled identity.

  .. deprecated:: 0.6.0
      Use ``oneid.get_or_create_identity(get_only=True)`` to recover your
      identity, or ``oneid.status()`` for a full picture including
      connected services and operator guidance.

  Reads the local credentials file and returns the identity information
  stored during enrollment. Does NOT make a network request.

  Returns:
      Identity: The enrolled identity.

  Raises:
      NotEnrolledError: If no credentials exist (call enroll() first).
  """
  import warnings
  warnings.warn(
    "oneid.whoami() is deprecated since v0.6.0. "
    "Use oneid.get_or_create_identity(get_only=True) or oneid.status() instead.",
    DeprecationWarning,
    stacklevel=2,
  )
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
    agent_identity_urn=creds.agent_identity_urn,
    display_name=creds.display_name,
  )


def get_or_create_identity(
  display_name: str | None = None,
  operator_email: str | None = None,
  requested_handle: str | None = None,
  api_base_url: str | None = None,
  get_only: bool = False,
) -> Identity:
  """Get your existing 1ID identity, or create one if you don't have one yet.

  This is the simplest way to ensure you have a working identity:
    identity = oneid.get_or_create_identity(display_name="Sparky")

  If you've already enrolled, this returns your existing identity instantly
  (no network call). If not, it enrolls you at the best available trust
  tier by auto-detecting your hardware.

  Pass get_only=True when you want to recover context without risking
  a new enrollment. This is useful for agents resuming after a restart:
    identity = oneid.get_or_create_identity(get_only=True)

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

      get_only: If True, only return an existing identity -- never
          create a new one. Raises NotEnrolledError if no credentials
          exist. Use this for context recovery after restarts.

  Returns:
      Identity: Your identity (existing or newly created).

  Raises:
      NotEnrolledError: If get_only=True and no credentials exist.
  """
  if credentials_exist():
    return whoami()

  if get_only:
    raise NotEnrolledError(
      "No 1ID identity found on this machine. "
      "You passed get_only=True, so no new enrollment was attempted. "
      "Call oneid.get_or_create_identity() without get_only to enroll, "
      "or call oneid.enroll() directly."
    )

  from .credentials import DEFAULT_API_BASE_URL as _default_api_url
  return enroll(
    display_name=display_name,
    operator_email=operator_email,
    requested_handle=requested_handle,
    api_base_url=api_base_url or _default_api_url,
  )


def status() -> WorldStatus:
  """Get the full picture of your 1ID identity and connected services.

  Calls the server's world endpoint with your Bearer token and returns
  everything you need to know: identity details, devices, connected
  RP services, available services, and operator guidance.

  Results are cached for 5 minutes. Call world.invalidate_world_cache()
  to force a fresh fetch.

  This is the recommended way for an agent to recover context after
  a restart or memory loss.

  Returns:
      WorldStatus: Complete identity state from the server.

  Raises:
      NotEnrolledError: If no credentials exist (call enroll() first).
      NetworkError: If the server cannot be reached.
      AuthenticationError: If the token is invalid or expired.
  """
  creds = load_credentials()
  from .world import fetch_world_status_from_server
  return fetch_world_status_from_server(creds)


def refresh() -> None:
  """Force-refresh the cached OAuth2 token.

  Discards the in-memory cached token and fetches a new one
  on the next get_token() call.
  """
  clear_cached_token()


def setup_tbs() -> bool:
  """One-time setup: grant TBS access to non-admin users (Windows only).

  This sets a Windows registry key so that all future TPM operations
  (extract, activate, sign) work without administrator privileges.
  Triggers a UAC prompt on Windows. No-op on other platforms.

  Call this when you catch TPMSetupRequiredError during enrollment.

  Returns:
      True if setup succeeded (or was already done).

  Raises:
      UACDeniedError: If the user denied the UAC prompt.
      HSMAccessError: If the registry key could not be set.
  """
  from .helper import setup_tbs_for_non_admin_tpm_access
  result = setup_tbs_for_non_admin_tpm_access()
  return result.get("ok", False)


def record_privacy_consent(mode: str = "sd-jwt") -> None:
  """Record the user's privacy consent choice in the credentials file.

  After the calling application shows a privacy warning and the user
  consents, call this to persist their preferred attestation mode.
  Valid modes are 'sd-jwt' (selective disclosure, recommended) and
  'direct' (full direct attestation).

  Args:
      mode: The user's chosen attestation mode ('sd-jwt' or 'direct').

  Raises:
      NotEnrolledError: If no credentials file exists yet.
      ValueError: If mode is not 'sd-jwt' or 'direct'.
  """
  from datetime import datetime, timezone
  from .credentials import load_credentials, save_credentials

  if mode not in ("sd-jwt", "direct"):
    raise ValueError(f"Invalid attestation mode '{mode}'. Must be 'sd-jwt' or 'direct'.")

  creds = load_credentials()
  creds = type(creds)(
    **{
      **{field: getattr(creds, field) for field in creds.__dataclass_fields__},
      "privacy_consent_given_at": datetime.now(timezone.utc).isoformat(),
      "default_attestation_mode": mode,
    }
  )
  save_credentials(creds)


# -- Public API --
__all__ = [
  # Core functions
  "enroll",
  "get_or_create_identity",
  "status",
  "get_token",
  "refresh",
  "setup_tbs",
  "record_privacy_consent",
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
  "WorldStatus",
  # Exceptions (all importable from oneid directly)
  "OneIDError",
  "EnrollmentError",
  "NoHSMError",
  "UACDeniedError",
  "HSMAccessError",
  "TPMSetupRequiredError",
  "AlreadyEnrolledError",
  "HandleTakenError",
  "HandleInvalidError",
  "HandleRetiredError",
  "AuthenticationError",
  "HardwareDeviceNotPresentError",
  "NetworkError",
  "NotEnrolledError",
  "BinaryNotFoundError",
  # Device management exceptions
  "DeviceManagementError",
  "DowngradeRejectedError",
  "ColocationRequiredError",
  "ColocationBindingError",
  "ColocationSessionExpiredError",
  "ColocationTimingViolationError",
  "DeviceAlreadyBoundError",
  "LastDeviceBurnRejectedError",
  "BurnConfirmationExpiredError",
  "HardwareLockedError",
  "IdentityAlreadyLockedError",
  "DeclaredTierCannotBeLockedError",
  "TooManyActiveDevicesForLockError",
  # Device management data types
  "DeviceInfo",
  "DeviceListResult",
  "DeviceAddResult",
  "BurnRequestResult",
  "BurnConfirmResult",
  "HardwareLockResult",
  # Device management module
  "devices",
  # Credential pointer module
  "credential_pointers",
  # Credential pointer exceptions
  "CredentialPointerError",
  "ConsentTokenGenerationError",
  "CredentialPointerNotFoundError",
  "CredentialPointerAlreadyRemovedError",
  # Credential pointer data types
  "ConsentTokenResult",
  "CredentialPointerInfo",
  "CredentialPointerListResult",
  # Peer identity verification
  "sign_challenge",
  "verify_peer_identity",
  "refresh_trust_roots",
  "get_trust_roots",
  "IdentityProofBundle",
  "VerifiedPeerIdentity",
  "PeerVerificationError",
  "CertificateChainValidationError",
  "SignatureVerificationError",
  "MissingIdentityCertificateError",
  # Version
  "__version__",
]
