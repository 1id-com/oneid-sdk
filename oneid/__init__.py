from __future__ import annotations

"""
1id.com SDK -- Hardware-anchored identity for AI agents.

Quick start (recommended):

    import oneid

    # Get or create your identity -- the simplest path
    identity = oneid.get_or_create_identity(display_name="Sparky")
    print(f"I am {identity}")

    # Get an access token. It is sender-constrained (cnf.jwk): requests must
    # also be signed with the enrolled key -- the SDK does this for its own
    # calls, and airs_http_message_signatures.sign_request does it for yours.
    response = oneid.send_http_request_with_sender_constrained_token(
      "GET", "https://1id.com/api/v1/identity/devices")
    print(response.status_code, response.json())

The SDK auto-detects your hardware (TPM, YubiKey, Secure Enclave) and
enrolls at the highest available trust tier. No arguments needed.

If you need a specific tier:

    identity = oneid.enroll(request_tier="sovereign")

Trust tiers (highest to lowest, RFC Section 3):
    'sovereign' -- Discrete/firmware TPM, manufacturer CA chain, Sybil-resistant
    'portable'  -- YubiKey PIV (Yubico attestation), manufacturer-attested, portable
    'virtual'   -- Hypervisor vTPM (VMware/Hyper-V/QEMU), hypervisor-attested
    'declared'  -- Software keys, no hardware proof, always works
"""

from .auth import clear_cached_token, get_token
from .credentials import credentials_exist, load_credentials, sync_device_certificate_chains_from_server
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
  AttestationGenerationError,
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
from .attestation import (
  prepare_attestation,
  prepare_direct_hardware_attestation,
  build_cms_signed_data_for_direct_attestation,
  compute_attestation_input_for_direct_mode,
  AttestationProof,
)
from .verify import (
  sign_challenge,
  verify_peer_identity,
  IdentityProofBundle,
  VerifiedPeerIdentity,
  PeerVerificationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  MissingIdentityCertificateError,
  RegistrarAuthorityValidationError,
  PeerVerificationTemporarilyUnavailableError,
  resolve_agent_identity_at_airs_registry,
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
  register_operator_email,
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
from . import airs_http_message_signatures


def send_http_request_with_sender_constrained_token(method, url, json=None, headers=None, token=None):
  """Send one HTTP request carrying this agent's access token SENDER-CONSTRAINED:
  Authorization plus an RFC 9421 signature by the enrolled key (TPM, PIV,
  Secure Enclave or declared key) over the exact method, URL and body
  (registry-04 "HTTP Message Signatures"). 1ID tokens carry cnf.jwk, so a
  service that verifies them refuses the token without this signature.
  Returns the response (status_code, text, json()); 4xx/5xx are returned,
  not raised. token defaults to get_token()."""
  from . import _http
  signed_headers = dict(headers or {})
  signed_headers["Authorization"] = token or get_token()
  return _http.Client().request(method.upper(), url, json=json, headers=signed_headers)


def _build_identity_from_local_credentials() -> Identity:
  """Build an Identity object from the local credentials file.

  Internal helper shared by whoami() and get_or_create_identity().
  Does NOT emit any deprecation warnings. Does NOT make a network request.
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

  canonical_id = creds.client_id
  handle = f"@{canonical_id}" if not canonical_id.startswith("@") else canonical_id

  # AUD-F59: the enrolled local device (same rule as login and signing), not
  # "any key reference is a TPM".
  from .credentials import local_signing_device_type_for_credentials
  hsm_type: HSMType | None = {
    "piv": HSMType.YUBIKEY, "enclave": HSMType.SECURE_ENCLAVE, "tpm": HSMType.TPM, "software": HSMType.SOFTWARE,
  }.get(local_signing_device_type_for_credentials(creds))

  return Identity(
    canonical_id=canonical_id,
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
  return _build_identity_from_local_credentials()


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
    return _build_identity_from_local_credentials()

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


# -- Public API --
__all__ = [
  # Sender-constrained requests (RFC 9421; sign_request / verify_request inside)
  "send_http_request_with_sender_constrained_token",
  "airs_http_message_signatures",
  # Core functions
  "enroll",
  "get_or_create_identity",
  "status",
  "get_token",
  "refresh",
  "setup_tbs",
  "sign_challenge_with_private_key",
  "prepare_attestation",
  "prepare_direct_hardware_attestation",
  "build_cms_signed_data_for_direct_attestation",
  "compute_attestation_input_for_direct_mode",
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
  "AttestationGenerationError",
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
  "register_operator_email",
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
  "RegistrarAuthorityValidationError",
  "PeerVerificationTemporarilyUnavailableError",
  "resolve_agent_identity_at_airs_registry",
  # Version
  "__version__",
]
