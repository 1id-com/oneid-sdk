"""
Device management for the 1id.com SDK.

Manages multiple hardware devices bound to a single identity:
  list()          -- List all devices (active and burned) via the server
  add()           -- Add a new hardware device (declared->hardware upgrade or co-location binding)
  burn()          -- Permanently retire a device (two-step with co-device signature)
  lock_hardware() -- Permanently lock identity to its single device (irreversible)

Trust tier is dynamic: determined by the last device used to authenticate.
The downgrade guard prevents adding weaker devices to stronger identities.

Usage:
    import oneid
    from oneid import devices

    # List all devices on your identity
    result = devices.list()
    for device in result.devices:
        print(f"{device.device_type} [{device.device_status}]")

    # Add a hardware device (auto-detects TPM or YubiKey)
    new_device = devices.add()
    print(f"Added {new_device.device_type} device")

    # Lock identity to its single hardware device (irreversible)
    lock_result = devices.lock_hardware()
    print(f"Locked: {lock_result.hardware_locked}")
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .auth import get_token
from .client import OneIDAPIClient
from .credentials import StoredCredentials, load_credentials, save_credentials
from .exceptions import (
  AuthenticationError,
  NetworkError,
  NotEnrolledError,
  OneIDError,
)

logger = logging.getLogger("oneid.devices")


# =====================================================================
# Device management exceptions
# =====================================================================

class DeviceManagementError(OneIDError):
  """Base exception for all device management failures."""

  def __init__(self, message: str = "Device management operation failed", error_code: str | None = None) -> None:
    super().__init__(message, error_code=error_code)


class DowngradeRejectedError(DeviceManagementError):
  """Server rejected adding a weaker device to a hardware-tier identity.

  Hardware-tier identities (sovereign, portable) can only add hardware
  devices. Adding software credentials would undermine the trust model.
  """

  def __init__(self, message: str = "Cannot add weaker device to hardware-tier identity") -> None:
    super().__init__(message, error_code="DOWNGRADE_REJECTED")


class ColocationRequiredError(DeviceManagementError):
  """Hardware-tier identity with existing devices requires co-location binding.

  When the identity already has active hardware devices, new devices must
  prove physical proximity via the 042.3 co-location binding ceremony.
  Use add(existing_device_fingerprint=..., existing_device_type=...) for
  hardware-to-hardware additions.
  """

  def __init__(self, message: str = "Co-location binding required for hardware-tier device addition") -> None:
    super().__init__(message, error_code="COLOCATION_REQUIRED")


class ColocationBindingError(DeviceManagementError):
  """Co-location binding ceremony failed."""

  def __init__(self, message: str = "Co-location binding ceremony failed", error_code: str | None = None) -> None:
    super().__init__(message, error_code=error_code or "COLOCATION_FAILED")


class ColocationSessionExpiredError(ColocationBindingError):
  """The 30-second co-location binding session expired."""

  def __init__(self, message: str = "Co-location binding session expired") -> None:
    super().__init__(message, error_code="SESSION_EXPIRED")


class ColocationTimingViolationError(ColocationBindingError):
  """Timing measurement during co-location binding was outside acceptable range.

  The TPM clock delta between the two quotes must be between 5ms and 500ms.
  Too fast suggests precomputed/replayed proofs; too slow suggests a remote device.
  """

  def __init__(
    self,
    message: str = "Co-location timing violation",
    elapsed_ms: float | None = None,
    severity: str | None = None,
  ) -> None:
    super().__init__(message, error_code="TIMING_VIOLATION")
    self.elapsed_ms = elapsed_ms
    self.severity = severity


class DeviceAlreadyBoundError(DeviceManagementError):
  """This device (TPM EK or PIV serial) is already bound to a different identity.

  Each hardware device can only be bound to one identity (anti-Sybil).
  """

  def __init__(self, message: str = "Device is already bound to another identity") -> None:
    super().__init__(message, error_code="DEVICE_ALREADY_BOUND")


class LastDeviceBurnRejectedError(DeviceManagementError):
  """Cannot burn the last active device on an identity.

  Burning the last device would make the identity permanently inaccessible.
  Add another device first, or consider hardware lock instead.
  """

  def __init__(self, message: str = "Cannot burn last active device") -> None:
    super().__init__(message, error_code="LAST_DEVICE_BURN_REJECTED")


class BurnConfirmationExpiredError(DeviceManagementError):
  """The 5-minute burn confirmation token has expired.

  Request a new burn token and retry.
  """

  def __init__(self, message: str = "Burn confirmation token expired") -> None:
    super().__init__(message, error_code="BURN_TOKEN_EXPIRED")


class HardwareLockedError(DeviceManagementError):
  """The identity is hardware-locked to a single device.

  Once locked, no new devices can be added and the existing device
  cannot be burned. This is irreversible.
  """

  def __init__(self, message: str = "Identity is hardware-locked to a single device") -> None:
    super().__init__(message, error_code="HARDWARE_LOCKED")


class IdentityAlreadyLockedError(DeviceManagementError):
  """Lock was requested but the identity is already locked (idempotent-safe)."""

  def __init__(self, message: str = "Identity is already hardware-locked") -> None:
    super().__init__(message, error_code="ALREADY_LOCKED")


class DeclaredTierCannotBeLockedError(DeviceManagementError):
  """A declared-tier identity cannot be hardware-locked (no hardware device)."""

  def __init__(self, message: str = "Declared-tier identities cannot be hardware-locked") -> None:
    super().__init__(message, error_code="DECLARED_TIER_CANNOT_LOCK")


class TooManyActiveDevicesForLockError(DeviceManagementError):
  """Hardware lock requires exactly 1 active device; burn extras first."""

  def __init__(self, message: str = "Too many active devices for hardware lock") -> None:
    super().__init__(message, error_code="TOO_MANY_ACTIVE_DEVICES")


# =====================================================================
# Data classes
# =====================================================================

@dataclass(frozen=True)
class DeviceInfo:
  """A single device bound to an identity."""
  device_type: str
  device_fingerprint: str
  device_status: str
  trust_tier: Optional[str] = None
  tpm_manufacturer: Optional[str] = None
  piv_serial: Optional[str] = None
  bound_at: Optional[str] = None
  burned_at: Optional[str] = None
  burn_reason: Optional[str] = None


@dataclass(frozen=True)
class DeviceListResult:
  """Result of listing all devices on an identity."""
  identity_internal_id: str
  total_device_count: int
  active_device_count: int
  burned_device_count: int
  devices: List[DeviceInfo] = field(default_factory=list)


@dataclass(frozen=True)
class DeviceAddResult:
  """Result of adding a new device to an identity."""
  device_type: str
  device_fingerprint: str
  trust_tier: str
  identity_was_upgraded_from_declared: bool
  previous_tier: Optional[str] = None
  device_serial: Optional[str] = None


@dataclass(frozen=True)
class BurnRequestResult:
  """Result of requesting a device burn (step 1 of 2)."""
  token_id: str
  expires_at: str
  target_device_fingerprint: str
  target_device_type: str
  active_devices_remaining_after_burn: int


@dataclass(frozen=True)
class BurnConfirmResult:
  """Result of confirming a device burn (step 2 of 2)."""
  burned_device_fingerprint: str
  burned_device_type: str
  burn_reason: Optional[str]
  confirmed_by_device_fingerprint: str
  confirmed_by_device_type: str
  remaining_active_devices: int


@dataclass(frozen=True)
class HardwareLockResult:
  """Result of locking an identity to its single hardware device."""
  identity_internal_id: str
  hardware_locked: bool
  trust_tier: str
  active_device_count: int


# =====================================================================
# Server error code -> exception mapping
# =====================================================================

_DEVICE_ERROR_CODE_TO_EXCEPTION_CLASS: dict[str, type[DeviceManagementError]] = {
  "DOWNGRADE_REJECTED": DowngradeRejectedError,
  "COLOCATION_REQUIRED": ColocationRequiredError,
  "SESSION_EXPIRED": ColocationSessionExpiredError,
  "TIMING_VIOLATION": ColocationTimingViolationError,
  "TPM_RESET_DETECTED": ColocationBindingError,
  "DEVICE_ALREADY_BOUND": DeviceAlreadyBoundError,
  "LAST_DEVICE_BURN_REJECTED": LastDeviceBurnRejectedError,
  "HARDWARE_LOCKED": HardwareLockedError,
  "ALREADY_LOCKED": IdentityAlreadyLockedError,
  "DECLARED_TIER_CANNOT_LOCK": DeclaredTierCannotBeLockedError,
  "TOO_MANY_ACTIVE_DEVICES": TooManyActiveDevicesForLockError,
}


def _raise_from_device_api_error(error_data: dict) -> None:
  """Raise the appropriate DeviceManagementError from a server error response."""
  error_code = error_data.get("code", "UNKNOWN")
  error_message = error_data.get("message", "Device management operation failed")

  exception_class = _DEVICE_ERROR_CODE_TO_EXCEPTION_CLASS.get(error_code, DeviceManagementError)

  if error_code == "TIMING_VIOLATION":
    raise ColocationTimingViolationError(
      message=error_message,
      elapsed_ms=error_data.get("elapsed_ms"),
      severity=error_data.get("severity"),
    )

  raise exception_class(error_message)


# =====================================================================
# Internal helpers
# =====================================================================

def _get_authenticated_api_client_and_token(
  credentials: StoredCredentials | None = None,
) -> tuple[OneIDAPIClient, Any, StoredCredentials]:
  """Load credentials, get a fresh token, and return (client, token, creds)."""
  if credentials is None:
    credentials = load_credentials()
  token = get_token(credentials=credentials)
  api_client = OneIDAPIClient(api_base_url=credentials.api_base_url)
  return api_client, token, credentials


def _make_authenticated_request(
  method: str,
  path: str,
  json_body: dict | None = None,
  credentials: StoredCredentials | None = None,
) -> dict:
  """Make an authenticated API request and return the response data.

  Handles the standard 1id.com envelope: {"ok": true, "data": {...}}.
  On error envelope, raises the appropriate DeviceManagementError.
  """
  api_client, token, creds = _get_authenticated_api_client_and_token(credentials)

  url = f"{api_client.api_base_url}{path}"
  headers = {
    "Authorization": token.authorization_header_value,
  }

  import httpx
  try:
    with httpx.Client(timeout=api_client.timeout_seconds) as http_client:
      response = http_client.request(
        method=method,
        url=url,
        json=json_body,
        headers={
          "User-Agent": "oneid-sdk-python",
          "Accept": "application/json",
          **headers,
        },
      )
  except httpx.ConnectError as connection_error:
    raise NetworkError(f"Could not connect to {url}: {connection_error}") from connection_error
  except httpx.TimeoutException as timeout_error:
    raise NetworkError(f"Request to {url} timed out: {timeout_error}") from timeout_error

  try:
    response_body = response.json()
  except Exception as json_error:
    raise NetworkError(f"Invalid JSON from {url} (HTTP {response.status_code}): {json_error}") from json_error

  if not response_body.get("ok", False):
    error_info = response_body.get("error", {})
    _raise_from_device_api_error(error_info)

  return response_body.get("data", {})


# =====================================================================
# list()
# =====================================================================

def list(credentials: StoredCredentials | None = None) -> DeviceListResult:
  """List all devices (active and burned) bound to this identity.

  Calls GET /api/v1/identity/devices with the current Bearer token.
  Returns structured device information from the server.

  Args:
      credentials: Optional pre-loaded credentials. If None, loaded from file.

  Returns:
      DeviceListResult with all devices and counts.

  Raises:
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token is invalid.
      NetworkError: If the server cannot be reached.
  """
  raw_data = _make_authenticated_request("GET", "/api/v1/identity/devices", credentials=credentials)

  devices = [
    DeviceInfo(
      device_type=d.get("device_type", "unknown"),
      device_fingerprint=d.get("device_fingerprint", ""),
      device_status=d.get("device_status", "active"),
      trust_tier=d.get("trust_tier"),
      tpm_manufacturer=d.get("tpm_manufacturer"),
      piv_serial=d.get("piv_serial"),
      bound_at=d.get("bound_at"),
      burned_at=d.get("burned_at"),
      burn_reason=d.get("burn_reason"),
    )
    for d in raw_data.get("devices", [])
  ]

  if credentials is None:
    credentials = load_credentials()

  return DeviceListResult(
    identity_internal_id=raw_data.get("identity_internal_id", credentials.client_id),
    total_device_count=raw_data.get("total_devices", len(devices)),
    active_device_count=raw_data.get("active_devices", 0),
    burned_device_count=raw_data.get("burned_devices", 0),
    devices=devices,
  )


# =====================================================================
# add()
# =====================================================================

def add(
  device_type: str | None = None,
  existing_device_fingerprint: str | None = None,
  existing_device_type: str | None = None,
  credentials: StoredCredentials | None = None,
) -> DeviceAddResult:
  """Add a new hardware device to this identity.

  Two code paths, automatically selected based on identity state:

  1. **Declared -> hardware upgrade** (no co-location):
     If the identity is declared-tier (software keys only), this detects
     available hardware (TPM or YubiKey), extracts attestation via the Go
     binary, sends the attestation to the server for validation, registers
     the device, upgrades the identity tier, and updates credentials.json.

  2. **Hardware -> hardware (co-location binding)**:
     If the identity already has hardware devices, this orchestrates the
     full 042.3 co-location binding ceremony: TPM quote C1, PIV signature
     S2, TPM bind-quote C2, proving physical proximity of old and new
     devices within a 30-second window. Pass existing_device_fingerprint
     and existing_device_type for this path.

  Args:
      device_type: Optional. 'tpm' or 'piv'. If None, auto-detects the
          best available hardware.
      existing_device_fingerprint: For hardware-to-hardware additions only.
          The fingerprint of the existing device to prove co-location with.
      existing_device_type: For hardware-to-hardware additions only.
          'tpm' or 'piv' -- the type of the existing device.
      credentials: Optional pre-loaded credentials.

  Returns:
      DeviceAddResult with the new device information.

  Raises:
      NotEnrolledError: If no credentials file exists.
      NoHSMError: If no compatible hardware is found.
      DowngradeRejectedError: If adding this device type would be a downgrade.
      ColocationRequiredError: If the identity has hardware but co-location
          params were not provided.
      ColocationBindingError: If the co-location ceremony fails.
      ColocationTimingViolationError: If timing is outside acceptable range.
      DeviceAlreadyBoundError: If the device is already bound to another identity.
      DeviceManagementError: For any other device management failure.
  """
  if credentials is None:
    credentials = load_credentials()

  current_tier = credentials.trust_tier

  if current_tier == "declared" or credentials.hsm_key_reference is None:
    return _add_device_via_declared_to_hardware_upgrade(
      device_type_preference=device_type,
      credentials=credentials,
    )
  else:
    if existing_device_fingerprint is None or existing_device_type is None:
      raise ColocationRequiredError(
        "This identity already has hardware devices. To add another device, "
        "you must provide existing_device_fingerprint and existing_device_type "
        "for the co-location binding ceremony. Use devices.list() to see your "
        "current devices."
      )
    return _add_device_via_colocation_binding(
      existing_device_fingerprint=existing_device_fingerprint,
      existing_device_type=existing_device_type,
      new_device_type=device_type or "piv",
      credentials=credentials,
    )


def _add_device_via_declared_to_hardware_upgrade(
  device_type_preference: str | None,
  credentials: StoredCredentials,
) -> DeviceAddResult:
  """Add a hardware device to a declared-tier identity (no co-location).

  1. Detect hardware via Go binary
  2. Extract attestation data via Go binary
  3. Send attestation to POST /api/v1/identity/devices/add
  4. Server validates, registers device, upgrades identity
  5. Update local credentials.json with new tier + HSM reference
  """
  from .helper import detect_available_hsms, extract_attestation_data
  from .enroll import _select_hsm_for_tier, TIERS_REQUIRING_HSM
  from .identity import TrustTier

  logger.info("Adding hardware device to declared-tier identity (upgrade path)")

  detected_hsms = detect_available_hsms()
  if not detected_hsms:
    from .exceptions import NoHSMError
    raise NoHSMError(
      "No hardware security module found. "
      "Device addition requires a TPM, YubiKey, or similar device."
    )

  selected_hsm = None

  if device_type_preference:
    for hsm in detected_hsms:
      if hsm.get("type") == device_type_preference or (
        device_type_preference == "piv" and hsm.get("type") in ("yubikey", "piv")
      ):
        selected_hsm = hsm
        break
    if selected_hsm is None:
      from .exceptions import NoHSMError
      raise NoHSMError(
        f"No {device_type_preference} device found. "
        f"Available HSMs: {', '.join(h.get('type', 'unknown') for h in detected_hsms)}"
      )
  else:
    tier_preference_order = [TrustTier.SOVEREIGN, TrustTier.PORTABLE]
    for tier in tier_preference_order:
      selected_hsm = _select_hsm_for_tier(detected_hsms, tier)
      if selected_hsm is not None:
        break

    if selected_hsm is None:
      from .exceptions import NoHSMError
      raise NoHSMError(
        f"Found HSM(s) ({', '.join(h.get('type', 'unknown') for h in detected_hsms)}) "
        "but none are compatible for device addition."
      )

  logger.info("Selected HSM: %s (%s)", selected_hsm.get("type"), selected_hsm.get("manufacturer", "unknown"))

  attestation_data = extract_attestation_data(selected_hsm)
  hsm_type = selected_hsm.get("type", "tpm")

  if hsm_type in ("yubikey", "piv"):
    request_body: dict[str, Any] = {
      "device_type": "piv",
      "attestation_cert_pem": attestation_data.get("attestation_cert_pem", attestation_data.get("ek_cert_pem", "")),
      "attestation_chain_pem": attestation_data.get("attestation_chain_pem", attestation_data.get("chain_pem", [])),
      "signing_key_public_pem": attestation_data.get("signing_key_public_pem", attestation_data.get("ak_public_pem", "")),
    }
    new_hsm_key_reference = "piv-slot-9a"
    new_key_algorithm = "ecdsa-p256"
  else:
    request_body = {
      "device_type": "tpm",
      "ek_certificate_pem": attestation_data.get("ek_cert_pem", ""),
      "ak_public_key_pem": attestation_data.get("ak_public_pem", ""),
      "ak_tpmt_public_b64": attestation_data.get("ak_tpmt_public_b64", ""),
      "ek_public_key_pem": attestation_data.get("ek_public_pem", ""),
      "ek_certificate_chain_pem": attestation_data.get("chain_pem", []),
    }
    new_hsm_key_reference = attestation_data.get("ak_handle", "transient")
    new_key_algorithm = "tpm-ak"

  response_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/devices/add",
    json_body=request_body,
    credentials=credentials,
  )

  new_tier = response_data.get("trust_tier", "sovereign" if hsm_type == "tpm" else "portable")
  identity_was_upgraded = response_data.get("identity_upgraded", False)

  if identity_was_upgraded:
    updated_credentials = StoredCredentials(
      client_id=credentials.client_id,
      client_secret=credentials.client_secret,
      token_endpoint=credentials.token_endpoint,
      api_base_url=credentials.api_base_url,
      trust_tier=new_tier,
      key_algorithm=new_key_algorithm,
      private_key_pem=None,
      hsm_key_reference=new_hsm_key_reference,
      enrolled_at=credentials.enrolled_at,
      display_name=credentials.display_name,
      agent_identity_urn=credentials.agent_identity_urn,
      privacy_consent_given_at=credentials.privacy_consent_given_at,
      default_attestation_mode=credentials.default_attestation_mode,
    )
    save_credentials(updated_credentials)
    logger.info(
      "Identity upgraded from declared to %s -- credentials.json updated (software key retired)",
      new_tier,
    )

  from .world import invalidate_world_cache
  invalidate_world_cache()

  return DeviceAddResult(
    device_type=response_data.get("device_type", request_body["device_type"]),
    device_fingerprint=response_data.get("device_fingerprint", ""),
    trust_tier=new_tier,
    identity_was_upgraded_from_declared=identity_was_upgraded,
    previous_tier=response_data.get("previous_tier"),
    device_serial=response_data.get("device_serial"),
  )


def _add_device_via_colocation_binding(
  existing_device_fingerprint: str,
  existing_device_type: str,
  new_device_type: str,
  credentials: StoredCredentials,
) -> DeviceAddResult:
  """Add a hardware device via the 042.3 co-location binding ceremony.

  Full ceremony orchestration:
    Phase 1: POST /piv-bind/begin -> get server nonce (N1)
    Phase 2: Go binary sign --output-clock with N1 -> get C1 quote (S1 = signature)
    Phase 3: Go binary piv-sign --data b64(S1||N1) -> get S2 signature
    Phase 4: Go binary tpm-bind-quote --extend-data b64(SHA256(S2))
             --qualifying-data b64(N1||S1||S2) --elevated -> get C2 quote
    Phase 5: Go binary extract --type yubikey -> get PIV attestation
    Phase 6: POST /piv-bind/complete with all collected data

  Requires both devices to be physically present on this machine.
  The entire ceremony must complete within 30 seconds.
  """
  from .helper import (
    _run_binary_command,
    detect_available_hsms,
    extract_attestation_data,
    sign_challenge_with_tpm,
  )

  logger.info(
    "Starting co-location binding: existing=%s/%s, new=%s",
    existing_device_type, existing_device_fingerprint[:16], new_device_type,
  )

  ak_handle = credentials.hsm_key_reference or ""

  # Phase 1: Begin session
  session_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/piv-bind/begin",
    json_body={
      "existing_device_fingerprint": existing_device_fingerprint,
      "existing_device_type": existing_device_type,
      "new_device_type": new_device_type,
    },
    credentials=credentials,
  )
  session_id = session_data["session_id"]
  server_nonce_b64 = session_data["server_nonce_b64"]
  server_nonce_bytes = base64.b64decode(server_nonce_b64)

  logger.info("Co-location session %s started (30s window)", session_id[:16])

  # Phase 2: C1 TPM Quote (sign nonce with clock output)
  c1_sign_args = ["--nonce", server_nonce_b64, "--output-clock"]
  if ak_handle and ak_handle != "transient":
    c1_sign_args.extend(["--ak-handle", ak_handle])
  c1_result = _run_binary_command("sign", args=c1_sign_args)
  c1_signature_b64 = c1_result.get("signature_b64", "")
  c1_signature_bytes = base64.b64decode(c1_signature_b64)

  c1_quote_data = {
    "clock_ms": c1_result.get("clock_ms", 0),
    "reset_count": c1_result.get("reset_count", 0),
    "restart_count": c1_result.get("restart_count", 0),
    "clock_safe": c1_result.get("clock_safe", True),
    "signature_b64": c1_signature_b64,
    "quoted_b64": c1_result.get("quoted_b64", ""),
  }

  logger.debug("C1 quote: clock=%dms, reset_count=%d", c1_quote_data["clock_ms"], c1_quote_data["reset_count"])

  # Phase 3: S2 PIV signature over (S1 || N1)
  s1_concat_n1 = c1_signature_bytes + server_nonce_bytes
  s1_concat_n1_b64 = base64.b64encode(s1_concat_n1).decode("ascii")

  s2_result = _run_binary_command(
    "piv-sign",
    args=["--data", s1_concat_n1_b64],
  )
  s2_signature_b64 = s2_result.get("signature_b64", "")
  s2_signature_bytes = base64.b64decode(s2_signature_b64)

  logger.debug("S2 PIV signature obtained")

  # Phase 4: C2 TPM bind-quote (extend PCR 16 with SHA256(S2), then quote)
  extend_hash = hashlib.sha256(s2_signature_bytes).digest()
  extend_data_b64 = base64.b64encode(extend_hash).decode("ascii")

  n1_s1_s2_concat = server_nonce_bytes + c1_signature_bytes + s2_signature_bytes
  qualifying_data_b64 = base64.b64encode(n1_s1_s2_concat).decode("ascii")

  c2_bind_quote_args = [
    "--extend-pcr", "16",
    "--extend-data", extend_data_b64,
    "--qualifying-data", qualifying_data_b64,
    "--elevated",
  ]
  if ak_handle and ak_handle != "transient":
    c2_bind_quote_args.extend(["--ak-handle", ak_handle])
  c2_result = _run_binary_command(
    "tpm-bind-quote",
    args=c2_bind_quote_args,
    timeout_seconds=60.0,
  )
  c2_quote_data = {
    "clock_ms": c2_result.get("clock_ms", 0),
    "reset_count": c2_result.get("reset_count", 0),
    "restart_count": c2_result.get("restart_count", 0),
    "clock_safe": c2_result.get("clock_safe", True),
    "pcr16_value_b64": c2_result.get("pcr16_value_b64", ""),
    "signature_b64": c2_result.get("signature_b64", ""),
    "quoted_b64": c2_result.get("quoted_b64", ""),
  }

  logger.debug("C2 quote: clock=%dms, elapsed=%dms", c2_quote_data["clock_ms"], c2_quote_data["clock_ms"] - c1_quote_data["clock_ms"])

  # Phase 5: Extract PIV attestation for the new device
  detected_hsms = detect_available_hsms()
  piv_hsm = None
  for hsm in detected_hsms:
    if hsm.get("type") in ("yubikey", "piv"):
      piv_hsm = hsm
      break

  if piv_hsm is None:
    raise ColocationBindingError("No PIV device found for attestation extraction")

  piv_attestation = extract_attestation_data(piv_hsm)
  new_device_attestation = {
    "attestation_cert_pem": piv_attestation.get("attestation_cert_pem", piv_attestation.get("ek_cert_pem", "")),
    "chain_pem": piv_attestation.get("attestation_chain_pem", piv_attestation.get("chain_pem", [])),
    "signing_key_public_pem": piv_attestation.get("signing_key_public_pem", piv_attestation.get("ak_public_pem", "")),
    "serial": piv_attestation.get("serial_number", piv_attestation.get("serial", "")),
  }

  # Phase 6: Complete binding
  complete_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/piv-bind/complete",
    json_body={
      "session_id": session_id,
      "c1_quote": c1_quote_data,
      "s2_signature_b64": s2_signature_b64,
      "c2_quote": c2_quote_data,
      "new_device_attestation": new_device_attestation,
    },
    credentials=credentials,
  )

  logger.info(
    "Co-location binding complete: session=%s, elapsed=%dms, verified=%s",
    session_id[:16],
    complete_data.get("elapsed_ms", 0),
    complete_data.get("verified", False),
  )

  from .world import invalidate_world_cache
  invalidate_world_cache()

  return DeviceAddResult(
    device_type="piv",
    device_fingerprint=complete_data.get("new_device_fingerprint", ""),
    trust_tier="portable",
    identity_was_upgraded_from_declared=False,
    device_serial=complete_data.get("new_device_serial"),
  )


# =====================================================================
# burn()
# =====================================================================

def burn(
  device_fingerprint: str,
  device_type: str,
  co_device_fingerprint: str,
  co_device_type: str,
  reason: str | None = None,
  credentials: StoredCredentials | None = None,
) -> BurnConfirmResult:
  """Permanently retire (burn) a device from this identity.

  Burning is irreversible: the device fingerprint is permanently marked
  in the anti-Sybil registry, preventing it from ever being used for
  any new identity. This prevents an attacker who obtains a retired
  device from creating a fresh identity with it.

  Two-step process:
    1. Request a burn confirmation token (server verifies not last device)
    2. Sign with a co-device and confirm (proves deliberate human intent)

  The co-device must be a DIFFERENT active device on the same identity.
  This prevents malware from silently destroying hardware utility.

  Args:
      device_fingerprint: Fingerprint of the device to burn.
      device_type: 'tpm' or 'piv'.
      co_device_fingerprint: Fingerprint of the co-signing device.
      co_device_type: 'tpm' or 'piv'.
      reason: Optional reason for the burn (e.g., 'migrated to new hardware').
      credentials: Optional pre-loaded credentials.

  Returns:
      BurnConfirmResult with details of the completed burn.

  Raises:
      LastDeviceBurnRejectedError: If this is the last active device.
      DeviceManagementError: If the burn request or confirmation fails.
      NotEnrolledError: If no credentials file exists.
      AuthenticationError: If the token is invalid.
      NetworkError: If the server cannot be reached.
  """
  if credentials is None:
    credentials = load_credentials()

  # Step 1: Request burn confirmation token
  logger.info(
    "Requesting burn token for %s/%s (co-device: %s/%s)",
    device_type, device_fingerprint[:16],
    co_device_type, co_device_fingerprint[:16],
  )

  burn_token_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/devices/burn",
    json_body={
      "device_fingerprint": device_fingerprint,
      "device_type": device_type,
      "reason": reason,
    },
    credentials=credentials,
  )

  token_id = burn_token_data["token_id"]
  logger.info(
    "Burn token issued: %s (expires: %s, %d devices will remain)",
    token_id[:16],
    burn_token_data.get("expires_at", "?"),
    burn_token_data.get("active_devices_remaining_after_burn", 0),
  )

  # Step 2: Sign with co-device and confirm
  co_device_signature_b64 = _sign_burn_confirmation_with_co_device(
    token_id=token_id,
    co_device_fingerprint=co_device_fingerprint,
    co_device_type=co_device_type,
    credentials=credentials,
  )

  confirm_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/devices/burn/confirm",
    json_body={
      "token_id": token_id,
      "co_device_signature_b64": co_device_signature_b64,
      "co_device_fingerprint": co_device_fingerprint,
      "co_device_type": co_device_type,
    },
    credentials=credentials,
  )

  logger.info(
    "Device burned: %s/%s (confirmed by %s/%s, %d devices remaining)",
    confirm_data.get("burned_device_type", device_type),
    confirm_data.get("burned_device_fingerprint", device_fingerprint)[:16],
    co_device_type, co_device_fingerprint[:16],
    confirm_data.get("remaining_active_devices", 0),
  )

  from .world import invalidate_world_cache
  invalidate_world_cache()

  return BurnConfirmResult(
    burned_device_fingerprint=confirm_data.get("burned_device_fingerprint", device_fingerprint),
    burned_device_type=confirm_data.get("burned_device_type", device_type),
    burn_reason=confirm_data.get("burn_reason", reason),
    confirmed_by_device_fingerprint=confirm_data.get("confirmed_by_device_fingerprint", co_device_fingerprint),
    confirmed_by_device_type=confirm_data.get("confirmed_by_device_type", co_device_type),
    remaining_active_devices=confirm_data.get("remaining_active_devices", 0),
  )


def _sign_burn_confirmation_with_co_device(
  token_id: str,
  co_device_fingerprint: str,
  co_device_type: str,
  credentials: StoredCredentials,
) -> str:
  """Sign the burn confirmation token with a co-device (TPM or PIV).

  The signature proves that a second device (not the one being burned)
  authorized the burn, preventing malware from silently destroying
  hardware utility.

  Returns base64-encoded signature.
  """
  message_to_sign = f"BURN:{token_id}"
  message_bytes_b64 = base64.b64encode(message_to_sign.encode("utf-8")).decode("ascii")

  if co_device_type == "tpm":
    from .helper import sign_challenge_with_tpm
    ak_handle = credentials.hsm_key_reference or ""
    sign_result = sign_challenge_with_tpm(nonce_b64=message_bytes_b64, ak_handle=ak_handle)
    return sign_result.get("signature_b64", "")
  elif co_device_type == "piv":
    from .helper import sign_challenge_with_piv
    sign_result = sign_challenge_with_piv(nonce_b64=message_bytes_b64)
    return sign_result.get("signature_b64", "")
  else:
    raise DeviceManagementError(
      f"Unsupported co-device type '{co_device_type}' for burn confirmation. "
      "Must be 'tpm' or 'piv'."
    )


# =====================================================================
# Convenience: request_burn / confirm_burn (for agents that need
# to separate the two steps, e.g. for async co-device signing)
# =====================================================================

def request_burn(
  device_fingerprint: str,
  device_type: str,
  reason: str | None = None,
  credentials: StoredCredentials | None = None,
) -> BurnRequestResult:
  """Request a burn confirmation token (step 1 of 2).

  Use this when you need to separate the burn request from the confirmation,
  for example when the co-device signing happens asynchronously or on a
  different machine.

  The returned token_id is valid for 5 minutes.

  Args:
      device_fingerprint: Fingerprint of the device to burn.
      device_type: 'tpm' or 'piv'.
      reason: Optional reason for the burn.
      credentials: Optional pre-loaded credentials.

  Returns:
      BurnRequestResult with token_id and expiry.
  """
  burn_token_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/devices/burn",
    json_body={
      "device_fingerprint": device_fingerprint,
      "device_type": device_type,
      "reason": reason,
    },
    credentials=credentials,
  )

  return BurnRequestResult(
    token_id=burn_token_data["token_id"],
    expires_at=burn_token_data.get("expires_at", ""),
    target_device_fingerprint=burn_token_data.get("target_device_fingerprint", device_fingerprint),
    target_device_type=burn_token_data.get("target_device_type", device_type),
    active_devices_remaining_after_burn=burn_token_data.get("active_devices_remaining_after_burn", 0),
  )


def confirm_burn(
  token_id: str,
  co_device_signature_b64: str,
  co_device_fingerprint: str,
  co_device_type: str,
  credentials: StoredCredentials | None = None,
) -> BurnConfirmResult:
  """Confirm a burn with a co-device signature (step 2 of 2).

  Use this with a token_id from request_burn() when the co-device
  signing is performed separately.

  Args:
      token_id: The burn confirmation token from request_burn().
      co_device_signature_b64: Base64-encoded signature from the co-device.
      co_device_fingerprint: Fingerprint of the signing co-device.
      co_device_type: 'tpm' or 'piv'.
      credentials: Optional pre-loaded credentials.

  Returns:
      BurnConfirmResult with details of the completed burn.
  """
  confirm_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/devices/burn/confirm",
    json_body={
      "token_id": token_id,
      "co_device_signature_b64": co_device_signature_b64,
      "co_device_fingerprint": co_device_fingerprint,
      "co_device_type": co_device_type,
    },
    credentials=credentials,
  )

  from .world import invalidate_world_cache
  invalidate_world_cache()

  return BurnConfirmResult(
    burned_device_fingerprint=confirm_data.get("burned_device_fingerprint", ""),
    burned_device_type=confirm_data.get("burned_device_type", ""),
    burn_reason=confirm_data.get("burn_reason"),
    confirmed_by_device_fingerprint=confirm_data.get("confirmed_by_device_fingerprint", co_device_fingerprint),
    confirmed_by_device_type=confirm_data.get("confirmed_by_device_type", co_device_type),
    remaining_active_devices=confirm_data.get("remaining_active_devices", 0),
  )


# =====================================================================
# lock_hardware -- permanently bind identity to its single device
# =====================================================================

def lock_hardware(
  credentials: StoredCredentials | None = None,
) -> HardwareLockResult:
  """Permanently lock this identity to its single active hardware device.

  This is an irreversible operation. Once locked:
    - No new devices can be added (add() will raise HardwareLockedError)
    - The existing device cannot be burned (burn() will raise HardwareLockedError)
    - The identity is permanently bound to one physical chip

  Preconditions enforced server-side:
    - Identity must be hardware-tier (sovereign, portable, or virtual)
    - Identity must have exactly 1 active device
    - If already locked, raises IdentityAlreadyLockedError (idempotent-safe)

  Args:
      credentials: Optional pre-loaded credentials. If None, loads from
          the default credentials.json file.

  Returns:
      HardwareLockResult with the lock confirmation details.

  Raises:
      DeclaredTierCannotBeLockedError: Identity is declared-tier (no hardware).
      TooManyActiveDevicesForLockError: Identity has != 1 active device.
      IdentityAlreadyLockedError: Identity is already locked.
      AuthenticationError: Token is invalid or expired.
      NetworkError: Server is unreachable.
  """
  lock_data = _make_authenticated_request(
    "POST",
    "/api/v1/identity/lock-hardware",
    json_body={},
    credentials=credentials,
  )

  from .world import invalidate_world_cache
  invalidate_world_cache()

  return HardwareLockResult(
    identity_internal_id=lock_data.get("identity_internal_id", ""),
    hardware_locked=lock_data.get("hardware_locked", True),
    trust_tier=lock_data.get("trust_tier", ""),
    active_device_count=lock_data.get("active_device_count", 1),
  )
