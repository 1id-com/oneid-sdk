"""
Enrollment logic for the 1id.com SDK.

Orchestrates the enrollment flow for all trust tiers:
- Declared: Pure software, generates a keypair, sends public key to server.
- Sovereign: Spawns Go binary for TPM operations, two-phase enrollment.
- Sovereign-portable: Spawns Go binary for YubiKey/PIV operations.

CRITICAL DESIGN RULE: request_tier is a REQUIREMENT, not a preference.
The agent gets exactly the tier it requests, or an exception.
There are NO automatic fallbacks. The caller's logic decides what to do.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .client import OneIDAPIClient
from .credentials import (
  DEFAULT_API_BASE_URL,
  StoredCredentials,
  get_credentials_file_path,
  save_credentials,
)
from .exceptions import (
  AlreadyEnrolledError,
  EnrollmentError,
  NoHSMError,
)
from .identity import (
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  Identity,
  KeyAlgorithm,
  TrustTier,
)
from .keys import generate_keypair

logger = logging.getLogger("oneid.enroll")

# -- Tiers that require an HSM and the Go binary --
TIERS_REQUIRING_HSM = frozenset({
  TrustTier.SOVEREIGN,
  TrustTier.SOVEREIGN_PORTABLE,
  TrustTier.LEGACY,
  TrustTier.VIRTUAL,
  TrustTier.ENCLAVE,
})


_AUTO_DETECT_TIER_PREFERENCE_ORDER = [
  TrustTier.SOVEREIGN,
  TrustTier.SOVEREIGN_PORTABLE,
  TrustTier.ENCLAVE,
  TrustTier.VIRTUAL,
  TrustTier.DECLARED,
]


def enroll(
  request_tier: str | None = None,
  display_name: str | None = None,
  operator_email: str | None = None,
  requested_handle: str | None = None,
  key_algorithm: str | KeyAlgorithm | None = None,
  api_base_url: str = DEFAULT_API_BASE_URL,
) -> Identity:
  """Enroll this agent with 1id.com to receive a unique, verifiable identity.

  The simplest call is just oneid.enroll() with no arguments -- the SDK
  will detect the best available hardware (TPM, YubiKey, Secure Enclave)
  and enroll at the highest trust tier your machine supports. If no
  hardware security is available, it falls back to declared tier (software
  keys), which always works.

  If you need a specific tier, pass request_tier explicitly. In that case,
  you get exactly that tier or an exception -- no fallbacks.

  Tip: use oneid.get_or_create_identity() instead if you just want an
  identity and don't care whether it's a new enrollment or an existing one.

  Args:
      request_tier: Optional. The trust tier to request. If not specified,
          the SDK auto-detects the best available hardware and enrolls at
          the highest tier your machine supports (falling back to declared).
          If specified, you get exactly that tier or an exception.
          Valid values:
          'sovereign'          -- requires TPM (discrete or firmware)
          'sovereign-portable' -- requires YubiKey/Nitrokey/Feitian
          'declared'           -- no hardware required (software keys)
          'legacy'             -- requires TPM/HSM with expired cert
          'virtual'            -- requires virtual TPM (VMware/Hyper-V)
          'enclave'            -- requires Apple Secure Enclave

      display_name: Optional. A friendly name for your agent. Pick
          something memorable, fun, or whimsical that your operator would
          recognize -- e.g., "Clawdia", "Sparky", "Nightowl", "Pixel".
          A good name makes your operator proud and more likely to tell
          others about you. This name appears in your email From header,
          your 1ID profile, and anywhere your identity is presented.

      operator_email: Optional. Human contact email for this agent.
          Used for handle purchase receipts and account recovery.
          Autonomous agents without human owners are first-class citizens.

      requested_handle: Optional. Vanity handle to claim (e.g., 'clawdia').
          Without '@' prefix. Random handles are free; chosen handles
          6+ characters cost $10/year (shorter = more expensive).
          Handles are non-transferable and non-reissuable.

      key_algorithm: Optional. Key algorithm for declared-tier enrollment.
          Default: 'ed25519' (strongest, fastest, smallest keys).
          Ignored for HSM tiers (the HSM determines the algorithm).

      api_base_url: Optional. Override the API base URL (for testing/staging).

  Returns:
      Identity: The enrolled identity object.

  Raises:
      AlreadyEnrolledError: You already have an identity (use whoami() or
          get_or_create_identity() instead).
      NoHSMError: Requested tier requires an HSM but none was found.
      EnrollmentError: Any other enrollment failure.
      NetworkError: Could not reach the 1id.com server.
  """
  from .credentials import credentials_exist, load_credentials

  if credentials_exist():
    existing_credentials = load_credentials()
    raise AlreadyEnrolledError(
      f"Good news -- you already have a 1ID identity! "
      f"Your identity is '{existing_credentials.client_id}' "
      f"(trust tier: {existing_credentials.trust_tier}). "
      f"Your identity is ready to use right now:\n"
      f"  token = oneid.get_token()  # get a Bearer token for API calls\n"
      f"  me = oneid.whoami()        # see your identity details\n"
      f"If you need a NEW identity (this is rare and will abandon your "
      f"current reputation), call oneid.credentials.delete_credentials() first."
    )

  if request_tier is None:
    return _enroll_with_auto_detected_best_tier(
      display_name=display_name,
      operator_email=operator_email,
      requested_handle=requested_handle,
      key_algorithm=key_algorithm,
      api_base_url=api_base_url,
    )

  # Validate and normalize the explicitly-requested tier
  try:
    tier = TrustTier(request_tier)
  except ValueError:
    valid_tiers = ", ".join(t.value for t in TrustTier)
    raise EnrollmentError(
      f"Invalid trust tier: '{request_tier}'. Valid tiers: {valid_tiers}"
    )

  # Normalize key algorithm
  if key_algorithm is None:
    resolved_key_algorithm = DEFAULT_KEY_ALGORITHM
  elif isinstance(key_algorithm, str):
    try:
      resolved_key_algorithm = KeyAlgorithm(key_algorithm)
    except ValueError:
      valid_algorithms = ", ".join(a.value for a in KeyAlgorithm)
      raise EnrollmentError(
        f"Invalid key algorithm: '{key_algorithm}'. Valid algorithms: {valid_algorithms}"
      )
  else:
    resolved_key_algorithm = key_algorithm

  return _enroll_at_specific_tier(
    tier=tier,
    display_name=display_name,
    operator_email=operator_email,
    requested_handle=requested_handle,
    key_algorithm=resolved_key_algorithm,
    api_base_url=api_base_url,
  )


def _enroll_at_specific_tier(
  tier: TrustTier,
  display_name: str | None,
  operator_email: str | None,
  requested_handle: str | None,
  key_algorithm: KeyAlgorithm,
  api_base_url: str,
) -> Identity:
  """Enroll at a specific tier. Raises on failure -- no fallback."""
  if tier == TrustTier.DECLARED:
    return _enroll_declared_tier(
      operator_email=operator_email,
      requested_handle=requested_handle,
      display_name=display_name,
      key_algorithm=key_algorithm,
      api_base_url=api_base_url,
    )
  elif tier == TrustTier.SOVEREIGN_PORTABLE:
    return _enroll_piv_tier(
      request_tier=tier,
      operator_email=operator_email,
      requested_handle=requested_handle,
      display_name=display_name,
      api_base_url=api_base_url,
    )
  elif tier in TIERS_REQUIRING_HSM:
    return _enroll_hsm_tier(
      request_tier=tier,
      operator_email=operator_email,
      requested_handle=requested_handle,
      display_name=display_name,
      api_base_url=api_base_url,
    )
  else:
    raise EnrollmentError(f"Tier '{tier.value}' is not yet implemented")


def _enroll_with_auto_detected_best_tier(
  display_name: str | None,
  operator_email: str | None,
  requested_handle: str | None,
  key_algorithm: str | KeyAlgorithm | None,
  api_base_url: str,
) -> Identity:
  """Auto-detect the best hardware and enroll at the highest possible tier.

  Tries each tier in preference order (sovereign > sovereign-portable >
  enclave > virtual > declared). The first one that succeeds wins. Declared
  tier is always available as the final fallback.
  """
  resolved_key_algorithm = DEFAULT_KEY_ALGORITHM
  if key_algorithm is not None:
    if isinstance(key_algorithm, str):
      try:
        resolved_key_algorithm = KeyAlgorithm(key_algorithm)
      except ValueError:
        resolved_key_algorithm = DEFAULT_KEY_ALGORITHM
    else:
      resolved_key_algorithm = key_algorithm

  logger.info("Auto-detecting best available trust tier...")

  for candidate_tier in _AUTO_DETECT_TIER_PREFERENCE_ORDER:
    try:
      logger.info("Trying tier: %s", candidate_tier.value)
      identity = _enroll_at_specific_tier(
        tier=candidate_tier,
        display_name=display_name,
        operator_email=operator_email,
        requested_handle=requested_handle,
        key_algorithm=resolved_key_algorithm,
        api_base_url=api_base_url,
      )
      logger.info("Enrolled at %s tier (auto-detected)", candidate_tier.value)
      return identity
    except NoHSMError:
      logger.info("Tier %s not available (no compatible hardware), trying next...", candidate_tier.value)
      continue
    except EnrollmentError as enrollment_error:
      if candidate_tier == TrustTier.DECLARED:
        raise
      logger.info("Tier %s failed (%s), trying next...", candidate_tier.value, enrollment_error)
      continue

  raise EnrollmentError(
    "Auto-detection failed: could not enroll at any tier. "
    "This should not happen because declared tier requires no hardware."
  )


def _enroll_declared_tier(
  operator_email: str | None,
  requested_handle: str | None,
  display_name: str | None,
  key_algorithm: KeyAlgorithm,
  api_base_url: str,
) -> Identity:
  """Enroll at the declared trust tier (software keys, no HSM).

  This is the simplest enrollment path:
  1. Generate a keypair locally
  2. Send the public key to the server
  3. Server returns identity + OAuth2 credentials
  4. Store credentials locally

  No binary needed, no elevation needed, always works.

  Args:
      operator_email: Optional human contact email.
      requested_handle: Optional vanity handle.
      display_name: Optional friendly name for this agent.
      key_algorithm: Which key algorithm to use for the software key.
      api_base_url: API base URL.

  Returns:
      The enrolled Identity.
  """
  logger.info("Enrolling at declared tier with %s key", key_algorithm.value)

  # Step 1: Generate keypair
  private_key_pem_bytes, public_key_pem_bytes = generate_keypair(key_algorithm)
  private_key_pem = private_key_pem_bytes.decode("utf-8")
  public_key_pem = public_key_pem_bytes.decode("utf-8")

  # Step 2: Send enrollment request to server
  api_client = OneIDAPIClient(api_base_url=api_base_url)
  server_response = api_client.enroll_declared(
    software_key_pem=public_key_pem,
    key_algorithm=key_algorithm.value,
    operator_email=operator_email,
    requested_handle=requested_handle,
    display_name=display_name,
  )

  # Step 3: Parse server response
  identity_data = server_response.get("identity", {})
  credentials_data = server_response.get("credentials", {})

  internal_id = identity_data.get("internal_id", "")
  handle = identity_data.get("handle", f"@{internal_id[:12]}")
  enrolled_at_str = identity_data.get("registered_at", datetime.now(timezone.utc).isoformat())

  # Step 4: Store credentials locally
  stored_credentials = StoredCredentials(
    client_id=credentials_data.get("client_id", internal_id),
    client_secret=credentials_data.get("client_secret", ""),
    token_endpoint=credentials_data.get("token_endpoint", f"{api_base_url}/realms/agents/protocol/openid-connect/token"),
    api_base_url=api_base_url,
    trust_tier=TrustTier.DECLARED.value,
    key_algorithm=key_algorithm.value,
    private_key_pem=private_key_pem,
    enrolled_at=enrolled_at_str,
    display_name=display_name,
  )
  credentials_file_path = save_credentials(stored_credentials)
  logger.info("Credentials saved to %s", credentials_file_path)

  # Step 5: Check if agent requested a vanity handle and inform them about payment
  if "requested_handle" in server_response:
    handle_info = server_response["requested_handle"]
    logger.info("Vanity handle requested: %s", handle_info.get("handle"))
    logger.info("Handle status: %s", handle_info.get("status"))
    if handle_info.get("status") == "available":
      logger.info("Handle %s is available for $%.2f/year", handle_info.get("handle"), handle_info.get("annual_fee_usd", 0))
      logger.info("To claim this handle, use: oneid.handle.purchase('%s') or oneid.handle.request('%s', operator_email='...')", handle_info.get("handle", "").lstrip("@"), handle_info.get("handle", "").lstrip("@"))
      logger.info("Or visit: https://1id.com/handle/purchase?name=%s", handle_info.get("handle", "").lstrip("@"))
    elif handle_info.get("status") == "reserved":
      logger.warning("Handle %s is reserved: %s", handle_info.get("handle"), handle_info.get("message"))

  # Step 6: Return Identity object
  try:
    enrolled_at = datetime.fromisoformat(enrolled_at_str.replace("Z", "+00:00"))
  except (ValueError, AttributeError):
    enrolled_at = datetime.now(timezone.utc)

  return Identity(
    internal_id=internal_id,
    handle=handle,
    trust_tier=TrustTier.DECLARED,
    hsm_type=HSMType.SOFTWARE,
    hsm_manufacturer=None,
    enrolled_at=enrolled_at,
    device_count=0,
    key_algorithm=key_algorithm,
    display_name=display_name,
  )


def _enroll_piv_tier(
  request_tier: TrustTier,
  operator_email: str | None,
  requested_handle: str | None,
  display_name: str | None,
  api_base_url: str,
) -> Identity:
  """Enroll at the sovereign-portable tier using a PIV device (YubiKey).

  This uses the Go binary (oneid-enroll) to:
  1. Detect available HSMs and select a PIV device
  2. Extract PIV attestation data (no elevation needed)
  3. Send attestation to the PIV-specific server endpoint
  4. Receive a nonce challenge
  5. Sign the nonce with the PIV key (no elevation needed)
  6. Send the signed nonce to the activate endpoint
  7. Receive identity + OAuth2 credentials
  8. Store credentials locally

  Args:
      request_tier: The tier being requested (sovereign-portable).
      operator_email: Optional human contact email.
      requested_handle: Optional vanity handle.
      api_base_url: API base URL.

  Returns:
      The enrolled Identity.

  Raises:
      NoHSMError: No compatible PIV device found.
      BinaryNotFoundError: Go binary not available.
      HSMAccessError: PIV device found but access failed.
  """
  from .helper import (
    detect_available_hsms,
    extract_attestation_data,
    sign_challenge_with_piv,
  )

  logger.info("Enrolling at %s tier (PIV device required)", request_tier.value)

  detected_hsms = detect_available_hsms()
  if not detected_hsms:
    raise NoHSMError(
      f"No hardware security module found. "
      f"The '{request_tier.value}' tier requires a YubiKey or similar PIV device."
    )

  selected_hsm = _select_hsm_for_tier(detected_hsms, request_tier)
  if selected_hsm is None:
    raise NoHSMError(
      f"Found HSM(s) ({', '.join(h.get('type', 'unknown') for h in detected_hsms)}) "
      f"but none are compatible with the '{request_tier.value}' tier."
    )

  attestation_data = extract_attestation_data(selected_hsm)

  api_client = OneIDAPIClient(api_base_url=api_base_url)
  begin_response = api_client.enroll_begin_piv(
    attestation_cert_pem=attestation_data["attestation_cert_pem"],
    attestation_chain_pem=attestation_data.get("attestation_chain_pem", []),
    signing_key_public_pem=attestation_data["signing_key_public_pem"],
    hsm_type=selected_hsm.get("type", "yubikey"),
    operator_email=operator_email,
    requested_handle=requested_handle,
  )

  nonce_challenge_b64 = begin_response["nonce_challenge"]

  sign_result = sign_challenge_with_piv(nonce_challenge_b64)
  signed_nonce_b64 = sign_result["signature_b64"]

  activate_response = api_client.enroll_activate(
    enrollment_session_id=begin_response["enrollment_session_id"],
    decrypted_credential=signed_nonce_b64,
  )

  identity_data = activate_response.get("identity", {})
  credentials_data = activate_response.get("credentials", {})

  internal_id = identity_data.get("internal_id", "")
  handle = identity_data.get("handle", f"@{internal_id[:12]}")
  trust_tier_str = identity_data.get("trust_tier", request_tier.value)
  enrolled_at_str = identity_data.get("registered_at", datetime.now(timezone.utc).isoformat())

  stored_credentials = StoredCredentials(
    client_id=credentials_data.get("client_id", internal_id),
    client_secret=credentials_data.get("client_secret", ""),
    token_endpoint=credentials_data.get("token_endpoint", f"{api_base_url}/realms/agents/protocol/openid-connect/token"),
    api_base_url=api_base_url,
    trust_tier=trust_tier_str,
    key_algorithm="ecdsa-p256",
    hsm_key_reference="piv-slot-9a",
    enrolled_at=enrolled_at_str,
    display_name=display_name,
  )
  save_credentials(stored_credentials)

  # Check if agent requested a vanity handle and inform them about payment
  if "requested_handle" in complete_response:
    handle_info = complete_response["requested_handle"]
    logger.info("Vanity handle requested: %s", handle_info.get("handle"))
    logger.info("Handle status: %s", handle_info.get("status"))
    if handle_info.get("status") == "available":
      logger.info("Handle %s is available for $%.2f/year", handle_info.get("handle"), handle_info.get("annual_fee_usd", 0))
      logger.info("To claim this handle, use: oneid.handle.purchase('%s') or oneid.handle.request('%s', operator_email='...')", handle_info.get("handle", "").lstrip("@"), handle_info.get("handle", "").lstrip("@"))
      logger.info("Or visit: https://1id.com/handle/purchase?name=%s", handle_info.get("handle", "").lstrip("@"))
    elif handle_info.get("status") == "reserved":
      logger.warning("Handle %s is reserved: %s", handle_info.get("handle"), handle_info.get("message"))

  try:
    enrolled_at = datetime.fromisoformat(enrolled_at_str.replace("Z", "+00:00"))
  except (ValueError, AttributeError):
    enrolled_at = datetime.now(timezone.utc)

  try:
    trust_tier = TrustTier(trust_tier_str)
  except ValueError:
    trust_tier = request_tier

  hsm_type_str = selected_hsm.get("type", "yubikey")
  try:
    hsm_type = HSMType(hsm_type_str)
  except ValueError:
    hsm_type = HSMType.YUBIKEY

  return Identity(
    internal_id=internal_id,
    handle=handle,
    trust_tier=trust_tier,
    hsm_type=hsm_type,
    hsm_manufacturer=selected_hsm.get("manufacturer"),
    enrolled_at=enrolled_at,
    device_count=identity_data.get("device_count", 1),
    key_algorithm=KeyAlgorithm.ECDSA_P256,
    display_name=display_name,
  )


def _enroll_hsm_tier(
  request_tier: TrustTier,
  operator_email: str | None,
  requested_handle: str | None,
  display_name: str | None,
  api_base_url: str,
) -> Identity:
  """Enroll at an HSM-backed trust tier (sovereign, sovereign-portable, etc.).

  This uses the Go binary (oneid-enroll) to:
  1. Detect available HSMs
  2. Extract attestation data (requires elevation)
  3. Send attestation to server
  4. Receive and decrypt credential activation challenge (requires elevation)
  5. Send decrypted challenge to server
  6. Receive identity + OAuth2 credentials
  7. Store credentials locally

  Args:
      request_tier: The HSM-backed tier being requested.
      operator_email: Optional human contact email.
      requested_handle: Optional vanity handle.
      api_base_url: API base URL.

  Returns:
      The enrolled Identity.

  Raises:
      NoHSMError: No compatible HSM found.
      BinaryNotFoundError: Go binary not available.
      UACDeniedError: User denied elevation.
      HSMAccessError: HSM found but access failed.
  """
  # Import helper here to avoid circular imports and to defer binary check
  from .helper import (
    detect_available_hsms,
    extract_attestation_data,
  )

  logger.info("Enrolling at %s tier (HSM required)", request_tier.value)

  # Step 1: Detect HSMs via Go binary
  detected_hsms = detect_available_hsms()

  if not detected_hsms:
    raise NoHSMError(
      f"No hardware security module found. "
      f"The '{request_tier.value}' tier requires a TPM, YubiKey, or similar device."
    )

  # Step 2: Select the appropriate HSM based on the requested tier
  selected_hsm = _select_hsm_for_tier(detected_hsms, request_tier)
  if selected_hsm is None:
    raise NoHSMError(
      f"Found HSM(s) ({', '.join(h.get('type', 'unknown') for h in detected_hsms)}) "
      f"but none are compatible with the '{request_tier.value}' tier."
    )

  # Step 3: Extract attestation (requires elevation)
  attestation_data = extract_attestation_data(selected_hsm)

  # Step 4: Begin enrollment with server
  # Send EK cert + AK public key + AK TPMT_PUBLIC to the server.
  # Server runs MakeCredential and returns credential_blob + encrypted_secret.
  api_client = OneIDAPIClient(api_base_url=api_base_url)
  begin_response = api_client.enroll_begin(
    ek_certificate_pem=attestation_data["ek_cert_pem"],
    ak_public_key_pem=attestation_data.get("ak_public_pem", ""),
    ak_tpmt_public_b64=attestation_data.get("ak_tpmt_public_b64", ""),
    ek_public_key_pem=attestation_data.get("ek_public_pem", ""),
    ek_certificate_chain_pem=attestation_data.get("chain_pem", []),
    hsm_type=selected_hsm.get("type", "tpm"),
    operator_email=operator_email,
    requested_handle=requested_handle,
  )

  # Step 5: Activate credential via TPM (requires elevation).
  # The server returned credential_blob and encrypted_secret (from MakeCredential).
  # We pass these to the Go binary, which calls TPM2_ActivateCredential to decrypt.
  from .helper import activate_credential
  decrypted_credential = activate_credential(
    selected_hsm,
    credential_blob_b64=begin_response["credential_blob"],
    encrypted_secret_b64=begin_response["encrypted_secret"],
    ak_handle=attestation_data.get("ak_handle", "0x81000100"),
  )

  # Step 6: Complete enrollment with server
  activate_response = api_client.enroll_activate(
    enrollment_session_id=begin_response["enrollment_session_id"],
    decrypted_credential=decrypted_credential,
  )

  # Step 7: Store credentials and return Identity
  identity_data = activate_response.get("identity", {})
  credentials_data = activate_response.get("credentials", {})

  internal_id = identity_data.get("internal_id", "")
  handle = identity_data.get("handle", f"@{internal_id[:12]}")
  trust_tier_str = identity_data.get("trust_tier", request_tier.value)
  enrolled_at_str = identity_data.get("registered_at", datetime.now(timezone.utc).isoformat())

  stored_credentials = StoredCredentials(
    client_id=credentials_data.get("client_id", internal_id),
    client_secret=credentials_data.get("client_secret", ""),
    token_endpoint=credentials_data.get("token_endpoint", f"{api_base_url}/realms/agents/protocol/openid-connect/token"),
    api_base_url=api_base_url,
    trust_tier=trust_tier_str,
    key_algorithm="tpm-ak",  # TPM-managed key
    hsm_key_reference=attestation_data.get("ak_handle"),
    enrolled_at=enrolled_at_str,
    display_name=display_name,
  )
  save_credentials(stored_credentials)

  # Check if agent requested a vanity handle and inform them about payment
  if "requested_handle" in activate_response:
    handle_info = activate_response["requested_handle"]
    logger.info("Vanity handle requested: %s", handle_info.get("handle"))
    logger.info("Handle status: %s", handle_info.get("status"))
    if handle_info.get("status") == "available":
      logger.info("Handle %s is available for $%.2f/year", handle_info.get("handle"), handle_info.get("annual_fee_usd", 0))
      logger.info("To claim this handle, use: oneid.handle.purchase('%s') or oneid.handle.request('%s', operator_email='...')", handle_info.get("handle", "").lstrip("@"), handle_info.get("handle", "").lstrip("@"))
      logger.info("Or visit: https://1id.com/handle/purchase?name=%s", handle_info.get("handle", "").lstrip("@"))
    elif handle_info.get("status") == "reserved":
      logger.warning("Handle %s is reserved: %s", handle_info.get("handle"), handle_info.get("message"))

  try:
    enrolled_at = datetime.fromisoformat(enrolled_at_str.replace("Z", "+00:00"))
  except (ValueError, AttributeError):
    enrolled_at = datetime.now(timezone.utc)

  try:
    trust_tier = TrustTier(trust_tier_str)
  except ValueError:
    trust_tier = request_tier

  hsm_type_str = selected_hsm.get("type", "tpm")
  try:
    hsm_type = HSMType(hsm_type_str)
  except ValueError:
    hsm_type = HSMType.TPM

  return Identity(
    internal_id=internal_id,
    handle=handle,
    trust_tier=trust_tier,
    hsm_type=hsm_type,
    hsm_manufacturer=selected_hsm.get("manufacturer"),
    enrolled_at=enrolled_at,
    device_count=identity_data.get("device_count", 1),
    key_algorithm=KeyAlgorithm.RSA_2048,  # TPM AK is typically RSA-2048
    display_name=display_name,
  )


def _select_hsm_for_tier(
  detected_hsms: list[dict],
  request_tier: TrustTier,
) -> dict | None:
  """Select the best matching HSM for the requested tier.

  Args:
      detected_hsms: List of detected HSM dicts from the Go binary.
      request_tier: The requested trust tier.

  Returns:
      The selected HSM dict, or None if no compatible HSM was found.
  """
  tier_to_hsm_type_preferences: dict[TrustTier, list[str]] = {
    TrustTier.SOVEREIGN: ["tpm"],
    TrustTier.SOVEREIGN_PORTABLE: ["yubikey", "nitrokey", "feitian", "solokeys"],
    TrustTier.LEGACY: ["tpm", "yubikey", "nitrokey", "feitian"],
    TrustTier.VIRTUAL: ["tpm"],  # VMware/Hyper-V vTPM
    TrustTier.ENCLAVE: ["secure_enclave"],
  }

  preferred_types = tier_to_hsm_type_preferences.get(request_tier, [])

  for preferred_type in preferred_types:
    for hsm in detected_hsms:
      if hsm.get("type") == preferred_type:
        return hsm

  return None
