"""
Go binary helper for the 1id.com SDK.

Manages the oneid-enroll Go binary:
- Locates the binary (cached or PATH)
- Downloads it from 1id.com if not present
- Spawns it for HSM operations (detect, extract, activate)
- Parses JSON output

The binary handles all platform-specific HSM operations:
- TPM access (Windows TBS.dll, Linux /dev/tpm*)
- YubiKey/PIV access (PCSC)
- Privilege elevation (UAC, sudo, pkexec)

The SDK communicates with the binary via JSON on stdin/stdout.

SESSION MODE:
For enrollment flows that require multiple elevated operations (extract + activate),
the SDK uses "session mode" to avoid multiple UAC prompts. A single elevated process
stays alive and accepts commands over a TCP socket (Windows) or stdin/stdout (Linux/macOS).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from .exceptions import (
  BinaryNotFoundError,
  HSMAccessError,
  NoHSMError,
  TPMSetupRequiredError,
  UACDeniedError,
)

# -- GitHub release URL for auto-download --
GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE = (
  "https://github.com/1id-com/oneid-enroll/releases/latest/download/{binary_name}"
)

logger = logging.getLogger("oneid.helper")

# -- Binary naming convention --
BINARY_NAME_PREFIX = "oneid-enroll"
BINARY_VERSION = "1.0.2"

# -- Download URLs --
BINARY_DOWNLOAD_BASE_URL = "https://github.com/1id-com/oneid-enroll/releases/latest"


def _get_platform_binary_name() -> str:
  """Return the platform-specific binary filename.

  Returns:
      Binary filename like 'oneid-enroll-windows-amd64.exe' or
      'oneid-enroll-linux-amd64'.
  """
  system = platform.system().lower()
  machine = platform.machine().lower()

  # Normalize architecture names
  if machine in ("x86_64", "amd64"):
    arch = "amd64"
  elif machine in ("aarch64", "arm64"):
    arch = "arm64"
  else:
    arch = machine

  # Normalize OS names
  if system == "windows":
    return f"{BINARY_NAME_PREFIX}-windows-{arch}.exe"
  elif system == "darwin":
    return f"{BINARY_NAME_PREFIX}-darwin-{arch}"
  else:
    return f"{BINARY_NAME_PREFIX}-linux-{arch}"


def _get_binary_cache_directory() -> Path:
  """Return the directory where downloaded binaries are cached.

  Returns:
      Path to ~/.oneid/bin/ (created if needed).
  """
  if platform.system() == "Windows":
    base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
  else:
    base = Path.home() / ".local" / "share"

  cache_dir = base / "oneid" / "bin"
  return cache_dir


def find_binary() -> Path | None:
  """Locate the oneid-enroll binary.

  Search order:
  1. Binary cache directory (~/.oneid/bin/ or %APPDATA%/oneid/bin/)
  2. Current working directory
  3. System PATH
  4. SDK package directory (for development)

  Returns:
      Path to the binary if found, None otherwise.
  """
  binary_name = _get_platform_binary_name()

  # 1. Check cache directory
  cache_dir = _get_binary_cache_directory()
  cached_binary = cache_dir / binary_name
  if cached_binary.exists() and os.access(str(cached_binary), os.X_OK):
    return cached_binary

  # 2. Check current working directory
  local_binary = Path.cwd() / binary_name
  if local_binary.exists() and os.access(str(local_binary), os.X_OK):
    return local_binary

  # Also check for the generic name (e.g., just 'oneid-enroll' or 'oneid-enroll.exe')
  generic_name = BINARY_NAME_PREFIX
  if platform.system() == "Windows":
    generic_name += ".exe"
  local_generic = Path.cwd() / generic_name
  if local_generic.exists() and os.access(str(local_generic), os.X_OK):
    return local_generic

  # 3. Check PATH
  import shutil
  path_binary = shutil.which(binary_name) or shutil.which(generic_name)
  if path_binary:
    return Path(path_binary)

  return None


# Publisher identity of the release binaries (AUD-F07). Windows: the Authenticode
# signer certificate's organisation; macOS: the Apple Developer ID team.
EXPECTED_WINDOWS_AUTHENTICODE_SIGNER_ORGANIZATION = "O=Aura Friday"
EXPECTED_APPLE_DEVELOPER_ID_TEAM_IDENTIFIER = "XQYBH3CT45"


def _verify_publisher_code_signature_of_downloaded_release_asset(asset_path: Path, asset_name: str) -> None:
  """Require a valid publisher code signature on a downloaded helper (Windows:
  Authenticode by EXPECTED_WINDOWS_AUTHENTICODE_SIGNER_ORGANIZATION; macOS:
  Developer ID of EXPECTED_APPLE_DEVELOPER_ID_TEAM_IDENTIFIER). Linux binaries
  are not code-signed; their SHA-256 check is the only one. Needs no elevation.

  Raises:
      BinaryNotFoundError: the signature is missing, invalid, or not ours.
  """
  system_name = platform.system()
  if system_name == "Windows":
    powershell_script = (
      "$s = Get-AuthenticodeSignature -LiteralPath $env:ONEID_HELPER_TO_VERIFY; "
      "$s.Status.ToString() + '|' + $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' })"
    )
    try:
      completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell_script],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "ONEID_HELPER_TO_VERIFY": str(asset_path)},
      )
    except (OSError, subprocess.TimeoutExpired) as powershell_error:
      raise BinaryNotFoundError(
        f"Could not check the Authenticode signature of {asset_name}: {powershell_error}"
      ) from powershell_error
    status_text, _, signer_subject = completed.stdout.strip().partition("|")
    if status_text != "Valid" or EXPECTED_WINDOWS_AUTHENTICODE_SIGNER_ORGANIZATION not in signer_subject:
      raise BinaryNotFoundError(
        f"{asset_name} is not validly signed by {EXPECTED_WINDOWS_AUTHENTICODE_SIGNER_ORGANIZATION} "
        f"(Authenticode status {status_text or 'unknown'}, signer '{signer_subject}'); refusing to install it."
      )
    logger.info("Authenticode signature verified for %s (%s)", asset_name, signer_subject)
  elif system_name == "Darwin":
    verify_run = subprocess.run(["codesign", "--verify", "--strict", str(asset_path)],
                                capture_output=True, text=True, timeout=60)
    describe_run = subprocess.run(["codesign", "-dv", "--verbose=2", str(asset_path)],
                                  capture_output=True, text=True, timeout=60)
    team_line = f"TeamIdentifier={EXPECTED_APPLE_DEVELOPER_ID_TEAM_IDENTIFIER}"
    if verify_run.returncode != 0 or team_line not in (describe_run.stdout + describe_run.stderr):
      raise BinaryNotFoundError(
        f"{asset_name} is not validly signed by Apple Developer ID team "
        f"{EXPECTED_APPLE_DEVELOPER_ID_TEAM_IDENTIFIER}; refusing to install it. "
        f"{verify_run.stderr.strip()[:200]}"
      )
    logger.info("Developer ID signature verified for %s (team %s)", asset_name,
                EXPECTED_APPLE_DEVELOPER_ID_TEAM_IDENTIFIER)
  else:
    logger.info("%s: no platform code signature on Linux; SHA-256 verified only", asset_name)


def _download_binary_from_github_release(binary_name: str, destination_path: Path) -> Path:
  """Download the oneid-enroll binary from the GitHub 'latest' release.

  Downloads to a temporary file first, verifies the SHA-256 checksum
  against the published .sha256 file, then moves to the final location.
  Sets the executable permission on non-Windows platforms.

  Args:
      binary_name: Platform-specific binary filename (e.g. 'oneid-enroll-linux-amd64').
      destination_path: Full path where the binary should be saved.

  Returns:
      Path to the downloaded binary.

  Raises:
      BinaryNotFoundError: If the download or checksum verification fails.
  """
  import hashlib
  import tempfile
  import urllib.request
  import urllib.error

  binary_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.format(binary_name=binary_name)
  checksum_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.format(binary_name=binary_name + ".sha256")

  logger.info("Downloading oneid-enroll binary from %s ...", binary_download_url)

  # Step 1: Download the binary to a temporary file
  temp_file_path = None
  try:
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    # Download binary
    temp_fd, temp_file_path_str = tempfile.mkstemp(
      prefix="oneid-enroll-download-",
      dir=str(destination_path.parent),
    )
    temp_file_path = Path(temp_file_path_str)
    os.close(temp_fd)

    urllib.request.urlretrieve(binary_download_url, str(temp_file_path))
    downloaded_size_bytes = temp_file_path.stat().st_size
    logger.info("Downloaded %d bytes to %s", downloaded_size_bytes, temp_file_path)

    if downloaded_size_bytes < 100_000:
      # Sanity check -- Go binaries are always > 1MB
      raise BinaryNotFoundError(
        f"Downloaded binary is suspiciously small ({downloaded_size_bytes} bytes). "
        f"The download URL may be incorrect or the release may be empty."
      )

    # Step 2: Download and verify SHA-256 checksum
    try:
      checksum_response = urllib.request.urlopen(checksum_download_url)
      checksum_line = checksum_response.read().decode("utf-8").strip()
      # Format: "hash  filename" (two spaces between hash and filename)
      expected_sha256_hash = checksum_line.split()[0].lower()

      # Compute actual hash
      sha256_hasher = hashlib.sha256()
      with open(temp_file_path, "rb") as binary_file_for_hashing:
        while True:
          chunk = binary_file_for_hashing.read(8192)
          if not chunk:
            break
          sha256_hasher.update(chunk)
      actual_sha256_hash = sha256_hasher.hexdigest().lower()

      if actual_sha256_hash != expected_sha256_hash:
        raise BinaryNotFoundError(
          f"SHA-256 checksum mismatch for {binary_name}. "
          f"Expected: {expected_sha256_hash}, got: {actual_sha256_hash}. "
          f"The binary may have been tampered with or the download was corrupted."
        )
      logger.info("SHA-256 checksum verified: %s", actual_sha256_hash)

    except urllib.error.URLError as checksum_error:
      # AUD-F07: never install a helper whose integrity could not be checked.
      raise BinaryNotFoundError(
        f"Could not download the checksum for {binary_name} ({checksum_error}); "
        f"refusing to install an unverified helper."
      ) from checksum_error

    # Step 2b: the checksum comes from the same release as the binary, so also
    # require the publisher's code signature where the platform has one.
    _verify_publisher_code_signature_of_downloaded_release_asset(temp_file_path, binary_name)

    # Step 3: Move temp file to final destination
    # On Windows, we may need to remove the destination first
    if destination_path.exists():
      destination_path.unlink()
    temp_file_path.rename(destination_path)
    temp_file_path = None  # prevent cleanup from deleting it

    # Step 4: Set executable permission on non-Windows platforms
    if platform.system() != "Windows":
      destination_path.chmod(destination_path.stat().st_mode | 0o755)

    logger.info("Binary installed to %s", destination_path)
    return destination_path

  except BinaryNotFoundError:
    raise
  except urllib.error.HTTPError as http_error:
    raise BinaryNotFoundError(
      f"Failed to download {binary_name} from GitHub release: "
      f"HTTP {http_error.code} {http_error.reason}. "
      f"URL: {binary_download_url}"
    ) from http_error
  except urllib.error.URLError as url_error:
    raise BinaryNotFoundError(
      f"Failed to download {binary_name}: {url_error.reason}. "
      f"Check your internet connection."
    ) from url_error
  except Exception as unexpected_error:
    raise BinaryNotFoundError(
      f"Unexpected error downloading {binary_name}: {unexpected_error}"
    ) from unexpected_error
  finally:
    # Clean up temp file if it still exists (download or verification failed)
    if temp_file_path and temp_file_path.exists():
      try:
        temp_file_path.unlink()
      except Exception:
        pass


# 2.2.0: `sign` hashes inputs over 1024 bytes with a TPM hash sequence, which
# every sender-constrained request (RFC 9421 signature base, OWN-038) needs;
# 2.1.0 was the corrected enrollment proof (review 072 #1).
MINIMUM_ONEID_ENROLL_HELPER_VERSION = (2, 2, 0)
_helper_versions_already_checked: dict = {}


def _parse_version_triple(version_text) -> tuple:
  try:
    return tuple(int(part) for part in str(version_text).strip().lstrip("v").split(".")[:3])
  except ValueError:
    return (0, 0, 0)


def _helper_binary_meets_minimum_version(binary_path: Path) -> bool:
  """Run `oneid-enroll version --json` once per (path, mtime) and compare
  with MINIMUM_ONEID_ENROLL_HELPER_VERSION (OWN-026: a stale cached helper
  must not be used just because it exists)."""
  try:
    cache_key = (str(binary_path), binary_path.stat().st_mtime)
  except OSError:
    return False
  if cache_key not in _helper_versions_already_checked:
    import json as _json
    reported_version = None
    try:
      completed = subprocess.run([str(binary_path), "version", "--json"], capture_output=True,
                                 text=True, timeout=15)
      reported_version = _json.loads(completed.stdout[completed.stdout.index("{"):]).get("version")
    except Exception:
      reported_version = None
    _helper_versions_already_checked[cache_key] = (
      _parse_version_triple(reported_version) >= MINIMUM_ONEID_ENROLL_HELPER_VERSION)
  return _helper_versions_already_checked[cache_key]


def ensure_binary_available() -> Path:
  """Ensure the oneid-enroll binary is available, downloading if needed.

  Search order:
  1. Local cache, current directory, PATH (via find_binary())
  2. Auto-download from GitHub releases to the cache directory

  Returns:
      Path to the available binary.

  Raises:
      BinaryNotFoundError: If the binary cannot be found or downloaded.
  """
  binary_path = find_binary()
  if binary_path is not None and _helper_binary_meets_minimum_version(binary_path):
    return binary_path

  # Missing or older than MINIMUM_ONEID_ENROLL_HELPER_VERSION -- download the
  # current release into the cache (replacing a stale cached copy).
  binary_name = _get_platform_binary_name()
  cache_dir = _get_binary_cache_directory()
  destination = cache_dir / binary_name

  logger.info(
    "oneid-enroll binary %s. Attempting auto-download from GitHub release...",
    "not found locally" if binary_path is None else
    f"at {binary_path} is older than {'.'.join(map(str, MINIMUM_ONEID_ENROLL_HELPER_VERSION))}",
  )

  try:
    return _download_binary_from_github_release(binary_name, destination)
  except BinaryNotFoundError as download_error:
    # Re-raise with additional help text
    raise BinaryNotFoundError(
      f"oneid-enroll binary not found in cache, current directory, or PATH, "
      f"and auto-download failed: {download_error}. "
      f"Expected filename: {binary_name}. "
      f"Manual download: https://github.com/1id-com/oneid-enroll/releases/latest"
    ) from download_error


def _run_binary_command(
  command: str,
  args: list[str] | None = None,
  json_mode: bool = True,
  timeout_seconds: float = 30.0,
) -> dict:
  """Run an oneid-enroll command and parse its JSON output.

  Args:
      command: The subcommand to run (e.g., 'detect', 'extract', 'activate').
      args: Additional command-line arguments.
      json_mode: If True, add --json flag and parse JSON stdout.
      timeout_seconds: Maximum time to wait for the command to complete.

  Returns:
      Parsed JSON output from the binary.

  Raises:
      BinaryNotFoundError: If the binary is not available.
      NoHSMError: If the binary reports no HSM found.
      UACDeniedError: If the user denied elevation.
      HSMAccessError: If the binary reports an HSM access error.
  """
  binary_path = ensure_binary_available()

  cmd = [str(binary_path), command]
  if json_mode:
    cmd.append("--json")
  if args:
    cmd.extend(args)

  logger.debug("Running: %s", " ".join(cmd))

  try:
    result = subprocess.run(
      cmd,
      capture_output=True,
      text=True,
      timeout=timeout_seconds,
    )
  except subprocess.TimeoutExpired:
    raise HSMAccessError(
      f"oneid-enroll '{command}' timed out after {timeout_seconds}s"
    )
  except FileNotFoundError:
    raise BinaryNotFoundError(
      f"Could not execute {binary_path}: file not found"
    )
  except PermissionError:
    raise BinaryNotFoundError(
      f"Could not execute {binary_path}: permission denied"
    )

  # Parse JSON output
  if json_mode and result.stdout.strip():
    try:
      output = json.loads(result.stdout)
    except json.JSONDecodeError as json_error:
      logger.error("Invalid JSON from binary: %s", result.stdout[:500])
      raise HSMAccessError(
        f"oneid-enroll returned invalid JSON: {json_error}"
      ) from json_error
  else:
    output = {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}

  # Check for error responses
  if result.returncode != 0:
    error_code = output.get("error_code", "UNKNOWN")
    error_message = output.get("error", result.stderr.strip() or f"Exit code {result.returncode}")

    if error_code == "TBS_ACCESS_DENIED" or error_code == "TBS_ACCESS_NOT_CONFIGURED":
      raise TPMSetupRequiredError(error_message)
    elif error_code == "NO_HSM_FOUND" or "no.*hsm" in error_message.lower() or "no.*tpm" in error_message.lower():
      raise NoHSMError(error_message)
    elif error_code == "UAC_DENIED" or "denied" in error_message.lower():
      raise UACDeniedError(error_message)
    elif error_code == "HSM_ACCESS_ERROR":
      raise HSMAccessError(error_message)
    else:
      raise HSMAccessError(f"oneid-enroll '{command}' failed: {error_message}")

  return output


def detect_available_hsms() -> list[dict]:
  # CROSS_IMPL_SYNC: hsm_detect
  # Implementations: py:oneid/helper.py go:internal/piv/detect.go+tpm/detect.go node:src/helper.ts
  """Detect available hardware security modules via the Go binary.

  Runs 'oneid-enroll detect --json' which does NOT require elevation.

  Returns:
      List of detected HSM dicts, each containing:
      - type: 'tpm', 'yubikey', 'nitrokey', etc.
      - manufacturer: Manufacturer code (e.g., 'INTC', 'Yubico')
      - firmware_version: Firmware version string
      - status: 'ready', 'locked', 'error'
      Empty list if no HSMs are found (not an error for detection).
  """
  try:
    output = _run_binary_command("detect")
    return output.get("hsms") or []
  except NoHSMError:
    return []
  except BinaryNotFoundError:
    raise
  except HSMAccessError:
    logger.warning("HSM detection failed, returning empty list")
    return []


def detect_available_signing_capability_tiers() -> dict:
  # CROSS_IMPL_SYNC: tier_detect
  # Implementations: py:oneid/helper.py node:src/helper.ts
  """Detect which signing capability tiers are available on this system.

  The 1id SDK supports three tiers of hardware signing, each with different
  dependency requirements. This function probes all three and reports what
  is available, so callers (and agents) can choose the best available path.

  Tier A -- Go binary (oneid-enroll):
    Handles all HSM types (TPM, PIV, Enclave). Requires the compiled binary.
    Supports --serial/--reader for multi-YubiKey targeting (v1.3.0+).
    Best choice when available.

  Tier B -- Native Python PC/SC for PIV (optional pyscard): multi-YubiKey
    enumeration, serial selection and PIV signing without a subprocess.
    PIV only; TPM and Secure Enclave always use Tier A (the helper). Same
    as the Node SDK (optional 'smartcard' package).

  Tier C -- Software-only:
    No hardware signing. Only software key operations are possible.
    Always available as a baseline. Useful when no HSM is accessible
    (e.g. cloud containers, sandboxed agents).

  Returns:
      Dict with keys:
        - tier_a_go_binary_is_available: bool
        - tier_a_go_binary_version: str or None
        - tier_a_go_binary_path: str or None
        - tier_b_piv_via_pyscard_is_available: bool
        - tier_b_piv_connected_yubikey_count: int (0 if pyscard unavailable)
        - tier_c_software_only_is_available: bool (always True)
        - recommended_piv_tier: "A" | "B" | "C"
        - recommended_tpm_tier: "A" | "C"
  """
  result = {
    "tier_a_go_binary_is_available": False,
    "tier_a_go_binary_version": None,
    "tier_a_go_binary_path": None,
    "tier_b_piv_via_pyscard_is_available": False,
    "tier_b_piv_connected_yubikey_count": 0,
    "tier_c_software_only_is_available": True,
    "recommended_piv_tier": "C",
    "recommended_tpm_tier": "C",
  }

  # Tier A: Go binary check
  try:
    binary_path = find_binary()
    if binary_path is not None:
      version_output = _run_binary_command("version")
      result["tier_a_go_binary_is_available"] = True
      result["tier_a_go_binary_version"] = version_output.get("version")
      result["tier_a_go_binary_path"] = str(binary_path)
      result["recommended_piv_tier"] = "A"
      result["recommended_tpm_tier"] = "A"
  except Exception as go_binary_probe_err:
    logger.debug("Tier A probe failed: %s", go_binary_probe_err)

  # Tier B PIV: pyscard check
  try:
    from smartcard.System import readers as pcsc_list_readers  # noqa: F811
    all_readers = pcsc_list_readers()
    result["tier_b_piv_via_pyscard_is_available"] = True
    # Count YubiKey-like readers specifically
    yubikey_reader_count = sum(
      1 for r in all_readers
      if "yubi" in str(r).lower() or "ccid" in str(r).lower()
    )
    result["tier_b_piv_connected_yubikey_count"] = yubikey_reader_count
    if not result["tier_a_go_binary_is_available"]:
      result["recommended_piv_tier"] = "B"
  except ImportError:
    logger.debug("Tier B PIV: pyscard not installed")
  except Exception as pyscard_probe_err:
    logger.debug("Tier B PIV probe failed: %s", pyscard_probe_err)

  return result


def extract_attestation_data(hsm: dict) -> dict:
  """Extract attestation data from an HSM.

  Runs 'oneid-enroll extract --json --type <hsm_type>'.
  On TPM: CreatePrimary (EK) and CreateLoaded (AK) work without elevation
  on Windows 8+ and all Linux. No UAC/sudo needed.

  For enclave types on macOS, automatically recovers from a hung
  CryptoTokenKit daemon by killing and restarting it, then retrying.

  Args:
      hsm: HSM dict from detect_available_hsms().

  Returns:
      Dict containing:
      - ek_cert_pem: PEM-encoded EK certificate
      - chain_pem: List of PEM-encoded intermediate CA certs (may be empty)
      - ak_public_pem: PEM-encoded AK public key
      - ak_handle: TPM handle reference for the AK
  """
  hsm_type = hsm.get("type", "tpm")
  args = ["--type", hsm_type]

  this_hsm_type_uses_secure_enclave = hsm_type in ("enclave", "secure_enclave")
  for attempt_number in range(2 if this_hsm_type_uses_secure_enclave else 1):
    try:
      return _run_binary_command("extract", args=args)
    except HSMAccessError as extract_error:
      timed_out = "timed out" in str(extract_error).lower()
      if timed_out and attempt_number == 0 and this_hsm_type_uses_secure_enclave:
        logger.warning(
          "Enclave extract timed out -- attempting CryptoTokenKit daemon recovery"
        )
        if _attempt_macos_cryptotokenkit_daemon_recovery():
          logger.info("ctkd daemon restarted -- retrying enclave extract")
          continue
      raise


def activate_credential(
  hsm: dict,
  credential_blob_b64: str,
  encrypted_secret_b64: str,
  ak_handle: str = "",
) -> str:
  """Decrypt a credential activation challenge via the HSM.

  Runs 'oneid-enroll activate --json --credential-blob <b64>
  --encrypted-secret <b64>'. On Windows, the Go binary auto-elevates
  via its internal fallback when TBS blocks ActivateCredential
  (0x80280400). On Linux, no elevation is needed.

  IMPORTANT: For enrollment, prefer ElevatedSession which combines
  extract + activate under a single UAC prompt.

  The AK is recreated on-demand (transient, deterministic -- same key every
  time). If ak_handle is a persistent hex handle (backward compat), it is
  passed via --ak-handle; otherwise the binary recreates the AK internally.

  Args:
      hsm: HSM dict from detect_available_hsms().
      credential_blob_b64: Base64-encoded credential blob from the server.
      encrypted_secret_b64: Base64-encoded encrypted secret from the server.
      ak_handle: Optional. Hex handle for backward compat with persistent AKs.

  Returns:
      Base64-encoded decrypted credential secret.
  """
  activate_args = [
    "--credential-blob", credential_blob_b64,
    "--encrypted-secret", encrypted_secret_b64,
  ]
  if ak_handle and ak_handle != "transient":
    activate_args.extend(["--ak-handle", ak_handle])
  output = _run_binary_command("activate", args=activate_args, timeout_seconds=120.0)
  return output.get("decrypted_credential", "")


def import_and_certify_wrapped_object_with_tpm(
  wrapped_object_public_b64: str,
  wrapped_object_duplicate_b64: str,
  wrapped_object_in_sym_seed_b64: str,
  certify_nonce_b64: str,
) -> dict:
  """Enrollment co-residency proof that needs NO elevation (oneid-enroll >= 2.0.0).

  Runs 'oneid-enroll import-certify --json ...': imports the Registrar-wrapped
  object under the EK, loads it, and certifies it with the AK over the nonce.
  Windows allows these TPM commands to ordinary users (ActivateCredential it
  does not), so unattended agents never see a UAC prompt.

  Returns:
      Dict with certify_info and certify_signature (base64).
  """
  return _run_binary_command("import-certify", args=[
    "--wrapped-object-public", wrapped_object_public_b64,
    "--wrapped-object-duplicate", wrapped_object_duplicate_b64,
    "--wrapped-object-in-sym-seed", wrapped_object_in_sym_seed_b64,
    "--certify-nonce", certify_nonce_b64,
  ], timeout_seconds=120.0)


# ---------------------------------------------------------------------------
# Session mode: single elevation for the entire enrollment flow
# ---------------------------------------------------------------------------

class ElevatedSession:
  """A persistent elevated connection to the oneid-enroll binary.

  Instead of spawning the binary twice (extract + activate), session mode
  spawns it once with elevation. This means the user sees only ONE UAC prompt
  for the entire enrollment process.

  On Windows: The elevated child connects to a TCP socket on localhost that
  the parent is listening on (because ShellExecuteEx doesn't pass stdin/stdout).

  On Linux/macOS: The elevated child uses stdin/stdout directly (pkexec/sudo
  preserve them).

  Usage:
      with ElevatedSession() as sess:
          extract_data = sess.extract()
          # ... talk to server, get credential_blob + encrypted_secret ...
          activate_data = sess.activate(credential_blob, encrypted_secret, ak_handle)
  """

  def __init__(self, timeout_seconds: float = 120.0):
    self._timeout_seconds = timeout_seconds
    self._process: subprocess.Popen | None = None
    self._reader = None
    self._writer = None
    self._server_socket: socket.socket | None = None
    self._conn_socket: socket.socket | None = None
    self._is_windows = platform.system() == "Windows"
    self._session_token: str = ""  # shared secret for TCP socket auth

  def __enter__(self):
    self.start()
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    self.close()
    return False

  def start(self):
    """Start the elevated session."""
    binary_path = ensure_binary_available()

    if self._is_windows:
      self._start_windows_session(binary_path)
    else:
      self._start_unix_session(binary_path)

    # If using TCP socket mode, authenticate with the shared token
    if self._session_token:
      auth_response = self._read_response()  # auth result
      if not auth_response.get("ok"):
        error_message = auth_response.get("error", "Authentication failed")
        raise HSMAccessError(f"Session auth failed: {error_message}")
      logger.debug("Session authenticated successfully")

    # Wait for the "ready" message from the session
    ready_response = self._read_response()
    if not ready_response.get("ok"):
      error_message = ready_response.get("error", "Session failed to start")
      raise HSMAccessError(f"Session startup failed: {error_message}")

    logger.debug("Elevated session started successfully")

  def _start_windows_session(self, binary_path: Path):
    """Start a session on Windows using TCP loopback socket.

    SECURITY:
      1. Generate a 32-byte random session token
      2. Listen on 127.0.0.1 with a random ephemeral port
      3. Pass both the port and the token to the elevated child
      4. Accept exactly ONE connection, then CLOSE the listener
      5. The child must send the token as its first message (auth command)
      6. This prevents a rogue local process from hijacking the session

    The token is passed via --session-token on the command line. This is visible
    to processes running as the same user, but:
      - If malware is running as the same user, elevation is moot anyway
      - The attacker also needs to connect before the real child (race condition)
      - The listener is closed immediately after the first connection
    """
    # Generate a random session token (32 bytes = 64 hex chars)
    import secrets
    self._session_token = secrets.token_hex(32)

    # Create a TCP server on localhost with a random port
    self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._server_socket.bind(("127.0.0.1", 0))
    self._server_socket.listen(1)
    self._server_socket.settimeout(self._timeout_seconds)
    _, port = self._server_socket.getsockname()

    pipe_address = f"127.0.0.1:{port}"
    logger.debug("Session TCP socket listening on %s", pipe_address)

    # Spawn the elevated session process with the session token.
    cmd = [
      str(binary_path), "session", "--elevated",
      "--pipe", pipe_address,
      "--session-token", self._session_token,
    ]
    logger.debug("Spawning elevated session: %s", " ".join(cmd[:5]) + " --session-token <redacted>")

    self._process = subprocess.Popen(
      cmd,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )

    # Wait for the elevated child to connect
    try:
      self._conn_socket, _ = self._server_socket.accept()
      self._conn_socket.settimeout(self._timeout_seconds)
    except socket.timeout:
      self.close()
      raise HSMAccessError(
        "Elevated session did not connect within timeout. "
        "UAC may have been denied."
      )

    # SECURITY: Close the listening socket IMMEDIATELY after accepting one
    # connection. No further connections are possible.
    try:
      self._server_socket.close()
    except Exception:
      pass
    self._server_socket = None

    self._reader = self._conn_socket.makefile("r")
    self._writer = self._conn_socket.makefile("w")

    # Send the auth command with the shared token
    auth_cmd = json.dumps({"command": "auth", "args": {"token": self._session_token}}) + "\n"
    self._conn_socket.sendall(auth_cmd.encode("utf-8"))

  def _start_unix_session(self, binary_path: Path):
    """Start a session on Linux/macOS using stdin/stdout.

    pkexec/sudo preserve stdin/stdout, so no socket is needed.
    """
    cmd = [str(binary_path), "session", "--elevated"]
    logger.debug("Spawning elevated session: %s", " ".join(cmd))

    self._process = subprocess.Popen(
      cmd,
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
    )

    self._reader = self._process.stdout
    self._writer = self._process.stdin

  def _send_command(self, command: str, args: dict | None = None) -> dict:
    """Send a command to the session and return the response."""
    cmd_obj = {"command": command}
    if args:
      cmd_obj["args"] = args

    cmd_json = json.dumps(cmd_obj) + "\n"
    logger.debug("Session send: %s", command)

    try:
      if self._is_windows and self._writer:
        self._writer.write(cmd_json.encode("utf-8") if isinstance(self._writer, socket.SocketIO) else cmd_json)
        self._writer.flush()
      elif self._writer:
        self._writer.write(cmd_json)
        self._writer.flush()
    except (BrokenPipeError, OSError) as e:
      raise HSMAccessError(f"Session connection lost: {e}")

    return self._read_response()

  def _read_response(self) -> dict:
    """Read a single JSON response line from the session."""
    try:
      if self._reader is None:
        raise HSMAccessError("Session not connected")

      line = self._reader.readline()
      if isinstance(line, bytes):
        line = line.decode("utf-8")
      line = line.strip()
      if not line:
        raise HSMAccessError("Session returned empty response (process may have exited)")

      return json.loads(line)
    except json.JSONDecodeError as e:
      raise HSMAccessError(f"Session returned invalid JSON: {e}")
    except (BrokenPipeError, OSError) as e:
      raise HSMAccessError(f"Session connection lost while reading: {e}")

  def extract(self, hsm_type: str = "tpm") -> dict:
    """Run EK extraction + AK generation within the session.

    Returns the same data structure as extract_attestation_data().
    """
    response = self._send_command("extract", {"type": hsm_type})
    if not response.get("ok"):
      error_code = response.get("error_code", "UNKNOWN")
      error_message = response.get("error", "Unknown error")
      if error_code == "NO_HSM_FOUND":
        raise NoHSMError(error_message)
      raise HSMAccessError(error_message)
    return response.get("data", {})

  def activate(
    self,
    credential_blob_b64: str,
    encrypted_secret_b64: str,
    ak_handle: str,
  ) -> str:
    """Run credential activation within the session.

    Returns the base64-encoded decrypted credential secret.
    """
    response = self._send_command("activate", {
      "credential_blob": credential_blob_b64,
      "encrypted_secret": encrypted_secret_b64,
      "ak_handle": ak_handle,
    })
    if not response.get("ok"):
      error_code = response.get("error_code", "UNKNOWN")
      error_message = response.get("error", "Unknown error")
      raise HSMAccessError(f"Credential activation failed: {error_message}")
    data = response.get("data", {})
    return data.get("decrypted_credential", "")

  def sign(self, nonce_b64: str, ak_handle: str) -> dict:
    """Sign a challenge nonce with the AK within the session.

    This also works without elevation (UserWithAuth key), but can be
    used within an existing session for convenience.

    Returns dict with signature_b64, ak_handle, algorithm.
    """
    response = self._send_command("sign", {
      "nonce": nonce_b64,
      "ak_handle": ak_handle,
    })
    if not response.get("ok"):
      error_message = response.get("error", "Unknown error")
      raise HSMAccessError(f"TPM signing failed: {error_message}")
    return response.get("data", {})

  def close(self):
    """Shut down the session."""
    try:
      if self._writer:
        quit_cmd = json.dumps({"command": "quit"}) + "\n"
        try:
          if isinstance(self._writer, socket.SocketIO):
            self._writer.write(quit_cmd.encode("utf-8"))
          else:
            self._writer.write(quit_cmd)
          self._writer.flush()
        except Exception:
          pass
    except Exception:
      pass

    # Close sockets and process
    for resource in [self._reader, self._writer, self._conn_socket, self._server_socket]:
      if resource:
        try:
          resource.close()
        except Exception:
          pass

    if self._process:
      try:
        self._process.terminate()
        self._process.wait(timeout=5)
      except Exception:
        try:
          self._process.kill()
        except Exception:
          pass

    self._reader = None
    self._writer = None
    self._conn_socket = None
    self._server_socket = None
    self._process = None


def setup_tbs_for_non_admin_tpm_access() -> dict:
  """Run the one-time TBS access setup via the Go binary.

  Calls 'oneid-enroll setup-tbs --elevated --json' which sets a Windows
  registry key to allow non-admin users to access TPM Base Services.
  Triggers a UAC prompt on Windows. No-op on other platforms.

  Returns:
      Dict with keys:
        - ok: True if setup succeeded or was already done
        - already_set: True if the registry key was already configured
        - platform: 'not_windows' on non-Windows platforms

  Raises:
      UACDeniedError: If the user denied the UAC prompt.
      HSMAccessError: If the registry key could not be set.
  """
  return _run_binary_command("setup-tbs", args=["--elevated"])


def sign_challenge_with_piv(
  nonce_b64: str,
  piv_serial_number: int | None = None,
) -> dict:
  # CROSS_IMPL_SYNC: piv_sign
  # Implementations: py:oneid/helper.py go:internal/piv/sign.go node:src/helper.ts
  """Sign a challenge nonce using the PIV key in slot 9a -- NO ELEVATION NEEDED.

  This is the core of PIV-backed challenge-response during enrollment.
  The agent signs the server-provided nonce, proving it controls the
  YubiKey that was attested during enrollment begin.

  PIV slot 9a with pin-policy=NEVER means no human interaction required.

  Uses a tiered fallback strategy:

    Tier A (Go binary): Spawns oneid-enroll with --serial/--reader targeting.
      Best choice when the Go binary is available. Supports all platforms.
    Tier B (pyscard): Pure-Python PC/SC signing via GENERAL AUTHENTICATE APDU.
      Used when multiple YubiKeys are connected, when a specific serial is
      requested, or as fallback when the Go binary is unavailable/fails.
    Tier C: Not applicable for PIV (hardware key required).

  When piv_serial_number is provided, Tier B is used directly (it can target
  a specific device). When multiple keys are detected, Tier B handles
  selection. For single-key cases, Tier A is tried first with Tier B fallback.

  Args:
      nonce_b64: Base64-encoded nonce from the server.
      piv_serial_number: Specific YubiKey serial to sign with. When None
          and multiple keys are present, the selection logic picks the
          most-recently-plugged key that has a slot 9a signing key.

  Returns:
      Dict with:
        - signature_b64: Base64-encoded ECDSA-SHA256 signature
        - algorithm: "ECDSA-SHA256"
        - serial_number: YubiKey serial number string

  Raises:
      NoHSMError: If no PIV device is accessible.
      HSMAccessError: If signing fails.
  """
  import base64

  # Tier B (pyscard) -- used when serial targeting or multi-key selection needed
  if piv_serial_number is not None:
    nonce_bytes = base64.b64decode(nonce_b64)
    available = enumerate_all_piv_capable_yubikeys_via_pcsc()
    reader = select_preferred_piv_yubikey_reader_name(
      available_yubikeys=available,
      preferred_serial_number=piv_serial_number,
    )
    if reader is None:
      raise NoHSMError(
        "YubiKey with serial %d not found among %d connected key(s)"
        % (piv_serial_number, len(available))
      )
    return sign_nonce_with_specific_piv_reader_via_pcsc(nonce_bytes, reader)

  # Enumerate keys via Tier B (pyscard) to detect multi-key situations
  tier_b_piv_via_pyscard_is_available = False
  available = []
  try:
    available = enumerate_all_piv_capable_yubikeys_via_pcsc()
    tier_b_piv_via_pyscard_is_available = True
  except Exception:
    pass

  # Tier B direct: multiple keys require targeted selection (Go binary cannot
  # enumerate all -- it opens the first one. Even with --serial, we need to
  # know WHICH serial to pass, which requires enumeration.)
  if len(available) > 1:
    nonce_bytes = base64.b64decode(nonce_b64)
    reader = select_preferred_piv_yubikey_reader_name(
      available_yubikeys=available,
    )
    if reader is None:
      raise NoHSMError("Multiple YubiKeys detected but none could be selected")
    return sign_nonce_with_specific_piv_reader_via_pcsc(nonce_bytes, reader)

  # Tier A (Go binary): try first for single-key case
  tier_a_last_error = None
  try:
    go_binary_sign_args = [
      "--nonce", nonce_b64,
      "--type", "yubikey",
    ]
    if len(available) == 1 and available[0].get("serial_number"):
      go_binary_sign_args.extend(["--serial", str(available[0]["serial_number"])])
    return _run_binary_command("sign", args=go_binary_sign_args)
  except BinaryNotFoundError:
    tier_a_last_error = "Go binary not found"
    logger.info("PIV Tier A unavailable (binary not found), falling back to Tier B")
  except (HSMAccessError, NoHSMError) as tier_a_err:
    tier_a_last_error = str(tier_a_err)
    logger.info("PIV Tier A failed (%s), falling back to Tier B", tier_a_err)

  # Tier B fallback: try pyscard direct signing for single-key case
  if tier_b_piv_via_pyscard_is_available and len(available) == 1:
    nonce_bytes = base64.b64decode(nonce_b64)
    return sign_nonce_with_specific_piv_reader_via_pcsc(
      nonce_bytes, available[0]["reader_name"]
    )

  # Both tiers exhausted
  if tier_a_last_error:
    raise HSMAccessError(
      "PIV signing failed: Tier A (Go binary): %s; "
      "Tier B (pyscard): %s"
      % (
        tier_a_last_error,
        "no YubiKeys detected" if not available else "unavailable",
      )
    )
  raise NoHSMError("No PIV signing capability available (no Go binary, no pyscard)")


def _find_secure_enclave_helper_binary() -> Path | None:
  """Locate the oneid-se-helper binary (macOS only).

  Search order:
    1. Alongside oneid-enroll in ~/.oneid/bin/
    2. In PATH
  """
  se_helper_name = "oneid-se-helper"

  cache_dir = _get_binary_cache_directory()
  cached_path = cache_dir / se_helper_name
  if cached_path.exists() and os.access(str(cached_path), os.X_OK):
    return cached_path

  main_binary = find_binary()
  if main_binary is not None:
    sibling_path = main_binary.parent / se_helper_name
    if sibling_path.exists() and os.access(str(sibling_path), os.X_OK):
      return sibling_path

  home_oneid_path = Path.home() / ".oneid" / "bin" / se_helper_name
  if home_oneid_path.exists() and os.access(str(home_oneid_path), os.X_OK):
    return home_oneid_path

  import shutil
  path_binary = shutil.which(se_helper_name)
  if path_binary:
    return Path(path_binary)

  return None


def ensure_secure_enclave_helper_available() -> Path:
  """Find oneid-se-helper, or download it from the oneid-enroll GitHub release
  into the helper cache (OWN-030: previously it had to be placed by hand).
  The download is SHA-256- and Developer-ID-verified like oneid-enroll. macOS only.

  Raises:
      NoHSMError: not macOS.
      BinaryNotFoundError: not found and the verified download failed.
  """
  if platform.system() != "Darwin":
    raise NoHSMError("The Secure Enclave helper exists only on macOS")
  existing_helper = _find_secure_enclave_helper_binary()
  if existing_helper is not None:
    return existing_helper
  machine_name = platform.machine().lower()
  release_asset_name = "oneid-se-helper-arm64" if machine_name in ("arm64", "aarch64") else "oneid-se-helper"
  destination = _get_binary_cache_directory() / "oneid-se-helper"
  logger.info("oneid-se-helper not found; downloading %s from the GitHub release", release_asset_name)
  return _download_binary_from_github_release(release_asset_name, destination)


_ENCLAVE_DEFAULT_KEY_TAG = "com.1id.enclave.default"

_SE_HELPER_COMMAND_TIMEOUT_SECONDS = 15.0
_CTKD_RESPAWN_WAIT_SECONDS = 3.0


def _attempt_macos_cryptotokenkit_daemon_recovery() -> bool:
  """Kill a hung macOS CryptoTokenKit daemon so launchd respawns a fresh one.

  On macOS, the per-user `ctkd` daemon handles all Secure Enclave XPC
  requests.  If it becomes unresponsive (observed after days/weeks of
  uptime), every SE operation blocks indefinitely at an XPC send.
  Killing the daemon with SIGKILL causes launchd to respawn it within
  seconds, restoring SE functionality.

  Returns True if recovery was attempted, False if not applicable
  (wrong platform, daemon not found, or permission denied).
  """
  if platform.system() != "Darwin":
    return False

  import signal

  try:
    ctkd_pgrep_result = subprocess.run(
      ["pgrep", "-u", str(os.getuid()), "-x", "ctkd"],
      capture_output=True, text=True, timeout=5.0,
    )
    if ctkd_pgrep_result.returncode != 0 or not ctkd_pgrep_result.stdout.strip():
      logger.warning("ctkd daemon not found for current user -- cannot recover")
      return False

    ctkd_pid_strings = ctkd_pgrep_result.stdout.strip().split("\n")
    for ctkd_pid_string in ctkd_pid_strings:
      ctkd_pid = int(ctkd_pid_string.strip())
      logger.warning(
        "Killing unresponsive ctkd daemon (PID %d) to restore "
        "Secure Enclave access -- launchd will respawn it",
        ctkd_pid,
      )
      os.kill(ctkd_pid, signal.SIGKILL)

    time.sleep(_CTKD_RESPAWN_WAIT_SECONDS)
    return True

  except (PermissionError, ProcessLookupError) as kill_error:
    logger.warning("Could not kill ctkd: %s", kill_error)
    return False
  except Exception as unexpected_error:
    logger.warning("ctkd recovery failed unexpectedly: %s", unexpected_error)
    return False


def _run_secure_enclave_helper_with_recovery(
  se_helper_path: Path,
  subcommand_and_args: list[str],
) -> dict:
  """Run an oneid-se-helper command, auto-recovering from a hung ctkd.

  If the command times out (indicating the CryptoTokenKit daemon is
  unresponsive), kills the daemon, waits for launchd to respawn it,
  and retries once.

  Args:
      se_helper_path: Path to the oneid-se-helper binary.
      subcommand_and_args: Command and arguments (e.g. ["sign", "--tag", ...]).

  Returns:
      Parsed JSON dict from the helper's stdout.

  Raises:
      NoHSMError: Binary not found.
      HSMAccessError: Command failed after retry.
  """
  cmd = [str(se_helper_path)] + subcommand_and_args

  for attempt_number in range(2):
    try:
      result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_SE_HELPER_COMMAND_TIMEOUT_SECONDS,
      )
    except subprocess.TimeoutExpired:
      if attempt_number == 0:
        logger.warning(
          "oneid-se-helper timed out after %.0fs -- "
          "attempting CryptoTokenKit daemon recovery",
          _SE_HELPER_COMMAND_TIMEOUT_SECONDS,
        )
        ctkd_recovery_was_attempted = _attempt_macos_cryptotokenkit_daemon_recovery()
        if ctkd_recovery_was_attempted:
          logger.info("ctkd daemon restarted -- retrying SE operation")
          continue
      raise HSMAccessError(
        f"oneid-se-helper timed out after {_SE_HELPER_COMMAND_TIMEOUT_SECONDS}s "
        f"(ctkd recovery {'attempted but did not help' if attempt_number > 0 else 'not possible'})"
      )
    except FileNotFoundError:
      raise NoHSMError(f"oneid-se-helper binary not found at {se_helper_path}")

    if result.returncode != 0:
      error_text = result.stderr.strip() or result.stdout.strip()
      raise HSMAccessError(f"oneid-se-helper failed: {error_text}")

    try:
      output = json.loads(result.stdout)
    except json.JSONDecodeError as json_error:
      raise HSMAccessError(
        f"oneid-se-helper returned invalid JSON: {json_error}"
      ) from json_error

    if output.get("status") != "ok":
      raise HSMAccessError(
        f"oneid-se-helper returned error: {output.get('error', 'unknown')}"
      )

    if attempt_number > 0:
      logger.info("SE operation succeeded after ctkd recovery")

    return output

  raise HSMAccessError("oneid-se-helper failed after ctkd recovery retry")


def sign_challenge_with_enclave(nonce_b64: str) -> dict:
  """Sign a challenge nonce using the Apple Secure Enclave -- NO ELEVATION NEEDED.

  Uses the P-256 key stored in the Secure Enclave via the oneid-se-helper
  Swift binary (NOT oneid-enroll, which does not support enclave signing).
  Only available on macOS with Apple Silicon or T2 security chip.

  If the underlying CryptoTokenKit daemon is unresponsive (a known macOS
  issue after prolonged uptime), the SDK automatically kills and restarts
  the daemon, then retries the operation.

  Args:
      nonce_b64: Base64-encoded nonce from the server.

  Returns:
      Dict with:
        - signature_b64: Base64-encoded ECDSA-SHA256 signature
        - algorithm: "ecdsa-p256-sha256"
        - key_tag: Keychain application tag identifying the key

  Raises:
      NoHSMError: If Secure Enclave is not available.
      HSMAccessError: If signing fails.
  """
  try:
    se_helper_path = ensure_secure_enclave_helper_available()
  except BinaryNotFoundError as se_helper_download_error:
    raise NoHSMError(
      f"oneid-se-helper binary not found and could not be downloaded: {se_helper_download_error}"
    ) from se_helper_download_error

  return _run_secure_enclave_helper_with_recovery(
    se_helper_path,
    ["sign", "--tag", _ENCLAVE_DEFAULT_KEY_TAG, "--nonce", nonce_b64],
  )


def sign_challenge_with_tpm(nonce_b64: str, ak_handle: str = "") -> dict:
  # CROSS_IMPL_SYNC: tpm_sign
  # Implementations: py:oneid/helper.py go:internal/tpm/sign.go node:src/helper.ts
  """Sign a challenge nonce using the TPM AK -- NO ELEVATION NEEDED.

  This is the core of ongoing TPM-backed authentication. The agent
  calls this to sign a server-provided nonce, proving it controls the
  same hardware that was enrolled.

  The AK is recreated on-demand (transient, deterministic -- same key every
  time on the same TPM). No persistent handle needed.

  Args:
      nonce_b64: Base64-encoded nonce from the server.
      ak_handle: Optional. Hex handle for backward compat with persistent AKs.

  Returns:
      Dict with:
        - signature_b64: Base64-encoded RSASSA-SHA256 signature
        - ak_handle: Handle used
        - algorithm: "RSASSA-SHA256"

  Raises:
      NoHSMError: If no TPM is accessible.
      HSMAccessError: If signing fails.
  """
  sign_args = ["--nonce", nonce_b64]
  if ak_handle and ak_handle != "transient":
    sign_args.extend(["--ak-handle", ak_handle])
  output = _run_binary_command("sign", args=sign_args)
  return output


# ---------------------------------------------------------------------------
# Phase 4: Multi-YubiKey enumeration and selection via PC/SC (pyscard)
# ---------------------------------------------------------------------------
# The Go binary always opens the first YubiKey it finds, so when multiple
# YubiKeys are connected the SDK uses pyscard directly to enumerate readers,
# get serial numbers, and sign with a specific device.
# ---------------------------------------------------------------------------

_PIV_AID_FOR_APPLET_SELECT = [0xA0, 0x00, 0x00, 0x03, 0x08]
_YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE = [
  0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
]


def _pcsc_parse_yubikey_management_device_info_tlv_for_serial_and_firmware(
  raw_device_info_bytes: list[int],
) -> dict:
  """Parse the TLV response from YubiKey management GET DEVICE INFO.

  Returns dict with optional 'serial' (int) and 'firmware' (str) keys.
  The first byte of the response is the total length; TLV pairs follow.
  Tag 0x02 (4 bytes, big-endian) = serial number.
  Tag 0x05 (3 bytes) = firmware major.minor.patch.
  """
  import struct
  result: dict = {}
  if not raw_device_info_bytes or len(raw_device_info_bytes) < 3:
    return result
  pos = 1  # skip length byte
  while pos < len(raw_device_info_bytes) - 1:
    tag = raw_device_info_bytes[pos]
    length = raw_device_info_bytes[pos + 1]
    pos += 2
    value = raw_device_info_bytes[pos:pos + length]
    pos += length
    if tag == 0x02 and length == 4:
      result["serial"] = struct.unpack(">I", bytes(value))[0]
    elif tag == 0x05 and length >= 3:
      result["firmware"] = "%d.%d.%d" % (value[0], value[1], value[2])
  return result


def enumerate_all_piv_capable_yubikeys_via_pcsc() -> list[dict]:
  # CROSS_IMPL_SYNC: piv_multi_key
  # Implementations: py:oneid/helper.py go:internal/piv/connection.go(MISSING) node:src/helper.ts(MISSING)
  """Enumerate all connected YubiKeys that have a PIV applet, via PC/SC.

  Each YubiKey is probed for its serial number (via the management applet)
  and whether slot 9a contains a key (via PIV GENERAL AUTHENTICATE probe).

  Returns a list of dicts in PC/SC enumeration order (the LAST entry is
  typically the most recently plugged device), each containing:
    - reader_name: str  (PC/SC reader name, needed to reconnect for signing)
    - serial_number: int | None
    - firmware_version: str | None
    - piv_slot_9a_has_signing_key: bool
    - pcsc_enumeration_index: int  (position in the reader list)
  """
  try:
    from smartcard.System import readers as pcsc_list_readers
  except ImportError:
    logger.warning(
      "pyscard not installed; cannot enumerate multiple YubiKeys. "
      "Install with: pip install pyscard"
    )
    return []

  try:
    all_pcsc_readers = pcsc_list_readers()
  except Exception as pcsc_error:
    logger.warning("PC/SC reader enumeration failed: %s", pcsc_error)
    return []

  import hashlib
  detected_yubikeys: list[dict] = []

  for reader_index, reader_object in enumerate(all_pcsc_readers):
    reader_name = str(reader_object)
    if "yubi" not in reader_name.lower():
      continue

    entry: dict = {
      "reader_name": reader_name,
      "serial_number": None,
      "firmware_version": None,
      "piv_slot_9a_has_signing_key": False,
      "pcsc_enumeration_index": reader_index,
    }

    try:
      connection = reader_object.createConnection()
      connection.connect()

      # Get serial + firmware via management applet
      select_mgmt_apdu = (
        [0x00, 0xA4, 0x04, 0x00, len(_YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE)]
        + _YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE
      )
      data, sw1, sw2 = connection.transmit(select_mgmt_apdu)
      if sw1 == 0x90:
        get_device_info_apdu = [0x00, 0x1D, 0x00, 0x00]
        data, sw1, sw2 = connection.transmit(get_device_info_apdu)
        if sw1 == 0x90 and data:
          parsed = _pcsc_parse_yubikey_management_device_info_tlv_for_serial_and_firmware(data)
          entry["serial_number"] = parsed.get("serial")
          entry["firmware_version"] = parsed.get("firmware")

      # Check if slot 9a has a signing key by probing GENERAL AUTHENTICATE
      select_piv_apdu = (
        [0x00, 0xA4, 0x04, 0x00, len(_PIV_AID_FOR_APPLET_SELECT)]
        + _PIV_AID_FOR_APPLET_SELECT
      )
      data, sw1, sw2 = connection.transmit(select_piv_apdu)
      if sw1 == 0x90:
        probe_hash = list(hashlib.sha256(b"phase4-slot-probe").digest())
        # GENERAL AUTHENTICATE: P1=0x11 (ECC P-256), P2=0x9A (slot 9a)
        probe_apdu = (
          [0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]
          + probe_hash
        )
        data, sw1, sw2 = connection.transmit(probe_apdu)
        if sw1 == 0x90:
          entry["piv_slot_9a_has_signing_key"] = True
        else:
          # Try RSA 2048 (P1=0x07) in case slot 9a has an RSA key
          probe_apdu_rsa = (
            [0x00, 0x87, 0x07, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]
            + probe_hash
          )
          data, sw1, sw2 = connection.transmit(probe_apdu_rsa)
          if sw1 == 0x90:
            entry["piv_slot_9a_has_signing_key"] = True

      connection.disconnect()
    except Exception as reader_error:
      logger.debug("Could not probe YubiKey at %s: %s", reader_name, reader_error)

    detected_yubikeys.append(entry)

  logger.info(
    "Enumerated %d PIV-capable YubiKey(s) via PC/SC",
    len(detected_yubikeys),
  )
  return detected_yubikeys


def select_preferred_piv_yubikey_reader_name(
  available_yubikeys: list[dict] | None = None,
  preferred_serial_number: int | None = None,
  registered_piv_device_serial_number: int | None = None,
) -> str | None:
  """Choose which YubiKey reader to use for PIV signing.

  Priority order (production-ready common-sense logic):
    1. Explicit serial override -- caller knows which key they want
    2. Registered device match -- the serial from credentials/database
    3. Most-recently-plugged heuristic -- LAST in PC/SC enumeration
       among keys that have a functioning slot 9a key
    4. If no key has slot 9a populated, pick the last enumerated anyway
       (enrollment will generate a key there)
    5. Single YubiKey -- no ambiguity, use it

  Args:
    available_yubikeys: Output of enumerate_all_piv_capable_yubikeys_via_pcsc().
        If None, will call that function automatically.
    preferred_serial_number: Explicit serial override from caller.
    registered_piv_device_serial_number: Serial of the PIV device registered
        in credentials for this identity (if known).

  Returns:
    PC/SC reader name string, or None if no YubiKey is available.
  """
  if available_yubikeys is None:
    available_yubikeys = enumerate_all_piv_capable_yubikeys_via_pcsc()

  if not available_yubikeys:
    return None

  # Single key: no ambiguity
  if len(available_yubikeys) == 1:
    return available_yubikeys[0]["reader_name"]

  # Priority 1: Explicit serial override
  if preferred_serial_number is not None:
    for yk in available_yubikeys:
      if yk["serial_number"] == preferred_serial_number:
        logger.info(
          "Selected YubiKey serial %d (explicit override) at reader %s",
          preferred_serial_number, yk["reader_name"],
        )
        return yk["reader_name"]
    logger.warning(
      "Requested YubiKey serial %d not found among %d connected keys",
      preferred_serial_number, len(available_yubikeys),
    )
    return None

  # Priority 2: Registered device match
  if registered_piv_device_serial_number is not None:
    for yk in available_yubikeys:
      if yk["serial_number"] == registered_piv_device_serial_number:
        logger.info(
          "Selected registered PIV YubiKey serial %d at reader %s",
          registered_piv_device_serial_number, yk["reader_name"],
        )
        return yk["reader_name"]
    logger.info(
      "Registered PIV serial %d not among connected keys; falling through to heuristic",
      registered_piv_device_serial_number,
    )

  # Priority 3: Last-enumerated key WITH a slot 9a key (most-recently-plugged)
  yubikeys_with_signing_key = [
    yk for yk in available_yubikeys if yk["piv_slot_9a_has_signing_key"]
  ]
  if yubikeys_with_signing_key:
    chosen = yubikeys_with_signing_key[-1]
    logger.info(
      "Selected most-recently-plugged YubiKey with slot 9a key: "
      "serial %s at reader %s (last of %d with keys)",
      chosen["serial_number"], chosen["reader_name"],
      len(yubikeys_with_signing_key),
    )
    return chosen["reader_name"]

  # Priority 4: Last-enumerated key (for enrollment or fresh setup)
  chosen = available_yubikeys[-1]
  logger.info(
    "No YubiKey has slot 9a key; selected last-enumerated: "
    "serial %s at reader %s",
    chosen["serial_number"], chosen["reader_name"],
  )
  return chosen["reader_name"]


def sign_nonce_with_specific_piv_reader_via_pcsc(
  nonce_bytes: bytes,
  reader_name: str,
) -> dict:
  """Sign a nonce using PIV slot 9a on a specific PC/SC reader.

  Pure Python implementation via pyscard APDUs -- does NOT use the Go binary.
  This enables signing with a specific YubiKey when multiple are connected.

  The nonce is SHA-256 hashed before sending to the card (matching the
  Go binary's behavior for ECDSA-SHA256).

  Args:
    nonce_bytes: Raw nonce bytes to sign (any length; will be SHA-256 hashed).
    reader_name: Exact PC/SC reader name string from enumeration.

  Returns:
    Dict matching the Go binary's output format:
      - signature_b64: Base64-encoded DER ECDSA signature
      - algorithm: "ECDSA-SHA256"
      - serial_number: YubiKey serial (str) if available

  Raises:
    NoHSMError: If the reader is not found or card not present.
    HSMAccessError: If PIV selection or signing fails.
  """
  import base64
  import hashlib

  try:
    from smartcard.System import readers as pcsc_list_readers
  except ImportError:
    raise HSMAccessError(
      "pyscard not installed; required for multi-YubiKey PIV signing. "
      "Install with: pip install pyscard"
    )

  try:
    all_readers = pcsc_list_readers()
  except Exception as pcsc_err:
    raise NoHSMError("PC/SC subsystem unavailable: %s" % pcsc_err)

  target_reader = None
  for r in all_readers:
    if str(r) == reader_name:
      target_reader = r
      break
  if target_reader is None:
    raise NoHSMError("PC/SC reader not found: %s" % reader_name)

  try:
    connection = target_reader.createConnection()
    connection.connect()
  except Exception as connect_err:
    raise NoHSMError("Cannot connect to YubiKey at %s: %s" % (reader_name, connect_err))

  try:
    # SELECT PIV applet
    select_piv = (
      [0x00, 0xA4, 0x04, 0x00, len(_PIV_AID_FOR_APPLET_SELECT)]
      + _PIV_AID_FOR_APPLET_SELECT
    )
    data, sw1, sw2 = connection.transmit(select_piv)
    if sw1 != 0x90:
      raise HSMAccessError("PIV applet selection failed: SW=%02X%02X" % (sw1, sw2))

    # Hash the nonce (matching Go binary: ECDSA-SHA256)
    digest_32_bytes = list(hashlib.sha256(nonce_bytes).digest())

    # GENERAL AUTHENTICATE: P1=0x11 (ECC P-256), P2=0x9A (slot 9a)
    # Data: 7C 24 82 00 81 20 [32 bytes]
    sign_apdu = (
      [0x00, 0x87, 0x11, 0x9A, 0x26,
       0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]
      + digest_32_bytes
    )
    data, sw1, sw2 = connection.transmit(sign_apdu)

    if sw1 == 0x69 and sw2 == 0x82:
      raise HSMAccessError(
        "PIV slot 9a requires PIN verification (pin-policy is not NEVER). "
        "This YubiKey may not be configured for agent use."
      )
    if sw1 == 0x6A and sw2 == 0x80:
      raise HSMAccessError(
        "No key in PIV slot 9a on this YubiKey. "
        "The key may not be enrolled or may need setup."
      )
    if sw1 != 0x90:
      raise HSMAccessError("PIV signing failed: SW=%02X%02X" % (sw1, sw2))

    # Parse response TLV: 7C [len] 82 [len] [signature bytes]
    raw_response = bytes(data)
    signature_der_bytes = _pcsc_extract_signature_from_general_authenticate_response(raw_response)

    # Get serial number for the response
    serial_str = ""
    try:
      select_mgmt = (
        [0x00, 0xA4, 0x04, 0x00, len(_YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE)]
        + _YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE
      )
      data2, sw1_2, sw2_2 = connection.transmit(select_mgmt)
      if sw1_2 == 0x90:
        data2, sw1_2, sw2_2 = connection.transmit([0x00, 0x1D, 0x00, 0x00])
        if sw1_2 == 0x90 and data2:
          parsed = _pcsc_parse_yubikey_management_device_info_tlv_for_serial_and_firmware(data2)
          if parsed.get("serial"):
            serial_str = str(parsed["serial"])
    except Exception:
      pass

    connection.disconnect()

    return {
      "signature_b64": base64.b64encode(signature_der_bytes).decode("ascii"),
      "algorithm": "ECDSA-SHA256",
      "serial_number": serial_str,
    }

  except (NoHSMError, HSMAccessError):
    connection.disconnect()
    raise
  except Exception as unexpected_err:
    connection.disconnect()
    raise HSMAccessError("Unexpected PIV signing error: %s" % unexpected_err)


def _pcsc_extract_signature_from_general_authenticate_response(
  raw_response_bytes: bytes,
) -> bytes:
  """Extract the signature from a PIV GENERAL AUTHENTICATE response.

  The response is TLV-encoded: tag 0x7C containing tag 0x82 with the
  DER-encoded ECDSA (or RSA) signature bytes.
  """
  if len(raw_response_bytes) < 4:
    raise HSMAccessError(
      "PIV GENERAL AUTHENTICATE response too short: %d bytes" % len(raw_response_bytes)
    )
  # Expect: 7C [length] 82 [length] [signature]
  if raw_response_bytes[0] != 0x7C:
    raise HSMAccessError(
      "Unexpected PIV response tag: 0x%02X (expected 0x7C)" % raw_response_bytes[0]
    )

  # Parse outer TLV (tag 7C)
  pos = 1
  outer_len, pos = _pcsc_parse_asn1_length(raw_response_bytes, pos)

  # Parse inner tag 82
  if pos >= len(raw_response_bytes) or raw_response_bytes[pos] != 0x82:
    raise HSMAccessError(
      "Unexpected inner PIV response tag: 0x%02X (expected 0x82)"
      % (raw_response_bytes[pos] if pos < len(raw_response_bytes) else 0)
    )
  pos += 1
  sig_len, pos = _pcsc_parse_asn1_length(raw_response_bytes, pos)

  signature_bytes = raw_response_bytes[pos:pos + sig_len]
  if len(signature_bytes) != sig_len:
    raise HSMAccessError(
      "Truncated PIV signature: expected %d bytes, got %d" % (sig_len, len(signature_bytes))
    )
  return signature_bytes


def _pcsc_parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
  """Parse an ASN.1/BER length field. Returns (length_value, new_offset)."""
  if offset >= len(data):
    raise HSMAccessError("ASN.1 length parse: offset %d beyond data" % offset)
  first_byte = data[offset]
  if first_byte < 0x80:
    return first_byte, offset + 1
  num_length_bytes = first_byte & 0x7F
  if num_length_bytes == 0 or offset + 1 + num_length_bytes > len(data):
    raise HSMAccessError("ASN.1 length parse: invalid multi-byte length")
  length_value = 0
  for i in range(num_length_bytes):
    length_value = (length_value << 8) | data[offset + 1 + i]
  return length_value, offset + 1 + num_length_bytes
