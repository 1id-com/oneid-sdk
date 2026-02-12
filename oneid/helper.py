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
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path

from .exceptions import (
  BinaryNotFoundError,
  HSMAccessError,
  NoHSMError,
  UACDeniedError,
)

logger = logging.getLogger("oneid.helper")

# -- Binary naming convention --
BINARY_NAME_PREFIX = "oneid-enroll"
BINARY_VERSION = "0.1.0"

# -- Download URLs (skipped for now -- see TODO) --
BINARY_DOWNLOAD_BASE_URL = "https://1id.com/sdk/v1"


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


def ensure_binary_available() -> Path:
  """Ensure the oneid-enroll binary is available, downloading if needed.

  Returns:
      Path to the available binary.

  Raises:
      BinaryNotFoundError: If the binary cannot be found or downloaded.
  """
  binary_path = find_binary()
  if binary_path is not None:
    return binary_path

  # TODO: Implement binary download from 1id.com with checksum verification
  # For now, log a warning and raise an error
  logger.warning(
    "oneid-enroll binary not found. Auto-download is not yet implemented. "
    "Download manually from %s or build from source.",
    BINARY_DOWNLOAD_BASE_URL,
  )

  raise BinaryNotFoundError(
    f"oneid-enroll binary not found in cache, current directory, or PATH. "
    f"Expected filename: {_get_platform_binary_name()}. "
    f"Download from {BINARY_DOWNLOAD_BASE_URL} or build from source in sdk/oneid-enroll/."
  )


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

    if error_code == "NO_HSM_FOUND" or "no.*hsm" in error_message.lower() or "no.*tpm" in error_message.lower():
      raise NoHSMError(error_message)
    elif error_code == "UAC_DENIED" or "denied" in error_message.lower():
      raise UACDeniedError(error_message)
    elif error_code == "HSM_ACCESS_ERROR":
      raise HSMAccessError(error_message)
    else:
      raise HSMAccessError(f"oneid-enroll '{command}' failed: {error_message}")

  return output


def detect_available_hsms() -> list[dict]:
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
    return output.get("hsms", [])
  except NoHSMError:
    return []
  except BinaryNotFoundError:
    raise
  except HSMAccessError:
    logger.warning("HSM detection failed, returning empty list")
    return []


def extract_attestation_data(hsm: dict) -> dict:
  """Extract attestation data from an HSM (requires elevation).

  Runs 'oneid-enroll extract --json --elevated --type <hsm_type>'
  which triggers UAC/sudo to read EK cert and generate AK.

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
  return _run_binary_command("extract", args=["--type", hsm_type, "--elevated"])


def activate_credential(hsm: dict, challenge: str) -> str:
  """Decrypt a credential activation challenge via the HSM (requires elevation).

  Runs 'oneid-enroll activate --json --elevated --challenge <base64>'
  which uses the TPM's EK to decrypt the server's challenge.

  Args:
      hsm: HSM dict from detect_available_hsms().
      challenge: Base64-encoded credential activation challenge from the server.

  Returns:
      Base64-encoded decrypted credential.
  """
  output = _run_binary_command("activate", args=["--challenge", challenge, "--elevated"])
  return output.get("decrypted_credential", "")
