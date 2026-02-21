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
  UACDeniedError,
)

# -- GitHub release URL for auto-download --
GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE = (
  "https://github.com/1id-com/oneid-enroll/releases/latest/download/{binary_name}"
)

logger = logging.getLogger("oneid.helper")

# -- Binary naming convention --
BINARY_NAME_PREFIX = "oneid-enroll"
BINARY_VERSION = "0.2.0"

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
      logger.warning(
        "Could not download checksum file (%s). "
        "Proceeding without verification -- binary is NOT integrity-checked.",
        checksum_error,
      )

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
  if binary_path is not None:
    return binary_path

  # Binary not found locally -- attempt auto-download from GitHub release
  binary_name = _get_platform_binary_name()
  cache_dir = _get_binary_cache_directory()
  destination = cache_dir / binary_name

  logger.info(
    "oneid-enroll binary not found locally. "
    "Attempting auto-download from GitHub release..."
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


def activate_credential(
  hsm: dict,
  credential_blob_b64: str,
  encrypted_secret_b64: str,
  ak_handle: str,
) -> str:
  """Decrypt a credential activation challenge via the HSM (requires elevation).

  Runs 'oneid-enroll activate --json --elevated --credential-blob <b64>
  --encrypted-secret <b64> --ak-handle <hex>' which uses the TPM's EK to
  decrypt the server's MakeCredential challenge, proving the AK is in this TPM.

  Args:
      hsm: HSM dict from detect_available_hsms().
      credential_blob_b64: Base64-encoded credential blob from the server.
      encrypted_secret_b64: Base64-encoded encrypted secret from the server.
      ak_handle: Hex string of the AK persistent handle (e.g., "0x81000100").

  Returns:
      Base64-encoded decrypted credential secret.
  """
  output = _run_binary_command(
    "activate",
    args=[
      "--credential-blob", credential_blob_b64,
      "--encrypted-secret", encrypted_secret_b64,
      "--ak-handle", ak_handle,
      "--elevated",
    ],
  )
  return output.get("decrypted_credential", "")


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


def sign_challenge_with_piv(nonce_b64: str) -> dict:
  """Sign a challenge nonce using the PIV key in slot 9a -- NO ELEVATION NEEDED.

  This is the core of PIV-backed challenge-response during enrollment.
  The agent signs the server-provided nonce, proving it controls the
  YubiKey that was attested during enrollment begin.

  PIV slot 9a with pin-policy=NEVER means no human interaction required.

  Args:
      nonce_b64: Base64-encoded nonce from the server.

  Returns:
      Dict with:
        - signature_b64: Base64-encoded ECDSA-SHA256 signature
        - algorithm: "ECDSA-SHA256"
        - serial_number: YubiKey serial number string

  Raises:
      NoHSMError: If no PIV device is accessible.
      HSMAccessError: If signing fails.
  """
  output = _run_binary_command(
    "sign",
    args=[
      "--nonce", nonce_b64,
      "--type", "yubikey",
    ],
  )
  return output


def sign_challenge_with_tpm(nonce_b64: str, ak_handle: str) -> dict:
  """Sign a challenge nonce using the TPM AK -- NO ELEVATION NEEDED.

  This is the core of ongoing TPM-backed authentication. The agent
  calls this to sign a server-provided nonce, proving it controls the
  same hardware that was enrolled.

  The AK has UserWithAuth=true, so TPM2_Sign works at normal user
  privilege. No UAC prompt, no admin, no sudo.

  Args:
      nonce_b64: Base64-encoded nonce from the server.
      ak_handle: Hex string of the AK persistent handle (e.g., "0x81000100").

  Returns:
      Dict with:
        - signature_b64: Base64-encoded RSASSA-SHA256 signature
        - ak_handle: Handle used
        - algorithm: "RSASSA-SHA256"

  Raises:
      NoHSMError: If no TPM is accessible.
      HSMAccessError: If signing fails.
  """
  output = _run_binary_command(
    "sign",
    args=[
      "--nonce", nonce_b64,
      "--ak-handle", ak_handle,
    ],
  )
  return output
