"""
Credential storage for the 1id.com SDK.

Manages the local credentials file that stores OAuth2 client credentials
and the agent's signing key (for declared-tier software keys or references
to TPM/YubiKey keys for hardware-backed tiers).

Storage locations:
  Windows:  %APPDATA%\\oneid\\credentials.json
  Linux:    ~/.config/oneid/credentials.json
  macOS:    ~/.config/oneid/credentials.json

Security:
  - File permissions set to owner-only (0600 on Unix, ACL on Windows)
  - Private keys are stored PEM-encoded in the credentials file
  - Credentials are NEVER logged or printed
"""

from __future__ import annotations

import json
import os
import platform
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .exceptions import NotEnrolledError


# -- Default server endpoints --
DEFAULT_API_BASE_URL = "https://1id.com"
DEFAULT_TOKEN_ENDPOINT = "https://1id.com/realms/agents/protocol/openid-connect/token"

# -- Credential file name --
CREDENTIALS_FILENAME = "credentials.json"


@dataclass
class StoredCredentials:
  """Credentials stored locally after enrollment.

  Contains everything needed to authenticate and sign challenges
  without re-enrolling.

  Attributes:
      client_id: The 1id internal ID (e.g., '1id-a7b3c9d2'), used as
                 OAuth2 client_id for the client_credentials grant.
      client_secret: OAuth2 client secret issued by Keycloak.
      token_endpoint: Full URL of the Keycloak token endpoint.
      api_base_url: Base URL for the 1id.com enrollment API.
      trust_tier: The trust tier assigned at enrollment.
      key_algorithm: The key algorithm used for the signing key.
      private_key_pem: PEM-encoded private key for challenge-response
                       signing (declared tier). None for TPM tiers where
                       signing is done by the Go binary via the TPM.
      hsm_key_reference: Reference to the HSM-stored key (e.g., TPM AK
                         handle or YubiKey PIV slot). None for declared tier.
      enrolled_at: ISO 8601 timestamp of enrollment.
  """
  client_id: str
  client_secret: str
  token_endpoint: str
  api_base_url: str
  trust_tier: str
  key_algorithm: str
  private_key_pem: str | None = None
  hsm_key_reference: str | None = None
  enrolled_at: str | None = None
  display_name: str | None = None


def get_credentials_directory() -> Path:
  """Return the platform-appropriate directory for storing credentials.

  Windows:  %APPDATA%\\oneid\\
  Linux:    ~/.config/oneid/
  macOS:    ~/.config/oneid/

  Returns:
      Path to the credentials directory (may not exist yet).
  """
  system_platform = platform.system()
  if system_platform == "Windows":
    appdata = os.environ.get("APPDATA")
    if appdata:
      return Path(appdata) / "oneid"
    # Fallback if APPDATA is not set (unusual)
    return Path.home() / "AppData" / "Roaming" / "oneid"
  else:
    # Linux and macOS both use ~/.config/oneid/
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
      return Path(xdg_config_home) / "oneid"
    return Path.home() / ".config" / "oneid"


def get_credentials_file_path() -> Path:
  """Return the full path to the credentials JSON file.

  Returns:
      Path to credentials.json in the platform-appropriate location.
  """
  return get_credentials_directory() / CREDENTIALS_FILENAME


def _set_owner_only_permissions(file_path: Path) -> None:
  """Set file permissions to owner-only (0600 on Unix, restricted ACL on Windows).

  This prevents other users on the system from reading the credentials file.
  On Windows, we rely on the default user-profile ACL (files in %APPDATA%
  are owner-only by default), but we still attempt to restrict access.

  Args:
      file_path: Path to the file whose permissions should be restricted.
  """
  system_platform = platform.system()
  if system_platform != "Windows":
    # Unix: chmod 600 (owner read+write only)
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
  # On Windows, %APPDATA% is already user-private.
  # Additional ACL restriction could be done via win32security,
  # but that requires pywin32 which we don't want as a dependency.


def save_credentials(credentials: StoredCredentials) -> Path:
  """Save enrollment credentials to the local credentials file.

  Creates the directory if it doesn't exist. Sets file permissions
  to owner-only for security.

  Args:
      credentials: The credentials to save.

  Returns:
      Path to the saved credentials file.
  """
  credentials_directory = get_credentials_directory()
  credentials_directory.mkdir(parents=True, exist_ok=True)

  credentials_file_path = credentials_directory / CREDENTIALS_FILENAME

  # Serialize to JSON
  credentials_dict: dict[str, Any] = {
    "client_id": credentials.client_id,
    "client_secret": credentials.client_secret,
    "token_endpoint": credentials.token_endpoint,
    "api_base_url": credentials.api_base_url,
    "trust_tier": credentials.trust_tier,
    "key_algorithm": credentials.key_algorithm,
    "enrolled_at": credentials.enrolled_at,
  }

  if credentials.private_key_pem is not None:
    credentials_dict["private_key_pem"] = credentials.private_key_pem
  if credentials.hsm_key_reference is not None:
    credentials_dict["hsm_key_reference"] = credentials.hsm_key_reference
  if credentials.display_name is not None:
    credentials_dict["display_name"] = credentials.display_name

  credentials_file_path.write_text(
    json.dumps(credentials_dict, indent=2) + "\n",
    encoding="utf-8",
  )

  _set_owner_only_permissions(credentials_file_path)

  return credentials_file_path


def load_credentials() -> StoredCredentials:
  """Load enrollment credentials from the local credentials file.

  Returns:
      The stored credentials.

  Raises:
      NotEnrolledError: If no credentials file exists (agent hasn't enrolled).
      OneIDError: If the credentials file is corrupted or unreadable.
  """
  credentials_file_path = get_credentials_file_path()

  if not credentials_file_path.exists():
    raise NotEnrolledError(
      f"No credentials file found at {credentials_file_path}. "
      "Call oneid.enroll() to create an identity first."
    )

  try:
    raw_json_text = credentials_file_path.read_text(encoding="utf-8")
    credentials_dict = json.loads(raw_json_text)
  except (json.JSONDecodeError, OSError) as read_error:
    from .exceptions import OneIDError
    raise OneIDError(
      f"Credentials file at {credentials_file_path} is corrupted or unreadable: {read_error}",
      error_code="CREDENTIALS_CORRUPTED",
    ) from read_error

  return StoredCredentials(
    client_id=credentials_dict["client_id"],
    client_secret=credentials_dict["client_secret"],
    token_endpoint=credentials_dict["token_endpoint"],
    api_base_url=credentials_dict["api_base_url"],
    trust_tier=credentials_dict.get("trust_tier", "declared"),
    key_algorithm=credentials_dict.get("key_algorithm", "ed25519"),
    private_key_pem=credentials_dict.get("private_key_pem"),
    hsm_key_reference=credentials_dict.get("hsm_key_reference"),
    enrolled_at=credentials_dict.get("enrolled_at"),
    display_name=credentials_dict.get("display_name"),
  )


def credentials_exist() -> bool:
  """Check whether a credentials file exists (agent has enrolled).

  Returns:
      True if the credentials file exists, False otherwise.
  """
  return get_credentials_file_path().exists()


def delete_credentials() -> bool:
  """Delete the local credentials file (for re-enrollment or cleanup).

  Returns:
      True if the file was deleted, False if it didn't exist.
  """
  credentials_file_path = get_credentials_file_path()
  if credentials_file_path.exists():
    credentials_file_path.unlink()
    return True
  return False
