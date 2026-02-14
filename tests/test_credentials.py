"""
Tests for credential storage and retrieval.

Verifies:
- Credentials can be saved and loaded
- Platform-appropriate directory is used
- File permissions are restrictive
- Missing credentials raise NotEnrolledError
- Corrupted credentials raise OneIDError
- Delete works correctly
- All fields round-trip correctly
"""

import json
import os
import platform
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from oneid.credentials import (
  StoredCredentials,
  credentials_exist,
  delete_credentials,
  get_credentials_directory,
  get_credentials_file_path,
  load_credentials,
  save_credentials,
)
from oneid.exceptions import NotEnrolledError, OneIDError


def _make_test_credentials(**overrides) -> StoredCredentials:
  """Create a StoredCredentials instance with sensible test defaults."""
  defaults = {
    "client_id": "1id-t3stag7x",
    "client_secret": "test-secret-value-not-for-production",
    "token_endpoint": "https://1id.com/realms/agents/protocol/openid-connect/token",
    "api_base_url": "https://1id.com",
    "trust_tier": "declared",
    "key_algorithm": "ed25519",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFake==\n-----END PRIVATE KEY-----\n",
    "enrolled_at": "2026-02-11T12:00:00Z",
  }
  defaults.update(overrides)
  return StoredCredentials(**defaults)


class TestCredentialsDirectoryPlatformSelection:
  """Verify the correct directory is chosen per platform."""

  @patch("oneid.credentials.platform.system", return_value="Windows")
  @patch.dict(os.environ, {"APPDATA": "C:\\Users\\TestBot\\AppData\\Roaming"})
  def test_windows_uses_appdata(self, _mock_system):
    result = get_credentials_directory()
    assert "AppData" in str(result) or "appdata" in str(result).lower()
    assert str(result).endswith("oneid")

  @patch("oneid.credentials.platform.system", return_value="Linux")
  @patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}, clear=False)
  def test_linux_uses_dot_config(self, _mock_system):
    result = get_credentials_directory()
    assert ".config" in str(result) or "oneid" in str(result)

  @patch("oneid.credentials.platform.system", return_value="Linux")
  @patch.dict(os.environ, {"XDG_CONFIG_HOME": "/custom/config"})
  def test_linux_respects_xdg_config_home(self, _mock_system):
    result = get_credentials_directory()
    # On Windows, Path("/custom/config") becomes WindowsPath('\\custom\\config'),
    # so we normalize with as_posix() for cross-platform comparison.
    assert result.as_posix().startswith("/custom/config")


class TestSaveAndLoadCredentials:
  """Verify credential save/load round-trip."""

  def test_save_and_load_round_trip(self, isolated_credentials_directory):
    """Saved credentials should load back identically."""
    original = _make_test_credentials()
    save_credentials(original)

    loaded = load_credentials()

    assert loaded.client_id == original.client_id
    assert loaded.client_secret == original.client_secret
    assert loaded.token_endpoint == original.token_endpoint
    assert loaded.api_base_url == original.api_base_url
    assert loaded.trust_tier == original.trust_tier
    assert loaded.key_algorithm == original.key_algorithm
    assert loaded.private_key_pem == original.private_key_pem
    assert loaded.enrolled_at == original.enrolled_at

  def test_save_and_load_with_hsm_key_reference(self, isolated_credentials_directory):
    """HSM key references should round-trip correctly."""
    original = _make_test_credentials(
      trust_tier="sovereign",
      key_algorithm="tpm-ak",
      private_key_pem=None,
      hsm_key_reference="tpm:ak:0x81000001",
    )
    save_credentials(original)
    loaded = load_credentials()

    assert loaded.hsm_key_reference == "tpm:ak:0x81000001"
    assert loaded.private_key_pem is None

  def test_save_creates_directory_if_missing(self, tmp_path):
    """save_credentials should create the directory tree if it doesn't exist."""
    nested_dir = tmp_path / "deep" / "nested" / "path"
    with patch("oneid.credentials.get_credentials_directory", return_value=nested_dir):
      save_credentials(_make_test_credentials())
      assert (nested_dir / "credentials.json").exists()

  def test_save_overwrites_existing_credentials(self, isolated_credentials_directory):
    """Saving new credentials should overwrite old ones."""
    save_credentials(_make_test_credentials(client_id="1id-old-one1"))
    save_credentials(_make_test_credentials(client_id="1id-new-one2"))

    loaded = load_credentials()
    assert loaded.client_id == "1id-new-one2"

  def test_credentials_file_is_valid_json(self, isolated_credentials_directory):
    """The credentials file must be valid, human-readable JSON."""
    save_credentials(_make_test_credentials())
    file_path = get_credentials_file_path()
    raw_text = file_path.read_text(encoding="utf-8")
    parsed = json.loads(raw_text)
    assert "client_id" in parsed
    assert "client_secret" in parsed


class TestFilePermissions:
  """Verify credentials file has restrictive permissions."""

  @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-only permission check")
  def test_unix_permissions_are_owner_only(self, isolated_credentials_directory):
    """On Unix, the file should be chmod 600 (owner read+write only)."""
    save_credentials(_make_test_credentials())
    file_path = get_credentials_file_path()
    file_stat = os.stat(file_path)
    mode = stat.S_IMODE(file_stat.st_mode)
    assert mode == 0o600, f"Expected 0600, got {oct(mode)}"


class TestLoadCredentialsErrors:
  """Verify error handling for missing and corrupt credentials."""

  def test_load_nonexistent_raises_not_enrolled(self, isolated_credentials_directory):
    """Loading from a nonexistent file should raise NotEnrolledError."""
    with pytest.raises(NotEnrolledError) as exc_info:
      load_credentials()
    assert "credentials" in str(exc_info.value).lower()

  def test_load_corrupted_json_raises_oneid_error(self, isolated_credentials_directory):
    """Corrupted JSON should raise OneIDError with CREDENTIALS_CORRUPTED code."""
    file_path = get_credentials_file_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text("this is not json {{{", encoding="utf-8")

    with pytest.raises(OneIDError) as exc_info:
      load_credentials()
    assert exc_info.value.error_code == "CREDENTIALS_CORRUPTED"


class TestCredentialsExistAndDelete:
  """Verify existence check and deletion."""

  def test_credentials_exist_returns_false_when_no_file(self, isolated_credentials_directory):
    assert credentials_exist() is False

  def test_credentials_exist_returns_true_after_save(self, isolated_credentials_directory):
    save_credentials(_make_test_credentials())
    assert credentials_exist() is True

  def test_delete_removes_file(self, isolated_credentials_directory):
    save_credentials(_make_test_credentials())
    assert credentials_exist() is True

    result = delete_credentials()
    assert result is True
    assert credentials_exist() is False

  def test_delete_nonexistent_returns_false(self, isolated_credentials_directory):
    result = delete_credentials()
    assert result is False
