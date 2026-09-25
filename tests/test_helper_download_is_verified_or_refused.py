"""AUD-F07: a downloaded helper is installed only after its SHA-256 checksum
AND (Windows/macOS) the publisher's code signature verify; a checksum that
cannot be fetched refuses the install instead of warning and continuing.
OWN-030: the Secure Enclave helper is fetched the same way."""

import os
import platform
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

from oneid import helper
from oneid.exceptions import BinaryNotFoundError, NoHSMError


def fake_urlretrieve_writing(content: bytes):
  def fake_urlretrieve(url, destination):
    Path(destination).write_bytes(content)
    return destination, None
  return fake_urlretrieve


def test_checksum_that_cannot_be_downloaded_refuses_the_install(tmp_path):
  destination = tmp_path / "oneid-enroll-test"
  with mock.patch("urllib.request.urlretrieve", fake_urlretrieve_writing(b"x" * 200_000)), \
       mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
    with pytest.raises(BinaryNotFoundError, match="refusing to install an unverified helper"):
      helper._download_binary_from_github_release("oneid-enroll-test", destination)
  assert not destination.exists()
  assert list(tmp_path.iterdir()) == []  # the temporary download is cleaned up


def test_checksum_mismatch_refuses_the_install(tmp_path):
  destination = tmp_path / "oneid-enroll-test"
  checksum_response = mock.MagicMock()
  checksum_response.read.return_value = b"0" * 64 + b"  oneid-enroll-test\n"
  with mock.patch("urllib.request.urlretrieve", fake_urlretrieve_writing(b"x" * 200_000)), \
       mock.patch("urllib.request.urlopen", return_value=checksum_response):
    with pytest.raises(BinaryNotFoundError, match="checksum mismatch"):
      helper._download_binary_from_github_release("oneid-enroll-test", destination)
  assert not destination.exists()


def test_matching_checksum_still_requires_the_publisher_signature(tmp_path):
  import hashlib
  content = b"x" * 200_000
  destination = tmp_path / "oneid-enroll-test"
  checksum_response = mock.MagicMock()
  checksum_response.read.return_value = hashlib.sha256(content).hexdigest().encode() + b"  oneid-enroll-test\n"
  with mock.patch("urllib.request.urlretrieve", fake_urlretrieve_writing(content)), \
       mock.patch("urllib.request.urlopen", return_value=checksum_response), \
       mock.patch.object(helper, "_verify_publisher_code_signature_of_downloaded_release_asset",
                         side_effect=BinaryNotFoundError("not validly signed")) as signature_check:
    with pytest.raises(BinaryNotFoundError, match="not validly signed"):
      helper._download_binary_from_github_release("oneid-enroll-test", destination)
  signature_check.assert_called_once()
  assert not destination.exists()


@pytest.mark.skipif(platform.system() != "Windows", reason="Authenticode is Windows-only")
def test_unsigned_file_fails_the_authenticode_check(tmp_path):
  unsigned_file = tmp_path / "unsigned-helper.exe"
  unsigned_file.write_bytes(b"MZ" + os.urandom(4096))
  with pytest.raises(BinaryNotFoundError, match="not validly signed"):
    helper._verify_publisher_code_signature_of_downloaded_release_asset(unsigned_file, "unsigned-helper.exe")


@pytest.mark.skipif(platform.system() != "Windows", reason="Authenticode is Windows-only")
def test_published_signed_helper_passes_the_authenticode_check():
  cached_helper = helper._get_binary_cache_directory() / helper._get_platform_binary_name()
  if not cached_helper.exists():
    pytest.skip("no published helper cached on this machine")
  helper._verify_publisher_code_signature_of_downloaded_release_asset(cached_helper, cached_helper.name)


def test_secure_enclave_helper_exists_only_on_macos():
  with mock.patch.object(helper.platform, "system", return_value="Windows"):
    with pytest.raises(NoHSMError):
      helper.ensure_secure_enclave_helper_available()


def test_missing_secure_enclave_helper_is_downloaded_for_the_right_architecture(tmp_path):
  with mock.patch.object(helper.platform, "system", return_value="Darwin"), \
       mock.patch.object(helper.platform, "machine", return_value="arm64"), \
       mock.patch.object(helper, "_find_secure_enclave_helper_binary", return_value=None), \
       mock.patch.object(helper, "_get_binary_cache_directory", return_value=tmp_path), \
       mock.patch.object(helper, "_download_binary_from_github_release",
                         return_value=tmp_path / "oneid-se-helper") as download:
    assert helper.ensure_secure_enclave_helper_available() == tmp_path / "oneid-se-helper"
  download.assert_called_once_with("oneid-se-helper-arm64", tmp_path / "oneid-se-helper")
