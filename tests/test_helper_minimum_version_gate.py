"""OWN-026: a found oneid-enroll helper older than the minimum this SDK needs
(2.1.0 -- the Registrar rejects the 2.0.0 enrollment proof) is replaced by a
fresh download instead of being used."""

import subprocess
from pathlib import Path
from unittest import mock

import pytest

from oneid import helper


@pytest.fixture(autouse=True)
def fresh_version_cache():
  helper._helper_versions_already_checked.clear()
  yield
  helper._helper_versions_already_checked.clear()


def run_ensure_with_cached_helper_reporting(tmp_path, version_stdout):
  cached_helper = tmp_path / "oneid-enroll-test"
  cached_helper.write_text("stub")
  completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=version_stdout, stderr="")
  with mock.patch.object(helper, "find_binary", return_value=cached_helper), \
       mock.patch.object(helper.subprocess, "run", return_value=completed), \
       mock.patch.object(helper, "_get_binary_cache_directory", return_value=tmp_path), \
       mock.patch.object(helper, "_download_binary_from_github_release",
                         side_effect=lambda name, destination: Path(destination)) as download:
    return cached_helper, helper.ensure_binary_available(), download


def test_current_helper_is_used_without_download(tmp_path):
  cached_helper, chosen, download = run_ensure_with_cached_helper_reporting(
    tmp_path, '{\n  "binary": "oneid-enroll",\n  "version": "2.2.0"\n}')
  assert chosen == cached_helper
  download.assert_not_called()


def test_stale_2_1_0_helper_is_replaced_by_a_download(tmp_path):
  _, chosen, download = run_ensure_with_cached_helper_reporting(
    tmp_path, '{"binary": "oneid-enroll", "version": "2.1.0"}')
  download.assert_called_once()
  assert chosen == tmp_path / helper._get_platform_binary_name()


def test_helper_without_a_readable_version_is_treated_as_stale(tmp_path):
  _, _, download = run_ensure_with_cached_helper_reporting(tmp_path, "not json")
  download.assert_called_once()


def test_version_parsing():
  assert helper._parse_version_triple("2.1.0") == (2, 1, 0)
  assert helper._parse_version_triple("v2.10.3") == (2, 10, 3)
  assert helper._parse_version_triple(None) == (0, 0, 0)
  assert helper._parse_version_triple("2.2.0") >= helper.MINIMUM_ONEID_ENROLL_HELPER_VERSION
  assert helper._parse_version_triple("2.1.0") < helper.MINIMUM_ONEID_ENROLL_HELPER_VERSION
