"""OWN-029: the friendly display_name reaches the server on the TPM
(sovereign/virtual) and PIV (portable) enrollment paths too -- it used to be
dropped there (only declared and enclave enrollment sent it). Hardware
detection and attestation are faked; the begin request is captured and stopped.
Mirrors oneid-node src/test/test_display_name_reaches_every_enrollment_path.ts."""
from unittest.mock import patch

import pytest

import oneid.helper
from oneid.client import OneIDAPIClient
from oneid.enroll import enroll

# Never touch the real credentials file (enroll() refuses when one exists).
pytestmark = pytest.mark.usefixtures("isolated_credentials_directory")


class BeginRequestCapturedStopHere(Exception):
  """Raised by the faked begin call once the request arguments are captured."""


def _capture_begin_request_arguments_and_stop(captured_arguments):
  def fake_begin_call(self, **keyword_arguments):
    captured_arguments.update(keyword_arguments)
    raise BeginRequestCapturedStopHere()
  return fake_begin_call


@pytest.mark.parametrize("request_tier, fake_detected_hsm, client_begin_method_name", [
  ("sovereign", {"type": "tpm"}, "enroll_begin"),
  ("virtual", {"type": "tpm"}, "enroll_begin"),
  ("portable", {"type": "yubikey"}, "enroll_begin_piv"),
])
def test_display_name_is_sent_in_hardware_enrollment_begin_request(request_tier, fake_detected_hsm, client_begin_method_name):
  captured_begin_arguments = {}
  with patch.object(oneid.helper, "detect_available_hsms", return_value=[fake_detected_hsm]), \
       patch.object(oneid.helper, "extract_attestation_data", return_value={
         "ek_cert_pem": "EK", "ak_public_pem": "AK", "attestation_cert_pem": "ATT", "signing_key_public_pem": "SIG"}), \
       patch.object(OneIDAPIClient, client_begin_method_name, _capture_begin_request_arguments_and_stop(captured_begin_arguments)):
    with pytest.raises(BeginRequestCapturedStopHere):
      enroll(request_tier=request_tier, display_name="Sparky", requested_handle="sparky-test")
  assert captured_begin_arguments["display_name"] == "Sparky"
  assert captured_begin_arguments["requested_handle"] == "sparky-test"


def test_display_name_is_sent_in_declared_enrollment_request():
  captured_declared_arguments = {}
  with patch.object(OneIDAPIClient, "enroll_declared", _capture_begin_request_arguments_and_stop(captured_declared_arguments)):
    with pytest.raises(BeginRequestCapturedStopHere):
      enroll(request_tier="declared", display_name="Sparky")
  assert captured_declared_arguments["display_name"] == "Sparky"
