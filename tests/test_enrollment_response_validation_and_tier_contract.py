"""AUD-F72: a successful enrollment response that does not name a valid identity
is refused and nothing is saved. AUD-F35: an explicitly requested tier is the
tier enrolled, or an exception (credentials of the identity that WAS created
are kept). Mirrors oneid-node src/test/test_enrollment_response_validation_and_tier_contract.ts."""

import copy
from unittest.mock import patch

import pytest

from oneid.credentials import credentials_exist
from oneid.enroll import enroll
from oneid.exceptions import EnrollmentError

# oneid.enroll is also the name of the exported enroll() function, so string
# patch targets resolve to the function on Python 3.8; patch the module object.
import importlib as _importlib
ENROLL_MODULE = _importlib.import_module("oneid.enroll")


def enroll_declared_with_server_response(response_data):
  with patch.object(ENROLL_MODULE, "OneIDAPIClient") as MockClient:
    MockClient.return_value.enroll_declared.return_value = response_data
    return enroll(request_tier="declared")


@pytest.mark.parametrize("breakage, message", [
  (lambda data: data.pop("identity"), "no identity object"),
  (lambda data: data["identity"].pop("agent_id"), "no valid canonical identity id"),
  (lambda data: data["identity"].update(agent_id="not-an-id"), "no valid canonical identity id"),
  (lambda data: data["identity"].pop("trust_tier"), "no valid trust tier"),
  (lambda data: data["identity"].update(trust_tier="imaginary"), "no valid trust tier"),
])
def test_malformed_success_response_is_refused_and_nothing_is_saved(
  isolated_credentials_directory, mock_server_declared_enrollment_response, breakage, message,
):
  response_data = copy.deepcopy(mock_server_declared_enrollment_response["data"])
  breakage(response_data)
  with pytest.raises(EnrollmentError, match=message):
    enroll_declared_with_server_response(response_data)
  assert not credentials_exist()


def test_a_different_tier_than_requested_raises_but_keeps_the_created_identity(
  isolated_credentials_directory, mock_server_declared_enrollment_response,
):
  response_data = copy.deepcopy(mock_server_declared_enrollment_response["data"])
  response_data["identity"]["trust_tier"] = "virtual"
  with pytest.raises(EnrollmentError, match="Requested trust tier 'declared' but the Registrar enrolled this device as 'virtual'"):
    enroll_declared_with_server_response(response_data)
  assert credentials_exist()
