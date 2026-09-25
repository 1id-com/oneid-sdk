"""AUD-F55: the token cache is per identity (a second identity never receives the
first one's token). AUD-F66 / AUD-LOST1: the enrolled local device, not the
trust tier, selects PIV / TPM / Secure Enclave. Mirrors oneid-node
src/test/test_identity_scoped_token_cache_and_local_device_routing.ts."""

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from oneid import auth
from oneid.credentials import StoredCredentials, local_signing_device_type_for_credentials
from oneid.identity import Token


def credentials_with(**fields) -> StoredCredentials:
  defaults = dict(client_id="id-aaaaa-bbbbb-ccccc-ddddd", client_secret="", token_endpoint="",
                  api_base_url="", trust_tier="declared", key_algorithm="ecdsa-p256")
  defaults.update(fields)
  return StoredCredentials(**defaults)


@pytest.mark.parametrize("fields, expected_device", [
  (dict(trust_tier="sovereign", hsm_key_reference="piv-slot-9a"), "piv"),
  (dict(trust_tier="sovereign", hsm_key_reference="secure-enclave"), "enclave"),
  (dict(trust_tier="portable", hsm_key_reference="0x81000100"), "tpm"),
  (dict(trust_tier="portable"), "piv"),
  (dict(trust_tier="enclave"), "enclave"),
  (dict(trust_tier="virtual"), "tpm"),
  (dict(trust_tier="declared", private_key_pem="PEM"), "software"),
  (dict(trust_tier="declared"), None),
])
def test_the_enrolled_local_binding_decides_the_signing_device(fields, expected_device):
  assert local_signing_device_type_for_credentials(credentials_with(**fields)) == expected_device


def test_sovereign_identity_with_an_enclave_binding_logs_in_with_the_enclave():
  enclave_token = Token(access_token="AT-enclave", token_type="Bearer", refresh_token=None, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
  with mock.patch.object(auth, "authenticate_with_enclave", return_value=enclave_token) as enclave_login, \
       mock.patch.object(auth, "authenticate_with_tpm") as tpm_login:
    auth.clear_cached_token()
    token = auth.get_token(credentials=credentials_with(trust_tier="sovereign", hsm_key_reference="secure-enclave"))
  assert token.access_token == "AT-enclave"
  enclave_login.assert_called_once()
  tpm_login.assert_not_called()
  auth.clear_cached_token()


def test_a_cached_token_is_only_returned_to_the_identity_it_was_issued_to():
  issued = []

  def issue_token(credentials):
    issued.append(credentials.client_id)
    return Token(access_token=f"AT-{len(issued)}", token_type="Bearer", refresh_token=None, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))

  identity_a = credentials_with(client_id="id-aaaaa-aaaaa-aaaaa-aaaaa", private_key_pem="PEM-A")
  identity_b = credentials_with(client_id="id-bbbbb-bbbbb-bbbbb-bbbbb", private_key_pem="PEM-B")
  with mock.patch.object(auth, "authenticate_with_declared_software_key", side_effect=issue_token):
    auth.clear_cached_token()
    first_a = auth.get_token(credentials=identity_a)
    second_a = auth.get_token(credentials=identity_a)
    first_b = auth.get_token(credentials=identity_b)
  auth.clear_cached_token()
  assert first_a.access_token == "AT-1"
  assert second_a.access_token == "AT-1"
  assert first_b.access_token == "AT-2"
  assert issued == ["id-aaaaa-aaaaa-aaaaa-aaaaa", "id-bbbbb-bbbbb-bbbbb-bbbbb"]


@pytest.mark.parametrize("fields, expected_hsm_type", [
  (dict(trust_tier="sovereign", hsm_key_reference="piv-slot-9a"), "yubikey"),
  (dict(trust_tier="sovereign", hsm_key_reference="secure-enclave"), "secure_enclave"),
  (dict(trust_tier="virtual", hsm_key_reference="0x81000100"), "tpm"),
  (dict(trust_tier="declared", private_key_pem="PEM"), "software"),
])
def test_local_identity_reports_the_enrolled_device_type(fields, expected_hsm_type):
  """AUD-F59: reconstruction no longer reports every key reference as a TPM."""
  import oneid
  with mock.patch("oneid.load_credentials", return_value=credentials_with(**fields)):
    assert oneid._build_identity_from_local_credentials().hsm_type.value == expected_hsm_type
