"""Regression tests for two-step TPM device addition."""

from unittest.mock import patch

from oneid.credentials import StoredCredentials
from oneid import devices


def _create_existing_sovereign_identity_credentials_for_device_addition():
  """Return credentials proving the additional-TPM path is not declared-only."""
  return StoredCredentials(
    client_id="id-aaaaa-bbbbb-ccccc-ddddd",
    client_secret="secret",
    token_endpoint="https://example.test/token",
    api_base_url="https://example.test",
    trust_tier="sovereign",
    key_algorithm="tpm-ak",
    hsm_key_reference="transient",
  )


@patch("oneid.world.invalidate_world_cache")
@patch("oneid.helper.activate_credential", return_value="decrypted-secret-base64")
@patch("oneid.helper.extract_attestation_data")
@patch("oneid.helper.detect_available_hsms")
@patch("oneid.devices._make_authenticated_request")
def test_existing_hardware_identity_adds_tpm_only_after_activate_credential(
  make_authenticated_request,
  detect_available_hsms,
  extract_attestation_data,
  activate_credential,
  _invalidate_world_cache,
):
  detected_tpm = {"type": "tpm", "manufacturer": "test"}
  detect_available_hsms.return_value = [detected_tpm]
  extract_attestation_data.return_value = {
    "ek_cert_pem": "EK certificate",
    "ak_public_pem": "AK public key",
    "ak_tpmt_public_b64": "TPMT public",
    "ek_public_pem": "legacy ignored EK key",
    "chain_pem": ["manufacturer intermediate"],
    "ak_handle": "transient",
  }
  make_authenticated_request.side_effect = [
    {
      "binding_session_id": "session-1",
      "credential_blob": "credential-blob",
      "encrypted_secret": "encrypted-secret",
    },
    {
      "device_type": "tpm",
      "device_fingerprint": "canonical-anchor",
      "trust_tier": "sovereign",
      "identity_upgraded": False,
    },
  ]

  result = devices.add(
    device_type="tpm",
    credentials=_create_existing_sovereign_identity_credentials_for_device_addition(),
  )

  assert result.device_fingerprint == "canonical-anchor"
  assert [request_call.args[1] for request_call in make_authenticated_request.call_args_list] == [
    "/api/v1/identity/devices/add/tpm/begin",
    "/api/v1/identity/devices/add/tpm/activate",
  ]
  activate_credential.assert_called_once_with(
    detected_tpm,
    credential_blob_b64="credential-blob",
    encrypted_secret_b64="encrypted-secret",
    ak_handle="transient",
  )
  activation_request_body = make_authenticated_request.call_args_list[1].kwargs["json_body"]
  assert activation_request_body == {
    "binding_session_id": "session-1",
    "decrypted_credential": "decrypted-secret-base64",
  }
