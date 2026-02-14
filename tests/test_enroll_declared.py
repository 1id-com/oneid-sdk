"""
Tests for declared-tier enrollment.

Verifies:
- Declared enrollment generates a keypair and calls the server
- Credentials are stored after successful enrollment
- Identity object is correctly populated
- Server errors are mapped to correct exceptions
- request_tier validation works
- No fallbacks (requesting sovereign without HSM raises NoHSMError)
- Key algorithm selection works
"""

from unittest.mock import MagicMock, patch

import pytest

import oneid
from oneid.credentials import load_credentials
from oneid.enroll import enroll
from oneid.exceptions import (
  EnrollmentError,
  HandleTakenError,
  NetworkError,
  NoHSMError,
)
from oneid.identity import KeyAlgorithm, TrustTier


class TestDeclaredTierEnrollment:
  """Test the declared-tier enrollment flow (no HSM, software keys)."""

  def test_declared_enrollment_succeeds_with_mock_server(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """Happy path: declared enrollment should return a valid Identity."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      identity = enroll(request_tier="declared")

    assert identity.internal_id == "1id-t3stag7x"
    assert identity.handle == "@1id-t3stag7x"
    assert identity.trust_tier == TrustTier.DECLARED
    assert identity.key_algorithm == KeyAlgorithm.ED25519  # default

  def test_declared_enrollment_stores_credentials(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """After enrollment, credentials should be loadable from disk."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      enroll(request_tier="declared")

    # Credentials should now exist and be loadable
    creds = load_credentials()
    assert creds.client_id == "1id-t3stag7x"
    assert creds.client_secret == "test-secret-do-not-use-in-production"
    assert creds.trust_tier == "declared"
    assert creds.private_key_pem is not None
    assert "BEGIN PRIVATE KEY" in creds.private_key_pem

  def test_declared_enrollment_sends_public_key_to_server(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """The public key (not private) should be sent to the server."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      enroll(request_tier="declared")

    # Check what was sent to the server
    call_args = mock_instance.enroll_declared.call_args
    sent_key = call_args.kwargs.get("software_key_pem") or call_args[1].get("software_key_pem")
    assert "BEGIN PUBLIC KEY" in sent_key
    assert "PRIVATE" not in sent_key  # NEVER send the private key

  def test_declared_enrollment_with_custom_key_algorithm(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """Agent should be able to choose RSA-4096 instead of Ed25519."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      identity = enroll(request_tier="declared", key_algorithm="rsa-4096")

    assert identity.key_algorithm == KeyAlgorithm.RSA_4096

    # Verify the stored key is actually RSA
    creds = load_credentials()
    assert creds.key_algorithm == "rsa-4096"
    assert "BEGIN PRIVATE KEY" in creds.private_key_pem

  def test_declared_enrollment_with_handle(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """Optional handle should be forwarded to the server."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      enroll(request_tier="declared", requested_handle="my-cool-bot")

    call_args = mock_instance.enroll_declared.call_args
    assert call_args.kwargs.get("requested_handle") == "my-cool-bot"

  def test_declared_enrollment_with_operator_email(
    self, isolated_credentials_directory, mock_server_declared_enrollment_response
  ):
    """Optional operator email should be forwarded to the server."""
    mock_response_data = mock_server_declared_enrollment_response["data"]

    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.return_value = mock_response_data

      enroll(request_tier="declared", operator_email="human@example.com")

    call_args = mock_instance.enroll_declared.call_args
    assert call_args.kwargs.get("operator_email") == "human@example.com"


class TestRequestTierValidation:
  """Test that request_tier is strictly validated with no fallbacks."""

  def test_invalid_tier_raises_enrollment_error(self, isolated_credentials_directory):
    """A nonsense tier should raise EnrollmentError."""
    with pytest.raises(EnrollmentError, match="Invalid trust tier"):
      enroll(request_tier="nonsense-tier")

  def test_empty_tier_raises_enrollment_error(self, isolated_credentials_directory):
    with pytest.raises(EnrollmentError):
      enroll(request_tier="")

  def test_sovereign_without_hsm_raises_no_hsm_error(self, isolated_credentials_directory):
    """Requesting sovereign without an HSM must raise NoHSMError, NOT fall back."""
    with patch("oneid.enroll._enroll_hsm_tier") as mock_hsm_enroll:
      mock_hsm_enroll.side_effect = NoHSMError("No TPM found")

      with pytest.raises(NoHSMError):
        enroll(request_tier="sovereign")

  def test_invalid_key_algorithm_raises_enrollment_error(self, isolated_credentials_directory):
    with pytest.raises(EnrollmentError, match="Invalid key algorithm"):
      enroll(request_tier="declared", key_algorithm="quantum-resistant-maybe")


class TestServerErrorHandling:
  """Test that server errors during enrollment are properly raised."""

  def test_handle_taken_error_from_server(self, isolated_credentials_directory):
    """Server returning HANDLE_TAKEN should raise HandleTakenError."""
    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.side_effect = HandleTakenError("Handle 'clawdia' is taken")

      with pytest.raises(HandleTakenError):
        enroll(request_tier="declared", requested_handle="clawdia")

  def test_network_error_propagates(self, isolated_credentials_directory):
    """Network errors should propagate as NetworkError."""
    with patch("oneid.enroll.OneIDAPIClient") as MockClient:
      mock_instance = MockClient.return_value
      mock_instance.enroll_declared.side_effect = NetworkError("Connection refused")

      with pytest.raises(NetworkError):
        enroll(request_tier="declared")


class TestNoFallbackRule:
  """THE critical design rule: request_tier is a requirement, not a preference.

  These tests verify that the SDK NEVER silently downgrades to a lower tier.
  """

  def test_sovereign_never_falls_back_to_declared(self, isolated_credentials_directory):
    """If sovereign fails, the caller should get an exception, never declared tier."""
    # Mock the HSM enrollment to raise NoHSMError
    with patch("oneid.enroll._enroll_hsm_tier") as mock_hsm:
      mock_hsm.side_effect = NoHSMError("No TPM")

      with pytest.raises(NoHSMError):
        enroll(request_tier="sovereign")

      # Verify no credentials were saved (enrollment failed)
      from oneid.credentials import credentials_exist
      assert not credentials_exist()

  def test_sovereign_portable_never_falls_back_to_declared(self, isolated_credentials_directory):
    """If sovereign-portable fails, no fallback."""
    with patch("oneid.enroll._enroll_hsm_tier") as mock_hsm:
      mock_hsm.side_effect = NoHSMError("No YubiKey")

      with pytest.raises(NoHSMError):
        enroll(request_tier="sovereign-portable")
