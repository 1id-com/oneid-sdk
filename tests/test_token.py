"""
Tests for access-token acquisition and caching.

Verifies:
- Declared-tier Binding-Proof Authentication: challenge -> nonce signed with
  the enrolled software key -> verify (registry draft: a static client_secret
  MUST NOT substitute for binding proof; external review 072 #6)
- No client_secret is ever sent
- Token caching (returns cached token when valid), force_refresh, clearing
- Proper error handling for auth failures
- NotEnrolledError when no credentials exist
"""

import base64
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from oneid.auth import (
  authenticate_with_declared_software_key,
  clear_cached_token,
  get_token,
)
from oneid.credentials import StoredCredentials
from oneid.exceptions import AuthenticationError, NetworkError, NotEnrolledError
from oneid.identity import Token

ENROLLED_KEY = ec.generate_private_key(ec.SECP256R1())
NONCE = b"\x07" * 32


def _make_test_stored_credentials(private_key_pem=None) -> StoredCredentials:
  return StoredCredentials(
    client_id="id-tsthj-zhshb-sqpck-bghgw",
    client_secret="test-secret-that-must-never-be-sent",
    token_endpoint="https://1id.com/realms/agents/protocol/openid-connect/token",
    api_base_url="https://1id.com",
    trust_tier="declared",
    key_algorithm="ecdsa-p256",
    private_key_pem=private_key_pem if private_key_pem is not None else ENROLLED_KEY.private_bytes(
      serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
  )


def _response(status_code, body):
  response = MagicMock()
  response.status_code = status_code
  response.json.return_value = body
  return response


def _challenge_then_verify_responses(mock_keycloak_token_response):
  def responses():
    while True:
      yield _response(200, {"ok": True, "data": {
        "challenge_id": "ch_test", "nonce_b64": base64.b64encode(NONCE).decode(), "device_type": "declared"}})
      yield _response(200, {"ok": True, "data": {"authenticated": True, "tokens": mock_keycloak_token_response}})
  return responses()


class TestDeclaredBindingProofAuthentication:
  def setup_method(self):
    clear_cached_token()

  def test_nonce_is_signed_by_the_enrolled_key_and_no_secret_is_sent(self, mock_keycloak_token_response):
    with patch("oneid.auth.httpx.Client") as MockHTTP:
      http = MockHTTP.return_value.__enter__.return_value
      http.post.side_effect = _challenge_then_verify_responses(mock_keycloak_token_response)
      token = authenticate_with_declared_software_key(credentials=_make_test_stored_credentials())

    assert isinstance(token, Token) and token.access_token == mock_keycloak_token_response["access_token"]
    challenge_call, verify_call = http.post.call_args_list
    assert challenge_call.args[0].endswith("/api/v1/auth/challenge")
    assert challenge_call.kwargs["json"] == {"identity_id": "id-tsthj-zhshb-sqpck-bghgw", "device_type": "declared"}
    verify_body = verify_call.kwargs["json"]
    assert verify_call.args[0].endswith("/api/v1/auth/verify")
    presented_key = serialization.load_pem_public_key(verify_body["public_key_pem"].encode())
    presented_key.verify(base64.b64decode(verify_body["signature_b64"]), NONCE, ec.ECDSA(hashes.SHA256()))
    assert presented_key.public_numbers() == ENROLLED_KEY.public_key().public_numbers()
    for call in http.post.call_args_list:
      assert "test-secret-that-must-never-be-sent" not in repr(call)

  def test_get_token_uses_binding_proof_for_declared(self, mock_keycloak_token_response):
    with patch("oneid.auth.httpx.Client") as MockHTTP:
      http = MockHTTP.return_value.__enter__.return_value
      http.post.side_effect = _challenge_then_verify_responses(mock_keycloak_token_response)
      get_token(credentials=_make_test_stored_credentials())
    assert [call.args[0].rsplit("/", 1)[-1] for call in http.post.call_args_list] == ["challenge", "verify"]

  def test_missing_enrolled_key_raises(self):
    with pytest.raises(AuthenticationError, match="no enrolled signing key"):
      authenticate_with_declared_software_key(credentials=_make_test_stored_credentials(private_key_pem=""))

  def test_rejected_proof_raises_authentication_error(self):
    with patch("oneid.auth.httpx.Client") as MockHTTP:
      http = MockHTTP.return_value.__enter__.return_value
      http.post.side_effect = [
        _response(200, {"ok": True, "data": {"challenge_id": "ch_test", "nonce_b64": base64.b64encode(NONCE).decode()}}),
        _response(401, {"ok": False, "error": {"message": "The presented key is not this identity's enrolled key."}}),
      ]
      with pytest.raises(AuthenticationError, match="not this identity's enrolled key"):
        authenticate_with_declared_software_key(credentials=_make_test_stored_credentials())

  def test_network_errors_raise_network_error(self):
    from oneid import _http
    for failure in (_http.ConnectError("Connection refused"), _http.TimeoutException("Timed out")):
      with patch("oneid.auth.httpx.Client") as MockHTTP:
        MockHTTP.return_value.__enter__.return_value.post.side_effect = failure
        with pytest.raises(NetworkError):
          authenticate_with_declared_software_key(credentials=_make_test_stored_credentials())


class TestTokenCaching:
  """Test the in-memory token cache (each login = challenge + verify)."""

  def setup_method(self):
    clear_cached_token()

  def _count_logins(self, mock_keycloak_token_response, action):
    creds = _make_test_stored_credentials()
    with patch("oneid.auth.httpx.Client") as MockHTTP:
      http = MockHTTP.return_value.__enter__.return_value
      http.post.side_effect = _challenge_then_verify_responses(mock_keycloak_token_response)
      action(creds)
    return http.post.call_count // 2

  def test_second_call_returns_cached_token(self, mock_keycloak_token_response):
    def action(creds):
      assert get_token(credentials=creds).access_token == get_token(credentials=creds).access_token
    assert self._count_logins(mock_keycloak_token_response, action) == 1

  def test_force_refresh_bypasses_cache(self, mock_keycloak_token_response):
    def action(creds):
      get_token(credentials=creds)
      get_token(credentials=creds, force_refresh=True)
    assert self._count_logins(mock_keycloak_token_response, action) == 2

  def test_clear_cached_token_forces_new_request(self, mock_keycloak_token_response):
    def action(creds):
      get_token(credentials=creds)
      clear_cached_token()
      get_token(credentials=creds)
    assert self._count_logins(mock_keycloak_token_response, action) == 2


class TestGetTokenWithoutCredentials:
  """Test get_token() when no credentials exist."""

  def setup_method(self):
    clear_cached_token()

  def test_get_token_without_enrollment_raises_not_enrolled(self, isolated_credentials_directory):
    """Calling get_token() before enrollment should raise NotEnrolledError."""
    with pytest.raises(NotEnrolledError):
      get_token()
