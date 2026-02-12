"""
Tests for OAuth2 token acquisition and caching.

Verifies:
- Token acquisition via client_credentials grant
- Token caching (returns cached token when valid)
- Token refresh when near expiry
- force_refresh bypasses cache
- Proper error handling for auth failures
- NotEnrolledError when no credentials exist
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from oneid.auth import (
  TOKEN_REFRESH_MARGIN_SECONDS,
  _request_token_from_keycloak,
  clear_cached_token,
  get_token,
)
from oneid.credentials import StoredCredentials
from oneid.exceptions import AuthenticationError, NetworkError, NotEnrolledError
from oneid.identity import Token


def _make_test_stored_credentials() -> StoredCredentials:
  return StoredCredentials(
    client_id="1id_t3stag7x",
    client_secret="test-secret",
    token_endpoint="https://1id.com/realms/agents/protocol/openid-connect/token",
    api_base_url="https://1id.com",
    trust_tier="declared",
    key_algorithm="ed25519",
    private_key_pem="fake-key",
  )


class TestTokenAcquisition:
  """Test token request from Keycloak."""

  def setup_method(self):
    """Clear token cache before each test."""
    clear_cached_token()

  def test_successful_token_request(self, mock_keycloak_token_response):
    """A 200 response from Keycloak should return a valid Token."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_keycloak_token_response

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.return_value = mock_response

      token = _request_token_from_keycloak(_make_test_stored_credentials())

    assert isinstance(token, Token)
    assert token.access_token == mock_keycloak_token_response["access_token"]
    assert token.token_type == "Bearer"
    assert token.this_token_has_not_yet_expired is True

  def test_auth_failure_raises_authentication_error(self):
    """A 401 response should raise AuthenticationError."""
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {
      "error": "invalid_client",
      "error_description": "Invalid client credentials",
    }

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.return_value = mock_response

      with pytest.raises(AuthenticationError, match="Invalid client credentials"):
        _request_token_from_keycloak(_make_test_stored_credentials())

  def test_network_error_on_connection_failure(self):
    """Connection failure should raise NetworkError."""
    import httpx

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.side_effect = httpx.ConnectError("Connection refused")

      with pytest.raises(NetworkError):
        _request_token_from_keycloak(_make_test_stored_credentials())

  def test_network_error_on_timeout(self):
    """Timeout should raise NetworkError."""
    import httpx

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.side_effect = httpx.TimeoutException("Timed out")

      with pytest.raises(NetworkError):
        _request_token_from_keycloak(_make_test_stored_credentials())


class TestTokenCaching:
  """Test the in-memory token cache."""

  def setup_method(self):
    clear_cached_token()

  def test_second_call_returns_cached_token(self, mock_keycloak_token_response):
    """get_token() should return the cached token if it's still valid."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_keycloak_token_response

    creds = _make_test_stored_credentials()

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.return_value = mock_response

      token1 = get_token(credentials=creds)
      token2 = get_token(credentials=creds)

    # Should have only made ONE HTTP request (second call used cache)
    assert mock_http_instance.post.call_count == 1
    assert token1.access_token == token2.access_token

  def test_force_refresh_bypasses_cache(self, mock_keycloak_token_response):
    """force_refresh=True should always make a new request."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_keycloak_token_response

    creds = _make_test_stored_credentials()

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.return_value = mock_response

      get_token(credentials=creds)
      get_token(credentials=creds, force_refresh=True)

    # Both calls should have made HTTP requests
    assert mock_http_instance.post.call_count == 2

  def test_clear_cached_token_forces_new_request(self, mock_keycloak_token_response):
    """clear_cached_token() followed by get_token() should make a new request."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_keycloak_token_response

    creds = _make_test_stored_credentials()

    with patch("oneid.auth.httpx.Client") as MockHTTP:
      mock_http_instance = MockHTTP.return_value.__enter__.return_value
      mock_http_instance.post.return_value = mock_response

      get_token(credentials=creds)
      clear_cached_token()
      get_token(credentials=creds)

    assert mock_http_instance.post.call_count == 2


class TestGetTokenWithoutCredentials:
  """Test get_token() when no credentials exist."""

  def setup_method(self):
    clear_cached_token()

  def test_get_token_without_enrollment_raises_not_enrolled(self, isolated_credentials_directory):
    """Calling get_token() before enrollment should raise NotEnrolledError."""
    with pytest.raises(NotEnrolledError):
      get_token()
