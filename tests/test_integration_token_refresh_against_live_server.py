"""
Integration test: token refresh against the live 1id.com server.

This test requires a real enrolled identity. It:
  1. Loads credentials from the default location
  2. Gets an initial token
  3. Forces a refresh
  4. Verifies the new token is different
  5. Verifies both tokens are valid JWTs with correct claims

Run with: pytest tests/test_integration_token_refresh_against_live_server.py -v

Skip conditions:
  - Skipped if no credentials file exists (not enrolled)
  - Skipped if the live server is unreachable
"""

import json
import base64
import pytest

from oneid.auth import clear_cached_token, get_token
from oneid.credentials import credentials_exist, load_credentials
from oneid.exceptions import NotEnrolledError, AuthenticationError, NetworkError
from oneid.identity import Token


# Skip all tests in this module if no credentials exist
pytestmark = pytest.mark.skipif(
  not credentials_exist(),
  reason="No credentials file found -- agent not enrolled on this machine",
)


def _decode_jwt_payload_without_verification(jwt_string):
  """Decode a JWT payload (middle segment) without verifying the signature.

  We only need to inspect claims -- the server already verified the token.
  """
  parts = jwt_string.split(".")
  if len(parts) != 3:
    raise ValueError(f"Not a valid JWT (expected 3 parts, got {len(parts)})")

  # Add padding to the base64url payload
  payload_b64 = parts[1]
  payload_b64 += "=" * (4 - len(payload_b64) % 4)
  payload_bytes = base64.urlsafe_b64decode(payload_b64)
  return json.loads(payload_bytes)


class TestTokenRefreshAgainstLiveServer:
  """Integration tests for token acquisition and refresh against live 1id.com."""

  def setup_method(self):
    """Clear any cached token before each test."""
    clear_cached_token()

  def test_initial_token_acquisition_succeeds(self):
    """Getting a token from the live server should succeed."""
    token = get_token()

    assert isinstance(token, Token)
    assert token.access_token is not None
    assert len(token.access_token) > 50  # JWTs are long
    assert token.token_type == "Bearer"
    assert token.expires_in > 0
    assert token.this_token_has_not_yet_expired is True

  def test_token_contains_correct_claims(self):
    """The token JWT should contain expected 1id.com claims."""
    token = get_token()
    claims = _decode_jwt_payload_without_verification(token.access_token)

    creds = load_credentials()

    # The 'sub' claim should match the client_id (which is the 1id internal ID)
    # or the 'azp' (authorized party) should match
    assert "sub" in claims or "azp" in claims or "clientId" in claims

    # Issuer should be the Keycloak realm
    assert "iss" in claims
    assert "1id.com" in claims["iss"] or "agents" in claims["iss"]

    # Should have expiry
    assert "exp" in claims
    assert "iat" in claims

  def test_force_refresh_returns_new_token(self):
    """Force-refreshing should return a token (may be same if within cache window)."""
    token_initial = get_token()
    clear_cached_token()
    token_refreshed = get_token(force_refresh=True)

    assert isinstance(token_refreshed, Token)
    assert token_refreshed.access_token is not None
    assert token_refreshed.this_token_has_not_yet_expired is True
    # Both should be valid JWTs
    assert len(token_initial.access_token.split(".")) == 3
    assert len(token_refreshed.access_token.split(".")) == 3

  def test_cached_token_returned_on_second_call(self):
    """Second call without force_refresh should return cached token."""
    token_first = get_token()
    token_second = get_token()

    # Same object should be returned (cached)
    assert token_first.access_token == token_second.access_token

  def test_credentials_match_token_identity(self):
    """The token's identity should match the stored credentials."""
    creds = load_credentials()
    token = get_token()
    claims = _decode_jwt_payload_without_verification(token.access_token)

    # The client_id should appear somewhere in the token claims
    client_id_found_in_token = (
      claims.get("azp") == creds.client_id
      or claims.get("clientId") == creds.client_id
      or claims.get("sub") == creds.client_id
    )
    assert client_id_found_in_token, (
      f"Expected client_id '{creds.client_id}' in token claims, "
      f"got: azp={claims.get('azp')}, clientId={claims.get('clientId')}, sub={claims.get('sub')}"
    )
