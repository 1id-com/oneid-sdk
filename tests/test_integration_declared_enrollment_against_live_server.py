"""
Integration test: declared-tier enrollment against the LIVE 1id.com server.

This test calls the real production API and creates a real identity.
Run manually -- NOT in CI (it creates persistent state on the server).

Usage:
    python -m pytest tests/test_integration_declared_enrollment_against_live_server.py -v -s
"""

import pytest
import httpx
import secrets
import sys
import os

# Add the parent directory to the path so we can import oneid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from oneid.enroll import enroll
from oneid.identity import Identity, TrustTier
from oneid.client import OneIDAPIClient

LIVE_API_BASE_URL = "https://1id.com"


def _server_is_reachable():
  """Check if the live server is reachable before running tests."""
  import urllib.request
  import ssl
  try:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(f"{LIVE_API_BASE_URL}/api/health")
    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
    return resp.status == 200
  except Exception:
    return False


# Skip the entire module if the server is not reachable
pytestmark = pytest.mark.skipif(
  not _server_is_reachable(),
  reason="Live server at 1id.com is not reachable"
)


class TestDeclaredEnrollmentAgainstLiveServer:
  """End-to-end integration tests for declared-tier enrollment."""

  def test_enroll_declared_tier_creates_real_identity_with_random_handle(self):
    """Enroll at declared tier with a random unique handle and verify the response."""
    random_suffix = secrets.token_hex(4)
    handle_name = f"integration-test-{random_suffix}"

    identity = enroll(
      request_tier="declared",
      requested_handle=handle_name,
      key_algorithm="ed25519",
      api_base_url=LIVE_API_BASE_URL,
    )

    assert isinstance(identity, Identity)
    assert identity.internal_id.startswith("1id_")
    assert len(identity.internal_id) == 12  # "1id_" + 8 chars
    assert identity.trust_tier == TrustTier.DECLARED
    assert identity.handle == f"@{handle_name}"
    print(f"\n  Enrolled: {identity.internal_id} as {identity.handle}")

  def test_enroll_declared_tier_without_handle(self):
    """Enroll at declared tier without a vanity handle."""
    identity = enroll(
      request_tier="declared",
      key_algorithm="ecdsa-p256",
      api_base_url=LIVE_API_BASE_URL,
    )

    assert isinstance(identity, Identity)
    assert identity.internal_id.startswith("1id_")
    # Handle should be @1id_XXXXXXXX (the internal ID)
    assert identity.handle.startswith("@1id_") or identity.handle.startswith("@")
    assert identity.trust_tier == TrustTier.DECLARED
    print(f"\n  Enrolled: {identity.internal_id} as {identity.handle}")

  def test_identity_lookup_after_enrollment(self):
    """Enroll, then look up the identity via the public API."""
    random_suffix = secrets.token_hex(4)
    handle_name = f"lookup-test-{random_suffix}"

    identity = enroll(
      request_tier="declared",
      requested_handle=handle_name,
      key_algorithm="ed25519",
      api_base_url=LIVE_API_BASE_URL,
    )

    # Now look it up
    api_client = OneIDAPIClient(api_base_url=LIVE_API_BASE_URL)
    lookup_data = api_client.get_identity(identity.internal_id)

    assert lookup_data["internal_id"] == identity.internal_id
    assert lookup_data["handle"] == f"@{handle_name}"
    assert lookup_data["trust_tier"] == "declared"
    assert lookup_data["status"] == "active"
    print(f"\n  Looked up: {lookup_data['internal_id']} = {lookup_data['handle']}")

  def test_handle_availability_check(self):
    """Check that a fresh handle is available, then claim it, then check again."""
    random_suffix = secrets.token_hex(4)
    handle_name = f"avail-test-{random_suffix}"

    api_client = OneIDAPIClient(api_base_url=LIVE_API_BASE_URL)

    # Should be available
    avail_result = api_client.check_handle_availability(handle_name)
    assert avail_result["status"] == "available"

    # Enroll with it
    enroll(
      request_tier="declared",
      requested_handle=handle_name,
      key_algorithm="ed25519",
      api_base_url=LIVE_API_BASE_URL,
    )

    # Should now be taken
    taken_result = api_client.check_handle_availability(handle_name)
    assert taken_result["status"] == "active"
    print(f"\n  Handle '@{handle_name}': available -> enrolled -> active")

  def test_duplicate_handle_is_rejected(self):
    """Try to enroll with an already-taken handle and verify the error."""
    from oneid.exceptions import HandleTakenError

    random_suffix = secrets.token_hex(4)
    handle_name = f"dup-test-{random_suffix}"

    # First enrollment should succeed
    enroll(
      request_tier="declared",
      requested_handle=handle_name,
      key_algorithm="ed25519",
      api_base_url=LIVE_API_BASE_URL,
    )

    # Second enrollment with same handle should fail
    with pytest.raises(HandleTakenError):
      enroll(
        request_tier="declared",
        requested_handle=handle_name,
        key_algorithm="ed25519",
        api_base_url=LIVE_API_BASE_URL,
      )

    print(f"\n  Duplicate handle '@{handle_name}' correctly rejected")

  def test_enrolled_agent_jwt_contains_oneid_claims(self):
    """Enroll, get a token, decode it, and verify 1id custom claims are present."""
    import base64
    import json as json_module
    from oneid.keys import generate_keypair
    from oneid.identity import KeyAlgorithm

    random_suffix = secrets.token_hex(4)
    handle_name = f"jwt-test-{random_suffix}"

    # Use the API client directly so we can capture the credentials
    api_client = OneIDAPIClient(api_base_url=LIVE_API_BASE_URL)
    _, public_key_pem_bytes = generate_keypair(KeyAlgorithm.ED25519)
    server_response = api_client.enroll_declared(
      software_key_pem=public_key_pem_bytes.decode("utf-8"),
      key_algorithm="ed25519",
      requested_handle=handle_name,
    )

    credentials = server_response.get("credentials", {})
    client_id = credentials["client_id"]
    client_secret = credentials["client_secret"]

    # Use the credentials to get a token
    token_response = api_client.get_token_with_client_credentials(
      client_id,
      client_secret,
    )
    access_token = token_response["access_token"]

    # Decode the JWT payload (no signature verification -- just inspection)
    payload_b64 = access_token.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
      payload_b64 += "=" * padding
    claims = json_module.loads(base64.urlsafe_b64decode(payload_b64))

    # Verify 1id claims
    assert claims.get("trust_tier") == "declared", f"trust_tier missing or wrong: {claims}"
    assert claims.get("handle") == f"@{handle_name}", f"handle missing or wrong: {claims}"
    assert claims.get("registered_at") is not None, f"registered_at missing: {claims}"
    internal_id = server_response.get("identity", {}).get("internal_id")
    assert claims.get("sub") == internal_id, f"sub should be 1id internal_id: {claims}"
    assert claims.get("iss") == "https://1id.com/realms/agents", f"issuer wrong: {claims}"

    # For declared tier, TPM claims should be absent
    assert claims.get("tpm_manufacturer") is None, "declared tier should not have tpm_manufacturer"
    assert claims.get("ek_fingerprint_prefix") is None, "declared tier should not have ek_fingerprint_prefix"

    print(f"\n  JWT claims verified for {internal_id}:")
    print(f"    trust_tier:    {claims['trust_tier']}")
    print(f"    handle:        {claims['handle']}")
    print(f"    registered_at: {claims['registered_at']}")
    print(f"    sub:           {claims['sub']}")
    print(f"    iss:           {claims['iss']}")
