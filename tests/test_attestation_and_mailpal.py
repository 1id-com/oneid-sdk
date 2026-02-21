"""
Tests for the attestation primitive (oneid.prepare_attestation)
and the mailpal convenience module (oneid.mailpal).

All network calls are mocked -- these are SDK unit tests,
not integration tests.
"""

from __future__ import annotations

import hashlib
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_credentials():
  """Return a mock StoredCredentials object."""
  creds = MagicMock()
  creds.client_id = "1id-TESTMOCK"
  creds.client_secret = "mock-secret"
  creds.api_base_url = "https://1id.com"
  creds.token_endpoint = "https://1id.com/realms/agents/protocol/openid-connect/token"
  return creds


def _mock_token():
  """Return a mock Token object."""
  from datetime import datetime, timezone, timedelta
  token = MagicMock()
  token.access_token = "mock-access-token-xyz"
  token.token_type = "Bearer"
  token.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
  return token


# ---------------------------------------------------------------------------
# Tests: prepare_attestation
# ---------------------------------------------------------------------------

class TestPrepareAttestation:
  """Test the oneid.prepare_attestation() core primitive."""

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof")
  def test_returns_attestation_proof_with_all_artifacts(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("signed.jwt.here", {"1id_trust_tier": "disc123"})
    mock_fetch_contact.return_value = ("a1b2c3d4", "a1b2c3d4.testhandle@1id.com")

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(content=b"test content")

    assert proof.sd_jwt == "signed.jwt.here"
    assert proof.sd_jwt_disclosures == {"1id_trust_tier": "disc123"}
    assert proof.contact_token == "a1b2c3d4"
    assert proof.contact_address == "a1b2c3d4.testhandle@1id.com"

    expected_digest = "sha256:" + hashlib.sha256(b"test content").hexdigest()
    assert proof.content_digest == expected_digest

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof")
  def test_accepts_pre_computed_content_digest(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("jwt", {})
    mock_fetch_contact.return_value = (None, None)

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(content_digest="sha256:abc123")

    assert proof.content_digest == "sha256:abc123"

  def test_rejects_both_content_and_digest(self):
    from oneid.attestation import prepare_attestation
    with pytest.raises(ValueError, match="not both"):
      prepare_attestation(content=b"data", content_digest="sha256:abc")

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof")
  def test_skips_sd_jwt_when_disabled(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_contact.return_value = ("tok", "addr")

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(include_sd_jwt=False)

    mock_fetch_sd_jwt.assert_not_called()
    assert proof.sd_jwt is None

  @patch("oneid.attestation.get_token")
  @patch("oneid.attestation.load_credentials")
  @patch("oneid.attestation._fetch_contact_token")
  @patch("oneid.attestation._fetch_sd_jwt_proof")
  def test_skips_contact_token_when_disabled(
    self,
    mock_fetch_sd_jwt,
    mock_fetch_contact,
    mock_load_creds,
    mock_get_token,
  ):
    mock_load_creds.return_value = _mock_credentials()
    mock_get_token.return_value = _mock_token()
    mock_fetch_sd_jwt.return_value = ("jwt", {})

    from oneid.attestation import prepare_attestation
    proof = prepare_attestation(include_contact_token=False)

    mock_fetch_contact.assert_not_called()
    assert proof.contact_token is None


# ---------------------------------------------------------------------------
# Tests: mailpal.send
# ---------------------------------------------------------------------------

class TestMailpalSend:
  """Test oneid.mailpal.send() convenience wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.prepare_attestation")
  @patch("oneid.mailpal.httpx.Client")
  def test_sends_email_with_attestation_headers(
    self,
    mock_httpx_client_class,
    mock_prepare,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_proof = MagicMock()
    mock_proof.sd_jwt = "signed.sd.jwt"
    mock_proof.contact_token = "a1b2c3d4"
    mock_proof.content_digest = "sha256:deadbeef"
    mock_prepare.return_value = mock_proof

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"message_id": "msg-001", "from": "agent@mailpal.com"}}

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="Test",
      text_body="Hello from test",
    )

    assert result.message_id == "msg-001"
    assert result.attestation_headers_included is True
    assert result.sd_jwt_header_included is True
    assert result.contact_token_header_included is True

    call_args = mock_http_client.post.call_args
    sent_json = call_args.kwargs.get("json") or call_args[1].get("json")
    assert "custom_headers" in sent_json
    assert sent_json["custom_headers"]["X-1ID-Proof"] == "signed.sd.jwt"
    assert sent_json["custom_headers"]["X-1ID-Contact-Token"] == "a1b2c3d4"

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_sends_email_without_attestation(
    self,
    mock_httpx_client_class,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"message_id": "msg-002"}}

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import send
    result = send(
      to=["recipient@example.com"],
      subject="No attestation",
      text_body="Plain message",
      include_attestation=False,
    )

    assert result.message_id == "msg-002"
    assert result.attestation_headers_included is False


# ---------------------------------------------------------------------------
# Tests: mailpal.activate
# ---------------------------------------------------------------------------

class TestMailpalActivate:
  """Test oneid.mailpal.activate() wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_returns_account_info(
    self,
    mock_httpx_client_class,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
      "data": {
        "primary_email": "1id-TESTMOCK@mailpal.com",
        "vanity_email": "clawdia@mailpal.com",
        "app_password": "generated-pw",
        "already_existed": False,
      }
    }

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.post.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import activate
    account = activate()

    assert account.primary_email == "1id-TESTMOCK@mailpal.com"
    assert account.vanity_email == "clawdia@mailpal.com"
    assert account.app_password == "generated-pw"
    assert account.already_existed is False


# ---------------------------------------------------------------------------
# Tests: mailpal.inbox
# ---------------------------------------------------------------------------

class TestMailpalInbox:
  """Test oneid.mailpal.inbox() wrapper."""

  @patch("oneid.mailpal.get_token")
  @patch("oneid.mailpal.httpx.Client")
  def test_returns_list_of_inbox_messages(
    self,
    mock_httpx_client_class,
    mock_get_token,
  ):
    mock_get_token.return_value = _mock_token()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
      "data": {
        "messages": [
          {"id": "m1", "from": "alice@example.com", "subject": "Hi", "received_at": "2026-02-20T10:00:00Z", "is_unread": True},
          {"id": "m2", "from": "bob@example.com", "subject": "Re: Hi", "received_at": "2026-02-20T11:00:00Z", "is_unread": False},
        ],
        "total_count": 2,
      }
    }

    mock_http_client = MagicMock()
    mock_http_client.__enter__ = MagicMock(return_value=mock_http_client)
    mock_http_client.__exit__ = MagicMock(return_value=False)
    mock_http_client.get.return_value = mock_response
    mock_httpx_client_class.return_value = mock_http_client

    from oneid.mailpal import inbox
    messages = inbox()

    assert len(messages) == 2
    assert messages[0].message_id == "m1"
    assert messages[0].subject == "Hi"
    assert messages[0].is_unread is True
    assert messages[1].message_id == "m2"
    assert messages[1].is_unread is False

