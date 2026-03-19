"""
Tests for Milestone 1B SDK changes:

- get_or_create_identity(get_only=True) with existing identity returns identity
- get_or_create_identity(get_only=True) with no identity raises NotEnrolledError
- status() returns WorldStatus with all expected fields
- AlreadyEnrolledError message mentions status(), does NOT mention deleting
- WorldStatus parsing from raw server response
- World cache TTL behaviour
- whoami() deprecation warning
"""

from __future__ import annotations

import time
import warnings
from unittest.mock import MagicMock, patch

import pytest

import oneid
from oneid.credentials import StoredCredentials
from oneid.exceptions import AlreadyEnrolledError, NotEnrolledError
from oneid.world import (
  WorldStatus,
  WorldIdentitySection,
  WorldServiceEntry,
  WorldGuidanceItem,
  WorldOperatorGuidance,
  _parse_world_response,
  invalidate_world_cache,
  _WORLD_CACHE_TTL_SECONDS,
)


_MOCK_STORED_CREDENTIALS = StoredCredentials(
  client_id="1id-t3stag7x",
  client_secret="test-secret",
  token_endpoint="https://1id.com/realms/agents/protocol/openid-connect/token",
  api_base_url="https://1id.com",
  trust_tier="declared",
  key_algorithm="ed25519",
  private_key_pem="-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFake\n-----END PRIVATE KEY-----\n",
  enrolled_at="2026-03-01T12:00:00Z",
  display_name="Sparky",
  agent_identity_urn="urn:aid:com.1id:1id-t3stag7x",
)


_MOCK_WORLD_SERVER_RESPONSE = {
  "identity": {
    "client_id": "1id-t3stag7x",
    "trust_tier": "declared",
    "handle": "@1id-t3stag7x",
    "agent_identity_urn": "urn:aid:com.1id:1id-t3stag7x",
    "enrolled_at": "2026-03-01T12:00:00Z",
    "hardware_locked": False,
    "operator_email_registered": False,
    "credential_pointer_count": 0,
    "trust_tier_note": "Software keys only -- no hardware attestation.",
    "display_name": "Sparky",
  },
  "devices": [],
  "connected_services": [],
  "available_services": [
    {
      "service_id": "mailpal.com",
      "service_name": "MailPal",
      "service_type": "email_workspace",
      "description": "Email for AI agents.",
      "signup_hint": "Use oneid.mailpal.activate()",
      "relevance_note": "Send and receive email as your 1ID identity.",
    },
    {
      "service_id": "geek.au",
      "service_name": "Geek.au Agent Chat",
      "service_type": "agent_chat",
      "description": "Chat for AI agents.",
      "signup_hint": "Visit https://geek.au",
      "relevance_note": "Chat with other agents.",
    },
  ],
  "operator_guidance": {
    "message_for_human": "Your AI agent Sparky has a verified identity!",
    "items": [
      {
        "id": "vanity_handle",
        "priority": "recommended",
        "title": "Get a memorable handle",
        "description": "Your agent has a random handle.",
        "human_action_url": "https://1id.com/handle/purchase?identity=1id-t3stag7x&token=abc",
        "agent_api_endpoint": "POST https://1id.com/api/v1/handle/purchase",
      },
      {
        "id": "operator_email",
        "priority": "recommended",
        "title": "Register your contact email",
        "description": "Register an operator email.",
        "human_action_url": "https://1id.com/operator/contact?identity=1id-t3stag7x&token=def",
        "agent_api_endpoint": "PUT https://1id.com/api/v1/identity/operator-email",
      },
    ],
  },
}


class TestGetOrCreateIdentityGetOnlyWithExistingCredentials:
  """get_or_create_identity(get_only=True) with existing creds returns identity."""

  def test_returns_identity_when_credentials_exist(
    self, isolated_credentials_directory
  ):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      identity = oneid.get_or_create_identity(get_only=True)

    assert identity.internal_id == "1id-t3stag7x"
    assert identity.trust_tier == oneid.TrustTier.DECLARED
    assert identity.display_name == "Sparky"

  def test_returns_identity_when_credentials_exist_without_get_only(
    self, isolated_credentials_directory
  ):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      identity = oneid.get_or_create_identity()

    assert identity.internal_id == "1id-t3stag7x"


class TestGetOrCreateIdentityGetOnlyWithNoCredentials:
  """get_or_create_identity(get_only=True) without creds raises NotEnrolledError."""

  def test_raises_not_enrolled_error_when_no_credentials(
    self, isolated_credentials_directory
  ):
    with pytest.raises(NotEnrolledError, match="get_only=True"):
      oneid.get_or_create_identity(get_only=True)

  def test_error_message_suggests_enrolling(
    self, isolated_credentials_directory
  ):
    with pytest.raises(NotEnrolledError) as exc_info:
      oneid.get_or_create_identity(get_only=True)

    message = str(exc_info.value)
    assert "oneid.get_or_create_identity()" in message
    assert "oneid.enroll()" in message


class TestStatusReturnsWorldStatus:
  """status() returns WorldStatus with all expected fields."""

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  @patch("oneid.load_credentials")
  def test_status_returns_world_status_dataclass(
    self, mock_load_creds, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_load_creds.return_value = _MOCK_STORED_CREDENTIALS
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    result = oneid.status()

    assert isinstance(result, WorldStatus)
    assert result.identity.client_id == "1id-t3stag7x"
    assert result.identity.trust_tier == "declared"
    assert result.identity.handle == "@1id-t3stag7x"
    assert result.identity.display_name == "Sparky"
    assert result.identity.hardware_locked is False
    assert result.identity.operator_email_registered is False

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  @patch("oneid.load_credentials")
  def test_status_includes_available_services(
    self, mock_load_creds, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_load_creds.return_value = _MOCK_STORED_CREDENTIALS
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    result = oneid.status()

    assert len(result.available_services) == 2
    service_ids = [s.service_id for s in result.available_services]
    assert "mailpal.com" in service_ids
    assert "geek.au" in service_ids

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  @patch("oneid.load_credentials")
  def test_status_includes_operator_guidance(
    self, mock_load_creds, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_load_creds.return_value = _MOCK_STORED_CREDENTIALS
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    result = oneid.status()

    assert result.operator_guidance is not None
    assert "Sparky" in result.operator_guidance.message_for_human
    assert len(result.operator_guidance.items) == 2
    item_ids = [i.id for i in result.operator_guidance.items]
    assert "vanity_handle" in item_ids
    assert "operator_email" in item_ids

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  @patch("oneid.load_credentials")
  def test_status_preserves_raw_response(
    self, mock_load_creds, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_load_creds.return_value = _MOCK_STORED_CREDENTIALS
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    result = oneid.status()

    assert result.raw_response is not None
    assert result.raw_response["identity"]["client_id"] == "1id-t3stag7x"


class TestAlreadyEnrolledErrorMessage:
  """AlreadyEnrolledError message mentions status(), does NOT mention deleting."""

  def test_message_mentions_status(self, isolated_credentials_directory):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with pytest.raises(AlreadyEnrolledError) as exc_info:
      oneid.enroll(request_tier="declared")

    message = str(exc_info.value)
    assert "oneid.status()" in message

  def test_message_does_not_mention_delete(self, isolated_credentials_directory):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with pytest.raises(AlreadyEnrolledError) as exc_info:
      oneid.enroll(request_tier="declared")

    message = str(exc_info.value).lower()
    assert "delete" not in message

  def test_message_mentions_get_or_create_identity(
    self, isolated_credentials_directory
  ):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with pytest.raises(AlreadyEnrolledError) as exc_info:
      oneid.enroll(request_tier="declared")

    message = str(exc_info.value)
    assert "get_or_create_identity" in message


class TestWorldStatusParsing:
  """Test _parse_world_response correctly maps raw JSON to dataclasses."""

  def test_parse_full_response_with_guidance(self):
    result = _parse_world_response(_MOCK_WORLD_SERVER_RESPONSE)

    assert isinstance(result, WorldStatus)
    assert isinstance(result.identity, WorldIdentitySection)
    assert result.identity.client_id == "1id-t3stag7x"
    assert result.identity.trust_tier == "declared"

  def test_parse_response_without_guidance(self):
    response_without_guidance = dict(_MOCK_WORLD_SERVER_RESPONSE)
    response_without_guidance.pop("operator_guidance", None)

    result = _parse_world_response(response_without_guidance)

    assert result.operator_guidance is None

  def test_parse_response_with_connected_services(self):
    response_with_connected = dict(_MOCK_WORLD_SERVER_RESPONSE)
    response_with_connected["connected_services"] = [
      {
        "service_id": "mailpal.com",
        "service_name": "MailPal",
        "service_type": "email_workspace",
        "description": "Email for agents.",
        "account_status": "active",
        "primary_identifier": "sparky@mailpal.com",
      }
    ]

    result = _parse_world_response(response_with_connected)

    assert len(result.connected_services) == 1
    assert result.connected_services[0].service_id == "mailpal.com"
    assert result.connected_services[0].account_status == "active"
    assert result.connected_services[0].primary_identifier == "sparky@mailpal.com"

  def test_parse_response_with_devices(self):
    response_with_devices = dict(_MOCK_WORLD_SERVER_RESPONSE)
    response_with_devices["devices"] = [
      {
        "device_id": "tpm-001",
        "device_type": "tpm",
        "manufacturer": "INTC",
        "serial_prefix": "ab12",
        "status": "active",
      }
    ]

    result = _parse_world_response(response_with_devices)

    assert len(result.devices) == 1
    assert result.devices[0].device_id == "tpm-001"
    assert result.devices[0].device_type == "tpm"
    assert result.devices[0].manufacturer == "INTC"

  def test_guidance_items_have_all_fields(self):
    result = _parse_world_response(_MOCK_WORLD_SERVER_RESPONSE)

    assert result.operator_guidance is not None
    for item in result.operator_guidance.items:
      assert isinstance(item, WorldGuidanceItem)
      assert item.id in ("vanity_handle", "operator_email")
      assert item.priority == "recommended"
      assert item.title
      assert item.description
      assert item.human_action_url
      assert item.agent_api_endpoint

  def test_service_entries_have_required_fields(self):
    result = _parse_world_response(_MOCK_WORLD_SERVER_RESPONSE)

    for svc in result.available_services:
      assert isinstance(svc, WorldServiceEntry)
      assert svc.service_id
      assert svc.service_name
      assert svc.service_type
      assert svc.description


class TestWorldCacheBehaviour:
  """Test that the world cache respects TTL and client_id."""

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  def test_second_call_uses_cache(
    self, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    from oneid.world import fetch_world_status_from_server

    result1 = fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)
    result2 = fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)

    assert result1.identity.client_id == result2.identity.client_id
    assert mock_client_instance._make_request.call_count == 1

  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  def test_invalidate_cache_forces_refetch(
    self, mock_get_token, mock_api_client_class
  ):
    invalidate_world_cache()
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    from oneid.world import fetch_world_status_from_server

    fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)
    invalidate_world_cache()
    fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)

    assert mock_client_instance._make_request.call_count == 2

  @patch("oneid.world.time")
  @patch("oneid.world.OneIDAPIClient")
  @patch("oneid.auth.get_token")
  def test_cache_expires_after_ttl(
    self, mock_get_token, mock_api_client_class, mock_time
  ):
    invalidate_world_cache()
    mock_token = MagicMock()
    mock_token.authorization_header_value = "Bearer mock-token"
    mock_get_token.return_value = mock_token

    mock_client_instance = mock_api_client_class.return_value
    mock_client_instance._make_request.return_value = (
      _MOCK_WORLD_SERVER_RESPONSE
    )

    from oneid.world import fetch_world_status_from_server

    mock_time.time.return_value = 1000000.0
    fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)

    mock_time.time.return_value = 1000000.0 + _WORLD_CACHE_TTL_SECONDS + 1
    fetch_world_status_from_server(_MOCK_STORED_CREDENTIALS)

    assert mock_client_instance._make_request.call_count == 2


class TestWhoamiDeprecationWarning:
  """whoami() should emit a DeprecationWarning."""

  def test_whoami_emits_deprecation_warning(
    self, isolated_credentials_directory
  ):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with warnings.catch_warnings(record=True) as caught_warnings:
      warnings.simplefilter("always")
      oneid.whoami()

    deprecation_warnings = [
      w for w in caught_warnings if issubclass(w.category, DeprecationWarning)
    ]
    assert len(deprecation_warnings) >= 1
    assert "deprecated" in str(deprecation_warnings[0].message).lower()
    assert "status()" in str(deprecation_warnings[0].message)

  def test_whoami_still_returns_identity(
    self, isolated_credentials_directory
  ):
    from oneid.credentials import save_credentials
    save_credentials(_MOCK_STORED_CREDENTIALS)

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      identity = oneid.whoami()

    assert identity.internal_id == "1id-t3stag7x"


class TestPublicAPIExports:
  """Verify __all__ changes: status and WorldStatus added, whoami/credentials_exist removed."""

  def test_status_in_all(self):
    assert "status" in oneid.__all__

  def test_world_status_in_all(self):
    assert "WorldStatus" in oneid.__all__

  def test_whoami_not_in_all(self):
    assert "whoami" not in oneid.__all__

  def test_credentials_exist_not_in_all(self):
    assert "credentials_exist" not in oneid.__all__

  def test_whoami_still_importable(self):
    assert hasattr(oneid, "whoami")
    assert callable(oneid.whoami)

  def test_credentials_exist_still_importable(self):
    assert hasattr(oneid, "credentials_exist")
    assert callable(oneid.credentials_exist)
