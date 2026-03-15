"""
World endpoint client and WorldStatus dataclass for the 1id.com SDK.

Calls GET /api/v1/identity/world with a Bearer token and returns
a structured WorldStatus containing identity, devices, connected
services, available services, and operator guidance.

Caching: results are cached for 5 minutes to avoid hitting the
server on every status() call. The cache is keyed by client_id.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client import OneIDAPIClient
from .credentials import StoredCredentials

logger = logging.getLogger("oneid.world")

_WORLD_CACHE_TTL_SECONDS = 300  # 5 minutes
_cached_world_response = None  # type: Optional[Dict[str, Any]]
_cached_world_fetched_at = 0.0  # type: float
_cached_world_client_id = None  # type: Optional[str]


@dataclass(frozen=True)
class WorldServiceEntry:
  """A single service in the connected_services or available_services list."""
  service_id: str
  service_name: str
  service_type: str
  description: str
  well_known_url: Optional[str] = None
  account_status: Optional[str] = None
  primary_identifier: Optional[str] = None
  quick_start: Optional[str] = None
  dashboard_url: Optional[str] = None
  signup_hint: Optional[str] = None
  info_url: Optional[str] = None
  relevance_note: Optional[str] = None
  aliases: Optional[List[str]] = None
  summary: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class WorldGuidanceItem:
  """A single operator guidance item."""
  id: str
  priority: str
  title: str
  description: str
  human_action_url: Optional[str] = None
  agent_api_endpoint: Optional[str] = None


@dataclass(frozen=True)
class WorldOperatorGuidance:
  """Operator guidance section from the world endpoint."""
  message_for_human: str
  items: List[WorldGuidanceItem] = field(default_factory=list)


@dataclass(frozen=True)
class WorldDeviceEntry:
  """A single device in the devices list."""
  device_id: str
  device_type: str
  manufacturer: Optional[str] = None
  serial_prefix: Optional[str] = None
  bound_at: Optional[str] = None
  last_used_at: Optional[str] = None
  status: str = "active"


@dataclass(frozen=True)
class WorldIdentitySection:
  """Identity section from the world endpoint."""
  client_id: str
  trust_tier: str
  handle: str
  agent_identity_urn: str
  enrolled_at: str
  hardware_locked: bool
  operator_email_registered: bool
  credential_pointer_count: int
  trust_tier_note: Optional[str] = None
  display_name: Optional[str] = None
  locked_at: Optional[str] = None
  hardware_lock_notice: Optional[str] = None
  upgraded_from_declared_at: Optional[str] = None


@dataclass(frozen=True)
class WorldStatus:
  """Complete world status returned by oneid.status().

  This is the single source of truth for an agent recovering context.
  Contains everything the agent needs to know about its identity,
  devices, connected services, available services, and operator guidance.
  """
  identity: WorldIdentitySection
  devices: List[WorldDeviceEntry]
  connected_services: List[WorldServiceEntry]
  available_services: List[WorldServiceEntry]
  operator_guidance: Optional[WorldOperatorGuidance] = None
  raw_response: Optional[Dict[str, Any]] = field(default=None, repr=False)


def fetch_world_status_from_server(
  stored_credentials: StoredCredentials,
) -> WorldStatus:
  """Fetch the world endpoint and return a structured WorldStatus.

  Gets a fresh Bearer token, calls GET /api/v1/identity/world,
  and parses the response into dataclasses.

  Args:
      stored_credentials: The locally stored credentials (for token + API URL).

  Returns:
      WorldStatus with all sections populated.

  Raises:
      NetworkError: If the server cannot be reached.
      AuthenticationError: If the token is invalid.
      NotEnrolledError: If no credentials exist.
  """
  global _cached_world_response, _cached_world_fetched_at, _cached_world_client_id

  now = time.time()
  if (
    _cached_world_response is not None
    and _cached_world_client_id == stored_credentials.client_id
    and (now - _cached_world_fetched_at) < _WORLD_CACHE_TTL_SECONDS
  ):
    return _parse_world_response(_cached_world_response)

  from .auth import get_token
  token = get_token()

  api_client = OneIDAPIClient(api_base_url=stored_credentials.api_base_url)
  raw_data = api_client._make_request(
    "GET",
    "/api/v1/identity/world",
    headers={"Authorization": token.authorization_header_value},
  )

  _cached_world_response = raw_data
  _cached_world_fetched_at = now
  _cached_world_client_id = stored_credentials.client_id

  return _parse_world_response(raw_data)


def invalidate_world_cache() -> None:
  """Clear the cached world response, forcing the next status() to
  fetch fresh data from the server.
  """
  global _cached_world_response, _cached_world_fetched_at, _cached_world_client_id
  _cached_world_response = None
  _cached_world_fetched_at = 0.0
  _cached_world_client_id = None


def _parse_world_response(data: Dict[str, Any]) -> WorldStatus:
  """Parse the raw world endpoint JSON into structured dataclasses."""
  identity_raw = data.get("identity", {})
  identity_section = WorldIdentitySection(
    client_id=identity_raw.get("client_id", ""),
    trust_tier=identity_raw.get("trust_tier", "declared"),
    handle=identity_raw.get("handle", ""),
    agent_identity_urn=identity_raw.get("agent_identity_urn", ""),
    enrolled_at=identity_raw.get("enrolled_at", ""),
    hardware_locked=bool(identity_raw.get("hardware_locked", False)),
    operator_email_registered=bool(
      identity_raw.get("operator_email_registered", False)
    ),
    credential_pointer_count=identity_raw.get(
      "credential_pointer_count", 0
    ),
    trust_tier_note=identity_raw.get("trust_tier_note"),
    display_name=identity_raw.get("display_name"),
    locked_at=identity_raw.get("locked_at"),
    hardware_lock_notice=identity_raw.get("hardware_lock_notice"),
    upgraded_from_declared_at=identity_raw.get(
      "upgraded_from_declared_at"
    ),
  )

  devices = [
    WorldDeviceEntry(
      device_id=d.get("device_id", ""),
      device_type=d.get("device_type", ""),
      manufacturer=d.get("manufacturer"),
      serial_prefix=d.get("serial_prefix"),
      bound_at=d.get("bound_at"),
      last_used_at=d.get("last_used_at"),
      status=d.get("status", "active"),
    )
    for d in data.get("devices", [])
  ]

  connected_services = [
    _parse_service_entry(s) for s in data.get("connected_services", [])
  ]
  available_services = [
    _parse_service_entry(s) for s in data.get("available_services", [])
  ]

  guidance_raw = data.get("operator_guidance")
  operator_guidance = None
  if guidance_raw:
    guidance_items = [
      WorldGuidanceItem(
        id=item.get("id", ""),
        priority=item.get("priority", ""),
        title=item.get("title", ""),
        description=item.get("description", ""),
        human_action_url=item.get("human_action_url"),
        agent_api_endpoint=item.get("agent_api_endpoint"),
      )
      for item in guidance_raw.get("items", [])
    ]
    operator_guidance = WorldOperatorGuidance(
      message_for_human=guidance_raw.get("message_for_human", ""),
      items=guidance_items,
    )

  return WorldStatus(
    identity=identity_section,
    devices=devices,
    connected_services=connected_services,
    available_services=available_services,
    operator_guidance=operator_guidance,
    raw_response=data,
  )


def _parse_service_entry(raw: Dict[str, Any]) -> WorldServiceEntry:
  """Parse a single service entry from the world response."""
  return WorldServiceEntry(
    service_id=raw.get("service_id", ""),
    service_name=raw.get("service_name", ""),
    service_type=raw.get("service_type", ""),
    description=raw.get("description", ""),
    well_known_url=raw.get("well_known_url"),
    account_status=raw.get("account_status"),
    primary_identifier=raw.get("primary_identifier"),
    quick_start=raw.get("quick_start"),
    dashboard_url=raw.get("dashboard_url"),
    signup_hint=raw.get("signup_hint"),
    info_url=raw.get("info_url"),
    relevance_note=raw.get("relevance_note"),
    aliases=raw.get("aliases"),
    summary=raw.get("summary"),
  )
