"""
Shared test fixtures for the oneid-sdk test suite.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def isolated_credentials_directory(tmp_path):
  """Provide an isolated temporary directory for credentials storage.

  Patches get_credentials_directory() to use a temp directory,
  preventing tests from touching real credential files.
  """
  with patch("oneid.credentials.get_credentials_directory", return_value=tmp_path):
    yield tmp_path


@pytest.fixture
def mock_server_declared_enrollment_response():
  """Return a mock server response for declared-tier enrollment.

  This is what POST /api/v1/enroll/declared returns on success.
  """
  return {
    "ok": True,
    "data": {
      "identity": {
        "internal_id": "1id-t3stag7x",
        "handle": "@1id-t3stag7x",
        "trust_tier": "declared",
        "tpm_manufacturer": None,
        "registered_at": "2026-02-11T12:00:00Z",
      },
      "credentials": {
        "client_id": "1id-t3stag7x",
        "client_secret": "test-secret-do-not-use-in-production",
        "token_endpoint": "https://1id.com/realms/agents/protocol/openid-connect/token",
        "grant_type": "client_credentials",
      },
      "initial_tokens": {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
        "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
      },
    },
    "error": None,
  }


@pytest.fixture
def mock_server_error_ek_already_registered():
  """Return a mock server error for duplicate EK registration."""
  return {
    "ok": False,
    "data": None,
    "error": {
      "code": "EK_ALREADY_REGISTERED",
      "message": "This TPM endorsement key is already associated with identity 1id-existing1",
    },
  }


@pytest.fixture
def mock_server_error_handle_taken():
  """Return a mock server error for taken handle."""
  return {
    "ok": False,
    "data": None,
    "error": {
      "code": "HANDLE_TAKEN",
      "message": "Handle 'clawdia' is already in use",
    },
  }


@pytest.fixture
def mock_keycloak_token_response():
  """Return a mock Keycloak token response."""
  return {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock-payload.mock-signature",
    "expires_in": 3600,
    "refresh_expires_in": 2592000,
    "refresh_token": "eyJhbGciOiJSUzI1NiJ9.mock-refresh",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "test-session",
    "scope": "openid profile",
  }
