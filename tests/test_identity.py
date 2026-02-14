"""
Tests for Identity and Token data models.

Verifies:
- Identity is frozen (immutable)
- Token expiry checking works
- Authorization header formatting works
- TrustTier enum values match spec
- KeyAlgorithm enum values match spec
- String representation is useful
"""

from datetime import datetime, timedelta, timezone

import pytest

from oneid.identity import (
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  Identity,
  KeyAlgorithm,
  Token,
  TrustTier,
)


class TestTrustTierEnum:
  """Verify TrustTier enum matches the spec exactly."""

  def test_all_six_tiers_exist(self):
    assert len(TrustTier) == 6

  def test_tier_values_match_spec(self):
    assert TrustTier.SOVEREIGN.value == "sovereign"
    assert TrustTier.SOVEREIGN_PORTABLE.value == "sovereign-portable"
    assert TrustTier.LEGACY.value == "legacy"
    assert TrustTier.VIRTUAL.value == "virtual"
    assert TrustTier.ENCLAVE.value == "enclave"
    assert TrustTier.DECLARED.value == "declared"

  def test_tiers_are_strings(self):
    """TrustTier should be usable as a string (str, Enum)."""
    assert isinstance(TrustTier.SOVEREIGN, str)
    assert TrustTier.SOVEREIGN == "sovereign"


class TestKeyAlgorithmEnum:
  """Verify KeyAlgorithm enum."""

  def test_all_five_algorithms_exist(self):
    assert len(KeyAlgorithm) == 5

  def test_algorithm_values(self):
    assert KeyAlgorithm.ED25519.value == "ed25519"
    assert KeyAlgorithm.ECDSA_P256.value == "ecdsa-p256"
    assert KeyAlgorithm.ECDSA_P384.value == "ecdsa-p384"
    assert KeyAlgorithm.RSA_2048.value == "rsa-2048"
    assert KeyAlgorithm.RSA_4096.value == "rsa-4096"

  def test_default_is_ed25519(self):
    assert DEFAULT_KEY_ALGORITHM == KeyAlgorithm.ED25519


class TestIdentityDataclass:
  """Verify the Identity dataclass behavior."""

  def _make_identity(self, **overrides):
    defaults = {
      "internal_id": "1id-t3stag7x",
      "handle": "@test-agent",
      "trust_tier": TrustTier.DECLARED,
      "hsm_type": HSMType.SOFTWARE,
      "hsm_manufacturer": None,
      "enrolled_at": datetime(2026, 2, 11, 12, 0, 0, tzinfo=timezone.utc),
      "device_count": 0,
      "key_algorithm": KeyAlgorithm.ED25519,
    }
    defaults.update(overrides)
    return Identity(**defaults)

  def test_identity_is_frozen(self):
    """Identity fields should not be modifiable after creation."""
    identity = self._make_identity()
    with pytest.raises(AttributeError):
      identity.internal_id = "1id-hacked!!"

  def test_identity_string_representation_is_useful(self):
    """str(identity) should show handle, tier, and ID."""
    identity = self._make_identity(handle="@clawdia", trust_tier=TrustTier.SOVEREIGN)
    s = str(identity)
    assert "@clawdia" in s
    assert "sovereign" in s
    assert "1id-t3stag7x" in s

  def test_sovereign_identity_fields(self):
    identity = self._make_identity(
      trust_tier=TrustTier.SOVEREIGN,
      hsm_type=HSMType.TPM,
      hsm_manufacturer="INTC",
      device_count=1,
      key_algorithm=KeyAlgorithm.RSA_2048,
    )
    assert identity.trust_tier == TrustTier.SOVEREIGN
    assert identity.hsm_type == HSMType.TPM
    assert identity.hsm_manufacturer == "INTC"
    assert identity.device_count == 1

  def test_declared_identity_has_no_hsm_manufacturer(self):
    identity = self._make_identity()
    assert identity.hsm_manufacturer is None


class TestTokenDataclass:
  """Verify the Token dataclass behavior."""

  def _make_token(self, **overrides):
    defaults = {
      "access_token": "eyJhbGciOiJSUzI1NiJ9.test.payload",
      "token_type": "Bearer",
      "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
      "refresh_token": None,
    }
    defaults.update(overrides)
    return Token(**defaults)

  def test_token_is_frozen(self):
    token = self._make_token()
    with pytest.raises(AttributeError):
      token.access_token = "stolen-token"

  def test_valid_token_reports_not_expired(self):
    """A token expiring in the future should report as not expired."""
    token = self._make_token(
      expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    assert token.this_token_has_not_yet_expired is True

  def test_expired_token_reports_expired(self):
    """A token that expired in the past should report as expired."""
    token = self._make_token(
      expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )
    assert token.this_token_has_not_yet_expired is False

  def test_authorization_header_value(self):
    """The authorization header should be 'Bearer <token>'."""
    token = self._make_token(access_token="abc123")
    assert token.authorization_header_value == "Bearer abc123"

  def test_token_with_refresh_token(self):
    token = self._make_token(refresh_token="refresh-abc")
    assert token.refresh_token == "refresh-abc"

  def test_token_without_refresh_token(self):
    token = self._make_token(refresh_token=None)
    assert token.refresh_token is None
