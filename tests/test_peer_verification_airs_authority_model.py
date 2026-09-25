"""Peer verification on the AIRS authority model (rebuilt 2026-09-26; AUD-F05,
F06, F32, F33, F69, F70, F86): Registry resolution -> current issuer -> binding
JWS signed by that issuer's key -> nonce signature by the bound key. The trust
tier and identity facts never come from the bundle. Mirrors oneid-node
src/test/test_peer_verification.ts."""

import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from oneid.verify import (
  IdentityProofBundle,
  PeerVerificationError,
  PeerVerificationTemporarilyUnavailableError,
  RegistrarAuthorityValidationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  verify_peer_identity,
)

AID = "urn:aid:global:id-tstpv-aaaaa-bbbbb-ccccc"
ISSUER = "https://issuer.example/realms/agents"


def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ec_public_jwk(private_key, kid=None) -> dict:
  numbers = private_key.public_key().public_numbers()
  jwk = {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}
  if kid:
    jwk["kid"] = kid
  return jwk


def make_binding_jws(registrar_key, prover_key, **overrides) -> str:
  now = int(time.time())
  header = {"alg": "ES256", "typ": "airs-email-binding+jwt", "kid": "registrar-1"}
  header.update(overrides.pop("header", {}))
  payload = {"iss": ISSUER, "sub": AID, "iat": now, "exp": now + 300,
             "cnf": {"jwk": ec_public_jwk(prover_key)}, "aid": {"trust_tier": "sovereign"}}
  payload.update(overrides)
  signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
  r, s = utils.decode_dss_signature(registrar_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
  return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture
def world():
  registrar_key = ec.generate_private_key(ec.SECP256R1())
  prover_key = ec.generate_private_key(ec.SECP256R1())
  nonce = os.urandom(32)
  registry_answer = {"current_issuer": ISSUER, "hardware_locked": True, "registered_at": "2026-09-25T10:35:15Z",
                     "max_active_trust_tier": "sovereign"}
  return {
    "registrar_key": registrar_key, "prover_key": prover_key, "nonce": nonce,
    "resolver": lambda aid: dict(registry_answer),
    "jwks": lambda issuer: [ec_public_jwk(registrar_key, kid="registrar-1")] if issuer == ISSUER else [],
  }


def bundle_for(world, binding=None, signature=None, claimed_tier="declared") -> IdentityProofBundle:
  return IdentityProofBundle(
    signature_bytes=signature or world["prover_key"].sign(world["nonce"], ec.ECDSA(hashes.SHA256())),
    agent_identity_urn=AID,
    registrar_binding_jws=binding if binding is not None else make_binding_jws(world["registrar_key"], world["prover_key"]),
    algorithm="ES256", agent_id="id-tstpv-aaaaa-bbbbb-ccccc", trust_tier=claimed_tier)


def verify(world, bundle, **kwargs):
  return verify_peer_identity(world["nonce"], bundle, current_issuer_resolver=kwargs.pop("resolver", world["resolver"]),
                              issuer_jwk_set_provider=kwargs.pop("jwks", world["jwks"]), **kwargs)


def test_valid_bundle_verifies_with_facts_from_the_registry_and_the_binding(world):
  verified = verify(world, bundle_for(world, claimed_tier="declared"))
  assert verified.agent_identity_urn == AID and verified.agent_id == "id-tstpv-aaaaa-bbbbb-ccccc"
  assert verified.trust_tier == "sovereign"  # from the Registrar binding, not the bundle's "declared" claim
  assert verified.hardware_locked is True and verified.enrolled_at == "2026-09-25T10:35:15Z"
  assert verified.issuer == ISSUER and verified.chain_valid is True


def test_dict_round_trip_verifies(world):
  assert verify(world, bundle_for(world).to_dict()).trust_tier == "sovereign"


def test_binding_from_an_issuer_that_is_not_the_registry_current_issuer_fails(world):
  binding = make_binding_jws(world["registrar_key"], world["prover_key"], iss="https://evil.example/realms/agents")
  with pytest.raises(RegistrarAuthorityValidationError, match="not the Registry's current issuer"):
    verify(world, bundle_for(world, binding=binding))


def test_binding_signed_by_a_key_outside_the_issuer_jwk_set_fails(world):
  impostor_key = ec.generate_private_key(ec.SECP256R1())
  with pytest.raises(RegistrarAuthorityValidationError, match="not signed by a key of"):
    verify(world, bundle_for(world, binding=make_binding_jws(impostor_key, world["prover_key"])))


def test_nonce_signed_by_another_key_fails(world):
  other_key = ec.generate_private_key(ec.SECP256R1())
  with pytest.raises(SignatureVerificationError):
    verify(world, bundle_for(world, signature=other_key.sign(world["nonce"], ec.ECDSA(hashes.SHA256()))))


def test_binding_for_another_aid_fails(world):
  binding = make_binding_jws(world["registrar_key"], world["prover_key"], sub="urn:aid:global:id-other-aaaaa-bbbbb-ccccc")
  with pytest.raises(RegistrarAuthorityValidationError, match="sub"):
    verify(world, bundle_for(world, binding=binding))


def test_expired_binding_fails(world):
  old = int(time.time()) - 3600
  binding = make_binding_jws(world["registrar_key"], world["prover_key"], iat=old - 300, exp=old)
  with pytest.raises(RegistrarAuthorityValidationError, match="expired"):
    verify(world, bundle_for(world, binding=binding))


def test_non_operational_identity_fails(world):
  def decommissioned(aid):
    raise RegistrarAuthorityValidationError(f"AIRS identity {aid!r} has lifecycleState 'decommissioned'")
  with pytest.raises(RegistrarAuthorityValidationError, match="decommissioned"):
    verify(world, bundle_for(world), resolver=decommissioned)


def test_registry_outage_is_temporary_not_a_pass(world):
  def unreachable(aid):
    raise PeerVerificationTemporarilyUnavailableError("RDAP: timeout")
  with pytest.raises(PeerVerificationTemporarilyUnavailableError):
    verify(world, bundle_for(world), resolver=unreachable)


def test_bundle_without_binding_is_refused(world):
  with pytest.raises(CertificateChainValidationError, match="no Registrar binding"):  # old name still catches it
    verify(world, bundle_for(world, binding=""))


def test_wrong_typ_and_symmetric_alg_are_refused(world):
  with pytest.raises(RegistrarAuthorityValidationError, match="typ"):
    verify(world, bundle_for(world, binding=make_binding_jws(world["registrar_key"], world["prover_key"], header={"typ": "JWT"})))
  with pytest.raises(RegistrarAuthorityValidationError, match="alg"):
    verify(world, bundle_for(world, binding=make_binding_jws(world["registrar_key"], world["prover_key"], header={"alg": "HS256"})))


def test_short_nonce_is_refused(world):
  with pytest.raises(PeerVerificationError, match="at least 16 bytes"):
    verify_peer_identity(b"short", bundle_for(world), current_issuer_resolver=world["resolver"],
                         issuer_jwk_set_provider=world["jwks"])
