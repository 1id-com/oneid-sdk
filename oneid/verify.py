"""
1id Peer Identity Verification -- the AIRS online authority model.

Rebuilt 2026-09-26 on the drafts' authority model (registry-04 / resolution /
email-hardware-attestation "Registrar Binding JWS"), replacing the old offline
certificate model (AUD-F05, F06, F32, F33, F69, F70, F86). Same protocol and
checks as the Node SDK (src/verify.ts).

Protocol:
  1. The verifier generates a random nonce (at least 16 bytes).
  2. The prover calls sign_challenge(nonce) -> IdentityProofBundle:
       - a signature over the nonce by the ENROLLED key of its local signing
         device (TPM AK, YubiKey slot 9a, Secure Enclave, or software key);
       - the Registrar Binding JWS for that key (iss, sub = the aid URN,
         cnf.jwk = the key, aid.trust_tier), fetched from the Registrar;
       - the aid URN and the algorithm.
  3. The verifier calls verify_peer_identity(nonce, bundle) -> VerifiedPeerIdentity:
       a. resolve the aid at the AIRS Registry (RDAP): the answer must name
          exactly this aid and be operational; it gives currentIssuer,
          hardwareLocked and the registration date;
       b. the binding JWS: typ, asymmetric alg, sub == aid, iat/exp current,
          cnf.jwk public only, iss == currentIssuer, signature by a key from
          THAT issuer's RFC 8414 metadata jwks_uri (never from the bundle);
       c. the nonce signature with cnf.jwk.
     The trust tier comes only from the Registrar-signed binding and the
     identity facts only from the Registry -- never from the bundle.

Verification is online by design: resolution supplies the current issuer and
the lifecycle state, so a decommissioned identity fails. For air-gapped use
pass current_issuer_resolver / issuer_jwk_set_provider with pre-fetched
answers (revocation is then only as fresh as those answers).
"""
from __future__ import annotations

import base64
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote as url_quote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from .credentials import StoredCredentials, load_credentials
from .exceptions import NotEnrolledError, OneIDError

logger = logging.getLogger("oneid.verify")

AIRS_RDAP_BASE_URL = "https://airs.1id.biz"
REGISTRAR_BINDING_JWS_TYP = "airs-email-binding+jwt"
_ACCEPTED_BINDING_JWS_ALGORITHMS = ("ES256", "RS256", "PS256")
_NETWORK_TIMEOUT_SECONDS = 10.0
_RFC8414_JWK_SET_CACHE_SECONDS = 300
_issuer_jwk_set_cache: dict = {}
_AID_URN_PATTERN = re.compile(r"urn:aid:[a-z0-9-]+:id-[a-z]{5}(-[a-z]{5}){3}")
_VALID_TRUST_TIERS = ("sovereign", "portable", "enclave", "virtual", "declared")


class PeerVerificationError(OneIDError):
  """Raised when a proof bundle fails validation."""


class RegistrarAuthorityValidationError(PeerVerificationError):
  """The peer's identity authority could not be established: the Registry does
  not resolve the aid to an operational identity, or the Registrar Binding JWS
  is not valid for it."""


# The old certificate-model name, kept so existing `except` clauses still work.
CertificateChainValidationError = RegistrarAuthorityValidationError


class PeerVerificationTemporarilyUnavailableError(PeerVerificationError):
  """Registry resolution or issuer key retrieval could not complete (network,
  timeout, HTTP 429/5xx). Neither a pass nor a permanent failure: retry."""


class SignatureVerificationError(PeerVerificationError):
  """The nonce signature was not made by the key the Registrar bound to the aid."""


class MissingIdentityCertificateError(PeerVerificationError):
  """The agent has no identity certificate chain stored (re-enroll or recover)."""


@dataclass
class IdentityProofBundle:
  """Assembled by the prover, sent to the verifier."""
  signature_bytes: bytes
  agent_identity_urn: str
  registrar_binding_jws: str
  algorithm: str
  agent_id: str = ""
  trust_tier: str = ""  # the prover's claim; informational only (never trusted)
  certificate_chain_pem: str = ""  # carried for SDK <= 3.1.1 verifiers; not used

  def to_dict(self) -> dict:
    return {
      "signature_b64": base64.b64encode(self.signature_bytes).decode("ascii"),
      "agent_identity_urn": self.agent_identity_urn,
      "registrar_binding_jws": self.registrar_binding_jws,
      "algorithm": self.algorithm,
      "agent_id": self.agent_id,
      "trust_tier": self.trust_tier,
      "certificate_chain_pem": self.certificate_chain_pem,
    }

  @classmethod
  def from_dict(cls, data: dict) -> IdentityProofBundle:
    return cls(
      signature_bytes=base64.b64decode(data["signature_b64"]),
      agent_identity_urn=data.get("agent_identity_urn", ""),
      registrar_binding_jws=data.get("registrar_binding_jws", ""),
      algorithm=data.get("algorithm", ""),
      agent_id=data.get("agent_id", ""),
      trust_tier=data.get("trust_tier", ""),
      certificate_chain_pem=data.get("certificate_chain_pem", ""),
    )


@dataclass
class VerifiedPeerIdentity:
  """Returned by the verifier after successful validation. Every field comes
  from the Registry (RDAP) or the Registrar-signed binding, never the bundle."""
  agent_id: str
  trust_tier: str
  enrolled_at: str
  hardware_locked: bool
  chain_valid: bool  # True: the Registry -> issuer -> binding -> key chain verified
  agent_identity_urn: str = ""
  issuer: str = ""
  registrar_binding_expires_at: int = 0


# ---------------------------------------------------------------------------
# Prover side
# ---------------------------------------------------------------------------

def _determine_signing_algorithm_name(creds: StoredCredentials) -> str:
  """Map credential key algorithm to a compact algorithm identifier."""
  algo = (creds.key_algorithm or "").lower()
  if "ed25519" in algo:
    return "EdDSA"
  if "p-384" in algo or "p384" in algo or "ecdsa-p384" in algo:
    return "ES384"
  if "p-256" in algo or "p256" in algo or "ecdsa" in algo or "piv" in algo:
    return "ES256"
  if "rsa-4096" in algo or "rsa4096" in algo:
    return "RS256"
  if "rsa" in algo or "tpm-ak" in algo:
    return "RS256"
  return "RS256"


def _sign_with_software_key(nonce_bytes: bytes, private_key_pem: str) -> bytes:
  """Sign using the locally stored software private key."""
  from .keys import sign_challenge_with_private_key
  return sign_challenge_with_private_key(private_key_pem, nonce_bytes)


def _sign_with_tpm(nonce_bytes: bytes, ak_handle: str) -> tuple[bytes, str]:
  """Sign using the TPM AK via the Go binary. Returns (signature_bytes, algorithm)."""
  from .helper import sign_challenge_with_tpm
  nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
  result = sign_challenge_with_tpm(nonce_b64, ak_handle)
  signature_b64 = result.get("signature_b64", "")
  algorithm = result.get("algorithm", "RSASSA-SHA256")
  algo_name = "RS256" if "RSA" in algorithm.upper() else algorithm
  return base64.b64decode(signature_b64), algo_name


def _sign_with_piv(
  nonce_bytes: bytes,
  piv_serial_number: int | None = None,
) -> tuple[bytes, str]:
  """Sign using the YubiKey PIV key. Returns (signature_bytes, algorithm).

  Phase 4: When piv_serial_number is provided or multiple YubiKeys are
  connected, uses pure-Python PC/SC signing to target the specific device.
  """
  from .helper import sign_challenge_with_piv
  nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
  result = sign_challenge_with_piv(nonce_b64, piv_serial_number=piv_serial_number)
  signature_b64 = result.get("signature_b64", "")
  algorithm = result.get("algorithm", "ECDSA-SHA256")
  algo_name = "ES256" if "ECDSA" in algorithm.upper() else algorithm
  return base64.b64decode(signature_b64), algo_name


def _sign_with_enclave(
  nonce_bytes: bytes,
  enclave_key_data_representation_b64: str | None = None,
) -> tuple[bytes, str]:
  """Sign using the Apple Secure Enclave. Returns (signature_bytes, algorithm).

  Before invoking the helper, ensures the on-disk SE key file exists.
  If the file was deleted but credentials.json still holds the
  dataRepresentation blob, restores it so the helper can sign.
  """
  from .enroll import _restore_enclave_key_file_from_credentials_if_missing
  from .helper import sign_challenge_with_enclave

  if enclave_key_data_representation_b64:
    _restore_enclave_key_file_from_credentials_if_missing(
      enclave_key_data_representation_b64,
    )

  nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
  result = sign_challenge_with_enclave(nonce_b64)
  signature_b64 = result.get("signature_b64", "")
  return base64.b64decode(signature_b64), "ES256"


def sign_challenge(
  nonce_bytes: bytes,
  signing_device_type: str | None = None,
  piv_serial_number: int | None = None,
) -> IdentityProofBundle:
  """Sign a verifier-provided nonce and assemble a proof bundle.

  The ENROLLED LOCAL DEVICE signs (hsm_key_reference first, the trust tier only
  as fallback -- the same rule login and Mode 1 use), unless signing_device_type
  selects one ("tpm" | "piv" | "enclave" | "software"). The bundle carries the
  Registrar Binding JWS for exactly the key that signed.

  Raises:
    NotEnrolledError: no credentials / no signing key.
    MissingIdentityCertificateError: no identity certificate chain stored.
    PeerVerificationError: the Registrar binding could not be obtained.
    HSMAccessError: hardware signing failed.
  """
  from .attestation import _certificate_chain_leaf_key_verifies_mode1_signature, _fetch_binding_jws
  from .auth import get_token
  from .credentials import local_signing_device_type_for_credentials
  from .mailpal import _extract_public_key_jwk_from_certificate_chain_pem
  from ._version import USER_AGENT

  creds = load_credentials()
  if not creds.identity_certificate_chain_pem:
    raise MissingIdentityCertificateError(
      "No identity certificate chain found in credentials. "
      "Re-enroll or recover your identity to obtain a certificate."
    )
  if not creds.agent_identity_urn:
    raise NotEnrolledError("These credentials have no agent identity URN; re-enroll to obtain one.")

  device_type = signing_device_type or local_signing_device_type_for_credentials(creds)
  if device_type == "tpm":
    signature_bytes, algorithm = _sign_with_tpm(nonce_bytes, creds.hsm_key_reference or "")
  elif device_type == "piv":
    signature_bytes, algorithm = _sign_with_piv(nonce_bytes, piv_serial_number=piv_serial_number)
  elif device_type == "enclave":
    signature_bytes, algorithm = _sign_with_enclave(
      nonce_bytes, enclave_key_data_representation_b64=creds.enclave_key_data_representation_b64)
  elif device_type == "software" and creds.private_key_pem:
    signature_bytes = _sign_with_software_key(nonce_bytes, creds.private_key_pem)
    algorithm = _determine_signing_algorithm_name(creds)
  else:
    raise NotEnrolledError(
      "Cannot sign challenge: no signing key available. "
      "Credentials exist but contain neither a private key nor an HSM reference."
    )
  if algorithm not in _ACCEPTED_BINDING_JWS_ALGORITHMS:
    raise PeerVerificationError(
      f"A {algorithm} key cannot carry a Registrar binding (ES256 / RS256 / PS256 only); "
      "enroll a declared identity with key_algorithm='ecdsa-p256' (the default) or use a hardware tier."
    )

  # The chain whose leaf is the key that just signed (per-device chains first).
  candidate_chains = []
  for chain_data in (creds.device_certificate_chains or {}).values():
    chain_pem = chain_data.get("certificate_chain_pem") if isinstance(chain_data, dict) else chain_data
    if chain_pem and chain_pem not in candidate_chains:
      candidate_chains.append(chain_pem)
  candidate_chains.append(creds.identity_certificate_chain_pem)
  signing_chain = next((chain for chain in candidate_chains
                        if _certificate_chain_leaf_key_verifies_mode1_signature(chain, nonce_bytes, signature_bytes, algorithm)),
                       None)
  if signing_chain is None:
    raise PeerVerificationError(
      "No stored certificate chain holds the key that signed; re-sync device certificates "
      "(oneid.sync_device_certificate_chains_from_server) or re-enroll."
    )
  signing_key_jwk = _extract_public_key_jwk_from_certificate_chain_pem(signing_chain)
  token = get_token(credentials=creds)
  api_base_url = creds.api_base_url or "https://1id.com"
  binding_jws = _fetch_binding_jws(api_base_url, {"Authorization": token, "User-Agent": USER_AGENT}, signing_key_jwk)
  if not binding_jws:
    raise PeerVerificationError("The Registrar did not issue a binding for the signing key; try again.")

  return IdentityProofBundle(
    signature_bytes=signature_bytes,
    agent_identity_urn=creds.agent_identity_urn,
    registrar_binding_jws=binding_jws,
    algorithm=algorithm,
    agent_id=creds.client_id,
    trust_tier=creds.trust_tier or "",
    certificate_chain_pem=signing_chain,
  )


# ---------------------------------------------------------------------------
# Verifier side
# ---------------------------------------------------------------------------

def _base64url_decode(text: str) -> bytes:
  return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _fetch_json_document(url: str, accept: str = "application/json") -> dict:
  """GET a JSON document. HTTP 4xx (except 429) raise HTTPError (permanent);
  network errors and 429/5xx raise PeerVerificationTemporarilyUnavailableError."""
  request = urllib.request.Request(url, headers={"Accept": accept})
  try:
    with urllib.request.urlopen(request, timeout=_NETWORK_TIMEOUT_SECONDS) as response:
      return json.loads(response.read().decode("utf-8"))
  except urllib.error.HTTPError as http_error:
    if http_error.code == 429 or http_error.code >= 500:
      raise PeerVerificationTemporarilyUnavailableError(f"{url}: HTTP {http_error.code}") from http_error
    raise
  except (urllib.error.URLError, TimeoutError, OSError) as network_error:
    raise PeerVerificationTemporarilyUnavailableError(f"{url}: {network_error}") from network_error


def resolve_agent_identity_at_airs_registry(agent_identity_urn: str) -> dict:
  """Resolve an aid at the AIRS Registry (RDAP) and apply the Resolution
  draft's checks: the answer names exactly this aid and it is operational.
  Returns {current_issuer, hardware_locked, registered_at, max_active_trust_tier}.

  Raises RegistrarAuthorityValidationError (unknown, other aid, not operational,
  no current issuer) or PeerVerificationTemporarilyUnavailableError.
  """
  rdap_url = f"{AIRS_RDAP_BASE_URL}/rdap/aid_identity/{url_quote(agent_identity_urn, safe='')}"
  try:
    data = _fetch_json_document(rdap_url, "application/rdap+json")
  except urllib.error.HTTPError as http_error:
    raise RegistrarAuthorityValidationError(
      f"AIRS Registry does not resolve {agent_identity_urn!r} (HTTP {http_error.code})") from http_error
  except json.JSONDecodeError as json_error:
    raise RegistrarAuthorityValidationError(f"RDAP answer for {agent_identity_urn!r} is not JSON") from json_error
  if not isinstance(data, dict) or data.get("objectClassName") != "aid_agentIdentity":
    raise RegistrarAuthorityValidationError(f"RDAP answer for {agent_identity_urn!r} is not an aid_agentIdentity object")
  aid_data = data.get("aid_data")
  if not isinstance(aid_data, dict):
    raise RegistrarAuthorityValidationError(f"RDAP answer for {agent_identity_urn!r} has no aid_data")
  if data.get("handle") != agent_identity_urn or aid_data.get("canonical") != agent_identity_urn:
    raise RegistrarAuthorityValidationError(
      f"RDAP answer names {aid_data.get('canonical')!r}, not the requested {agent_identity_urn!r}")
  lifecycle_state = aid_data.get("lifecycleState")
  if lifecycle_state != "operational":
    raise RegistrarAuthorityValidationError(
      f"AIRS identity {agent_identity_urn!r} has lifecycleState {lifecycle_state!r} (must be operational)")
  current_issuer = aid_data.get("currentIssuer")
  if not isinstance(current_issuer, str) or not current_issuer:
    raise RegistrarAuthorityValidationError(f"AIRS identity {agent_identity_urn!r} has no current issuer")
  registered_at = next((event.get("eventDate", "") for event in data.get("events") or []
                        if isinstance(event, dict) and event.get("eventAction") == "registration"), "")
  return {
    "current_issuer": current_issuer,
    "hardware_locked": aid_data.get("hardwareLocked") is True,
    "registered_at": registered_at,
    "max_active_trust_tier": aid_data.get("maxActiveTrustTier", ""),
  }


def fetch_issuer_jwk_set_via_rfc8414_metadata(issuer_uri: str) -> list:
  """The issuer's signing keys, ONLY from its RFC 8414 metadata jwks_uri
  (metadata.issuer must equal the issuer). Cached per issuer for 5 minutes."""
  cached_entry = _issuer_jwk_set_cache.get(issuer_uri)
  if cached_entry and time.time() - cached_entry[0] < _RFC8414_JWK_SET_CACHE_SECONDS:
    return cached_entry[1]
  parsed_issuer = urlparse(issuer_uri)
  if parsed_issuer.scheme != "https" or not parsed_issuer.netloc or parsed_issuer.query or parsed_issuer.fragment:
    raise RegistrarAuthorityValidationError(f"issuer {issuer_uri!r} is not an https issuer identifier (RFC 8414)")
  metadata_url = f"https://{parsed_issuer.netloc}/.well-known/oauth-authorization-server{parsed_issuer.path.rstrip('/')}"
  try:
    metadata = _fetch_json_document(metadata_url)
  except urllib.error.HTTPError as http_error:
    raise RegistrarAuthorityValidationError(f"RFC 8414 metadata for {issuer_uri!r} unavailable (HTTP {http_error.code})") from http_error
  if metadata.get("issuer") != issuer_uri:
    raise RegistrarAuthorityValidationError(
      f"RFC 8414 metadata issuer {metadata.get('issuer')!r} does not equal {issuer_uri!r}")
  jwks_uri = metadata.get("jwks_uri")
  if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
    raise RegistrarAuthorityValidationError(f"RFC 8414 metadata for {issuer_uri!r} has no https jwks_uri")
  try:
    jwk_set = _fetch_json_document(jwks_uri)
  except urllib.error.HTTPError as http_error:
    raise RegistrarAuthorityValidationError(f"JWK Set {jwks_uri} unavailable (HTTP {http_error.code})") from http_error
  keys = jwk_set.get("keys") if isinstance(jwk_set, dict) else None
  if not isinstance(keys, list):
    raise RegistrarAuthorityValidationError(f"JWK Set {jwks_uri} has no keys array")
  _issuer_jwk_set_cache[issuer_uri] = (time.time(), keys)
  return keys


def _public_key_from_jwk(jwk: dict):
  """EC (P-256/P-384) or RSA public key from a JWK; private members refused."""
  if any(member in jwk for member in ("d", "p", "q", "dp", "dq", "qi", "k")):
    raise ValueError("JWK contains private key members")
  if jwk.get("kty") == "EC":
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}.get(jwk.get("crv"))
    if curve is None:
      raise ValueError(f"unsupported EC curve {jwk.get('crv')!r}")
    return ec.EllipticCurvePublicNumbers(
      int.from_bytes(_base64url_decode(jwk["x"]), "big"),
      int.from_bytes(_base64url_decode(jwk["y"]), "big"), curve).public_key()
  if jwk.get("kty") == "RSA":
    return rsa.RSAPublicNumbers(
      int.from_bytes(_base64url_decode(jwk["e"]), "big"),
      int.from_bytes(_base64url_decode(jwk["n"]), "big")).public_key()
  raise ValueError(f"unsupported JWK kty {jwk.get('kty')!r}")


def _jws_signature_is_valid(public_key, alg: str, signing_input: bytes, signature: bytes) -> bool:
  try:
    if alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey) and len(signature) == 64:
      der_signature = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
      public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    elif alg == "RS256" and isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256" and isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    else:
      return False
    return True
  except (InvalidSignature, ValueError):
    return False


def _nonce_signature_is_valid(public_key, algorithm: str, nonce_bytes: bytes, signature: bytes) -> bool:
  """The prover's nonce signature (DER ECDSA as PIV / Secure Enclave / software
  keys produce it, or 64-octet r||s) with the bound key."""
  try:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
      if len(signature) == 64:
        signature = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
      public_key.verify(signature, nonce_bytes, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, rsa.RSAPublicKey) and algorithm == "PS256":
      public_key.verify(signature, nonce_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, nonce_bytes, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
      public_key.verify(signature, nonce_bytes)
    else:
      return False
    return True
  except (InvalidSignature, ValueError):
    return False


def verify_peer_identity(
  nonce_bytes: bytes,
  proof_bundle: IdentityProofBundle | dict,
  api_base_url: str | None = None,
  *,
  current_issuer_resolver: Optional[Callable[[str], dict]] = None,
  issuer_jwk_set_provider: Optional[Callable[[str], list]] = None,
  reference_time_unix: Optional[int] = None,
  max_clock_skew_seconds: int = 300,
) -> VerifiedPeerIdentity:
  """Validate another agent's proof bundle on the AIRS authority model (see the
  module docstring). api_base_url is accepted for compatibility and unused: the
  authority now comes from the AIRS Registry and the issuer it names.

  current_issuer_resolver(aid) -> dict like resolve_agent_identity_at_airs_registry()
  and issuer_jwk_set_provider(issuer) -> list of JWKs replace the network lookups
  (tests, air-gapped use).

  Raises:
    RegistrarAuthorityValidationError (alias CertificateChainValidationError)
    SignatureVerificationError
    PeerVerificationTemporarilyUnavailableError
    PeerVerificationError (malformed bundle)
  """
  if isinstance(proof_bundle, dict):
    proof_bundle = IdentityProofBundle.from_dict(proof_bundle)
  if len(nonce_bytes) < 16:
    raise PeerVerificationError("The verifier nonce must be at least 16 bytes")
  aid = proof_bundle.agent_identity_urn
  if not aid or not _AID_URN_PATTERN.fullmatch(aid):
    raise PeerVerificationError(f"Proof bundle carries no valid agent identity URN ({aid!r})")
  if not proof_bundle.registrar_binding_jws:
    raise RegistrarAuthorityValidationError(
      "Proof bundle carries no Registrar binding (made by an SDK older than 3.1.2?); "
      "ask the peer to upgrade and sign again.")

  parts = proof_bundle.registrar_binding_jws.split(".")
  if len(parts) != 3:
    raise RegistrarAuthorityValidationError("Registrar binding is not a compact JWS")
  try:
    header = json.loads(_base64url_decode(parts[0]))
    payload = json.loads(_base64url_decode(parts[1]))
    jws_signature = _base64url_decode(parts[2])
  except (ValueError, json.JSONDecodeError) as decode_error:
    raise RegistrarAuthorityValidationError(f"Registrar binding cannot be decoded: {decode_error}") from decode_error
  if header.get("typ") != REGISTRAR_BINDING_JWS_TYP:
    raise RegistrarAuthorityValidationError(f"Registrar binding typ must be {REGISTRAR_BINDING_JWS_TYP!r}")
  jws_alg = header.get("alg", "")
  if jws_alg not in _ACCEPTED_BINDING_JWS_ALGORITHMS:
    raise RegistrarAuthorityValidationError(f"Registrar binding alg {jws_alg!r} is not accepted")
  if payload.get("sub") != aid:
    raise RegistrarAuthorityValidationError(f"Registrar binding sub {payload.get('sub')!r} is not {aid!r}")
  now = int(reference_time_unix if reference_time_unix is not None else time.time())
  issued_at, expires_at = payload.get("iat"), payload.get("exp")
  if not isinstance(issued_at, int) or not isinstance(expires_at, int) or expires_at <= issued_at:
    raise RegistrarAuthorityValidationError("Registrar binding needs integer iat < exp")
  if issued_at > now + max_clock_skew_seconds:
    raise RegistrarAuthorityValidationError("Registrar binding iat is in the future")
  if expires_at < now - max_clock_skew_seconds:
    raise RegistrarAuthorityValidationError("Registrar binding has expired; ask the peer to sign again")
  bound_jwk = (payload.get("cnf") or {}).get("jwk")
  if not isinstance(bound_jwk, dict):
    raise RegistrarAuthorityValidationError("Registrar binding has no cnf.jwk")
  bound_trust_tier = (payload.get("aid") or {}).get("trust_tier", "")
  if bound_trust_tier not in _VALID_TRUST_TIERS:
    raise RegistrarAuthorityValidationError(f"Registrar binding carries no valid aid.trust_tier ({bound_trust_tier!r})")
  try:
    bound_public_key = _public_key_from_jwk(bound_jwk)
  except (ValueError, KeyError) as jwk_error:
    raise RegistrarAuthorityValidationError(f"Registrar binding cnf.jwk is unusable: {jwk_error}") from jwk_error

  # Authority: the Registry names the current issuer; the binding must be its.
  registry_answer = (current_issuer_resolver or resolve_agent_identity_at_airs_registry)(aid)
  current_issuer = registry_answer.get("current_issuer", "")
  if payload.get("iss") != current_issuer:
    raise RegistrarAuthorityValidationError(
      f"Registrar binding iss {payload.get('iss')!r} is not the Registry's current issuer {current_issuer!r}")
  issuer_keys = (issuer_jwk_set_provider or fetch_issuer_jwk_set_via_rfc8414_metadata)(current_issuer)
  signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
  candidate_keys = [key for key in issuer_keys if isinstance(key, dict)
                    and (header.get("kid") is None or key.get("kid") == header.get("kid"))]
  binding_signature_valid = False
  for candidate_jwk in candidate_keys:
    try:
      issuer_public_key = _public_key_from_jwk(candidate_jwk)
    except (ValueError, KeyError):
      continue
    if _jws_signature_is_valid(issuer_public_key, jws_alg, signing_input, jws_signature):
      binding_signature_valid = True
      break
  if not binding_signature_valid:
    raise RegistrarAuthorityValidationError(
      f"Registrar binding is not signed by a key of {current_issuer!r} (RFC 8414 jwks_uri)")

  if not _nonce_signature_is_valid(bound_public_key, proof_bundle.algorithm, nonce_bytes, proof_bundle.signature_bytes):
    raise SignatureVerificationError("The nonce signature was not made by the key the Registrar bound to this identity")

  canonical_id = aid.rsplit(":", 1)[-1]
  logger.info("Peer identity verified: %s, tier=%s, issuer=%s", aid, bound_trust_tier, current_issuer)
  return VerifiedPeerIdentity(
    agent_id=canonical_id,
    trust_tier=bound_trust_tier,
    enrolled_at=registry_answer.get("registered_at", ""),
    hardware_locked=bool(registry_answer.get("hardware_locked")),
    chain_valid=True,
    agent_identity_urn=aid,
    issuer=current_issuer,
    registrar_binding_expires_at=expires_at,
  )
