"""
AIRS proof-of-possession for HTTP requests: the RFC 9421 HTTP Message
Signatures profile of draft-drake-agent-identity-registry-04 "HTTP Message
Signatures" (sender-constrained tokens; review 072 / OWN-038).

An AIRS access token carries cnf.jwk: the public key of the enrolled
hardware (or declared software) key that authenticated when the token was
issued. The token alone proves nothing -- every request that presents it must
also carry a fresh signature by that key over the request, so a stolen token
is useless without the hardware.

Profile (registry-04):
  label "airs"; covered components, in this order: "@method", "@target-uri",
  "authorization", then "content-digest" when the request has content (the
  RFC 9530 digest is checked against the received bytes) and "content-type"
  when present; parameters created, nonce (>= 96 bits), tag="airs-pop";
  maximum age 60 s plus a small clock-skew allowance; a repeated nonce is
  rejected; the verification key comes ONLY from the token's cnf.jwk (a
  keyid parameter never redirects verification); asymmetric algorithms only:
  RSASSA-PKCS1-v1_5 SHA-256 for RSA keys (TPM attestation keys),
  ECDSA P-256 SHA-256 with the RFC 9421 r||s encoding for EC keys (PIV,
  Secure Enclave, declared), Ed25519 for OKP keys.

This one module serves both sides: sign_request() for agents (the SDK signs
every authenticated call through it) and verify_request() for relying
parties (1id.com and MailPal use it; anyone else can). Python 3.9-safe;
depends only on `cryptography`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

AIRS_SIGNATURE_LABEL = "airs"
AIRS_SIGNATURE_TAG = "airs-pop"
MAXIMUM_SIGNATURE_AGE_SECONDS = 60
# registry-04: "60 seconds plus a small clock-skew allowance". Agents' clocks
# drift (a Windows host was 11 s fast on 2026-09-25); the SDKs correct for it
# with the token's server-issued iat (sign_request_with_token), and relying
# parties allow 30 s for clients that do not.
ALLOWED_CLOCK_SKEW_SECONDS = 30
MINIMUM_NONCE_BITS = 96
REQUIRED_COVERED_COMPONENTS = ("@method", "@target-uri", "authorization")


class AirsHttpMessageSignatureRejected(Exception):
  """The request's AIRS proof of possession is missing, stale, replayed, or
  invalid. Relying parties answer HTTP 401 (registry-04)."""


# --------------------------------------------------------------------------
# Content-Digest (RFC 9530)
# --------------------------------------------------------------------------

def compute_content_digest_header_value_for_request_body(body: bytes) -> str:
  return "sha-256=:%s:" % base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")


def _content_digest_matches_body(content_digest_header_value: str, body: bytes) -> bool:
  for member in content_digest_header_value.split(","):
    name, _, value = member.strip().partition("=")
    if name.strip().lower() == "sha-256":
      value = value.strip()
      if len(value) >= 2 and value[0] == ":" and value[-1] == ":":
        try:
          return base64.b64decode(value[1:-1], validate=True) == hashlib.sha256(body).digest()
        except (ValueError, TypeError):
          return False
  return False


# --------------------------------------------------------------------------
# Signature base (RFC 9421 s2.5) and parameters
# --------------------------------------------------------------------------

def serialize_airs_signature_parameters(
  covered_component_names: Sequence[str], created: int, nonce: str,
  keyid: Optional[str] = None,
) -> str:
  inner_list = "(%s)" % " ".join('"%s"' % name for name in covered_component_names)
  serialized = '%s;created=%d;nonce="%s";tag="%s"' % (inner_list, created, nonce, AIRS_SIGNATURE_TAG)
  if keyid:
    # RFC 7638 thumbprint of the token's cnf.jwk: lets generic RFC 9421
    # libraries resolve the key; never used to choose a different key.
    serialized += ';keyid="%s"' % keyid
  return serialized


def compute_rfc7638_jwk_sha256_thumbprint(jwk: Mapping[str, object]) -> str:
  import json
  required_members = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x")}
  members = required_members.get(str(jwk.get("kty")))
  if members is None:
    raise AirsHttpMessageSignatureRejected("cannot thumbprint JWK key type %r" % jwk.get("kty"))
  canonical = json.dumps({name: jwk[name] for name in members}, separators=(",", ":"), sort_keys=True)
  return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("utf-8")).digest()).decode("ascii").rstrip("=")


def build_airs_signature_base(
  covered_component_values: Sequence[Tuple[str, str]], serialized_signature_parameters: str,
) -> bytes:
  lines = ['"%s": %s' % (name, value) for name, value in covered_component_values]
  lines.append('"@signature-params": %s' % serialized_signature_parameters)
  return "\n".join(lines).encode("utf-8")


def _normalized_header_value(value: str) -> str:
  # RFC 9421 s2.1: strip leading/trailing whitespace (single field values)
  return value.strip()


# --------------------------------------------------------------------------
# Minimal Structured Field parsing for Signature-Input / Signature
# (RFC 8941 dictionaries whose members are inner lists or byte sequences)
# --------------------------------------------------------------------------

_SF_KEY = r"[a-z*][a-z0-9_\-.*]*"


def _split_top_level_dictionary_members(field_value: str) -> List[str]:
  members, depth, in_string, current = [], 0, False, []
  index = 0
  while index < len(field_value):
    character = field_value[index]
    if in_string:
      current.append(character)
      if character == "\\" and index + 1 < len(field_value):
        index += 1
        current.append(field_value[index])
      elif character == '"':
        in_string = False
    elif character == '"':
      in_string = True
      current.append(character)
    elif character == "(":
      depth += 1
      current.append(character)
    elif character == ")":
      depth -= 1
      current.append(character)
    elif character == "," and depth == 0:
      members.append("".join(current).strip())
      current = []
    else:
      current.append(character)
    index += 1
  if "".join(current).strip():
    members.append("".join(current).strip())
  return members


def _parse_signature_input_member(member_value: str) -> Tuple[List[str], Dict[str, object]]:
  match = re.fullmatch(r'\(\s*((?:"[^"\\]*"\s*)*)\)(.*)', member_value.strip(), re.S)
  if not match:
    raise AirsHttpMessageSignatureRejected("Signature-Input member is not an inner list")
  components = re.findall(r'"([^"\\]*)"', match.group(1))
  parameters: Dict[str, object] = {}
  for parameter in re.finditer(r';\s*(%s)(?:=("(?:[^"\\]|\\.)*"|-?\d+|[A-Za-z*][A-Za-z0-9:/%%*._!#$&\'+^`|~-]*))?' % _SF_KEY,
                               match.group(2)):
    name, raw = parameter.group(1), parameter.group(2)
    if raw is None:
      value: object = True
    elif raw.startswith('"'):
      value = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    elif re.fullmatch(r"-?\d+", raw):
      value = int(raw)
    else:
      value = raw
    parameters[name] = value
  return components, parameters


def _dictionary_members_by_label(field_value: str) -> Dict[str, str]:
  members = {}
  for member in _split_top_level_dictionary_members(field_value):
    label, separator, value = member.partition("=")
    if not separator or not re.fullmatch(_SF_KEY, label.strip()):
      raise AirsHttpMessageSignatureRejected("malformed signature dictionary member")
    members[label.strip()] = value.strip()
  return members


# --------------------------------------------------------------------------
# Keys and algorithms (from cnf.jwk only)
# --------------------------------------------------------------------------

def _b64url_decode(value: str) -> bytes:
  return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_public_key_from_confirmation_jwk(confirmation_jwk: Mapping[str, object]):
  from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
  key_type = confirmation_jwk.get("kty")
  if key_type == "RSA":
    return rsa.RSAPublicNumbers(
      int.from_bytes(_b64url_decode(str(confirmation_jwk["e"])), "big"),
      int.from_bytes(_b64url_decode(str(confirmation_jwk["n"])), "big")).public_key()
  if key_type == "EC" and confirmation_jwk.get("crv") == "P-256":
    return ec.EllipticCurvePublicNumbers(
      int.from_bytes(_b64url_decode(str(confirmation_jwk["x"])), "big"),
      int.from_bytes(_b64url_decode(str(confirmation_jwk["y"])), "big"), ec.SECP256R1()).public_key()
  if key_type == "OKP" and confirmation_jwk.get("crv") == "Ed25519":
    return ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(str(confirmation_jwk["x"])))
  raise AirsHttpMessageSignatureRejected(
    "cnf.jwk key type %r is not an AIRS confirmation key (RSA, EC P-256, Ed25519)" % key_type)


def convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s(der_signature: bytes, coordinate_octets: int = 32) -> bytes:
  from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
  r, s = decode_dss_signature(der_signature)
  return r.to_bytes(coordinate_octets, "big") + s.to_bytes(coordinate_octets, "big")


def _verify_signature_with_confirmation_key(public_key, signature: bytes, signature_base: bytes) -> None:
  from cryptography.exceptions import InvalidSignature
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
  from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
  try:
    if isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, signature_base, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
      if len(signature) != 64:
        raise AirsHttpMessageSignatureRejected("ecdsa-p256-sha256 signature must be 64 octets (r||s)")
      public_key.verify(
        encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
        signature_base, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
      public_key.verify(signature, signature_base)
    else:
      raise AirsHttpMessageSignatureRejected("unsupported confirmation key")
  except InvalidSignature:
    raise AirsHttpMessageSignatureRejected("signature does not verify with the token's cnf.jwk") from None


# --------------------------------------------------------------------------
# Signing (agents)
# --------------------------------------------------------------------------

def sign_request(
  method: str,
  target_uri: str,
  headers: Mapping[str, str],
  body: Optional[bytes],
  sign_signature_base_with_confirmation_key: Callable[[bytes], bytes],
  created: Optional[int] = None,
  nonce: Optional[str] = None,
  confirmation_jwk: Optional[Mapping[str, object]] = None,
) -> Dict[str, str]:
  """Return the headers to ADD to an authenticated request: Content-Digest
  (when there is content), Signature-Input and Signature. `headers` must
  already hold the Authorization field; `sign_signature_base_with_
  confirmation_key` returns the RFC 9421 signature bytes (RSASSA-PKCS1-v1_5,
  raw r||s for P-256, or Ed25519) made by the token's confirmation key."""
  lowered = {name.lower(): value for name, value in headers.items()}
  if "authorization" not in lowered:
    raise ValueError("sign_request needs the Authorization header it protects")
  added: Dict[str, str] = {}
  covered: List[Tuple[str, str]] = [
    ("@method", method.upper()),
    ("@target-uri", target_uri),
    ("authorization", _normalized_header_value(lowered["authorization"])),
  ]
  if body:
    added["Content-Digest"] = compute_content_digest_header_value_for_request_body(body)
    covered.append(("content-digest", added["Content-Digest"]))
  if "content-type" in lowered:
    covered.append(("content-type", _normalized_header_value(lowered["content-type"])))
  created = int(time.time()) if created is None else created
  nonce = nonce or base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
  parameters = serialize_airs_signature_parameters(
    [name for name, _ in covered], created, nonce,
    keyid=compute_rfc7638_jwk_sha256_thumbprint(confirmation_jwk) if confirmation_jwk else None)
  signature = sign_signature_base_with_confirmation_key(build_airs_signature_base(covered, parameters))
  added["Signature-Input"] = "%s=%s" % (AIRS_SIGNATURE_LABEL, parameters)
  added["Signature"] = "%s=:%s:" % (AIRS_SIGNATURE_LABEL, base64.b64encode(signature).decode("ascii"))
  return added


def server_clock_offset_seconds_from_access_token(access_token: str, received_at: Optional[float] = None) -> float:
  """Seconds to add to the local clock to approximate the issuer's clock: the
  token's iat (server time at issuance) minus the local time it arrived. Read
  without verification (it only steers the `created` parameter)."""
  import json
  try:
    segment = access_token.split(".")[1]
    issued_at = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))).get("iat")
  except (IndexError, ValueError, AttributeError):
    return 0.0
  if not isinstance(issued_at, (int, float)):
    return 0.0
  return float(issued_at) - (time.time() if received_at is None else received_at)


def sign_request_with_token(
  method: str, target_uri: str, headers: Mapping[str, str], body: Optional[bytes], token,
) -> Dict[str, str]:
  """sign_request for an oneid Token: its enrolled-key signer, its cnf.jwk as
  keyid, and `created` on the issuer's clock (local time + the offset learned
  from the token's iat), so a drifting agent clock does not get requests
  refused as stale or future-dated."""
  signer = getattr(token, "airs_request_signer", None)
  if signer is None:
    raise ValueError("this Token cannot sign requests (it was not issued through oneid.get_token())")
  offset = getattr(token, "server_clock_offset_seconds", 0.0) or 0.0
  return sign_request(method, target_uri, headers, body, signer,
                      created=int(time.time() + offset),
                      confirmation_jwk=getattr(token, "confirmation_jwk", None))


# --------------------------------------------------------------------------
# Verification (relying parties)
# --------------------------------------------------------------------------

def verify_request(
  method: str,
  target_uri: str,
  headers: Mapping[str, str],
  body: bytes,
  confirmation_jwk: Mapping[str, object],
  record_nonce_and_report_if_already_seen: Callable[[str, int], bool],
  now: Optional[float] = None,
) -> None:
  """Verify a request's AIRS proof of possession against the token's
  cnf.jwk. `target_uri` is the absolute URI the client addressed (the
  relying party's public origin + path + query). `record_nonce_and_report_
  if_already_seen(nonce, expires_at_epoch)` must atomically record the nonce
  and return True when it was already recorded (replay). Raises
  AirsHttpMessageSignatureRejected; returns None when the proof is valid."""
  lowered = {name.lower(): value for name, value in headers.items()}
  if "signature-input" not in lowered or "signature" not in lowered:
    raise AirsHttpMessageSignatureRejected(
      "missing Signature-Input/Signature: AIRS tokens are sender-constrained (registry-04), "
      "a bearer presentation is not accepted")
  signature_inputs = _dictionary_members_by_label(lowered["signature-input"])
  signatures = _dictionary_members_by_label(lowered["signature"])
  if AIRS_SIGNATURE_LABEL not in signature_inputs or AIRS_SIGNATURE_LABEL not in signatures:
    raise AirsHttpMessageSignatureRejected('no signature labelled "%s"' % AIRS_SIGNATURE_LABEL)
  components, parameters = _parse_signature_input_member(signature_inputs[AIRS_SIGNATURE_LABEL])

  if parameters.get("tag") != AIRS_SIGNATURE_TAG:
    raise AirsHttpMessageSignatureRejected('tag parameter must be "%s"' % AIRS_SIGNATURE_TAG)
  if "keyid" in parameters and parameters["keyid"] != compute_rfc7638_jwk_sha256_thumbprint(confirmation_jwk):
    # registry-04: keyid MUST NOT redirect verification to a different key
    raise AirsHttpMessageSignatureRejected("keyid does not name the token's cnf.jwk")
  created, nonce = parameters.get("created"), parameters.get("nonce")
  if not isinstance(created, int) or isinstance(created, bool):
    raise AirsHttpMessageSignatureRejected("created parameter missing")
  if not isinstance(nonce, str) or not nonce:
    raise AirsHttpMessageSignatureRejected("nonce parameter missing")
  if len(nonce) * 6 < MINIMUM_NONCE_BITS:
    raise AirsHttpMessageSignatureRejected("nonce shorter than %d bits" % MINIMUM_NONCE_BITS)
  now = time.time() if now is None else now
  if created > now + ALLOWED_CLOCK_SKEW_SECONDS:
    raise AirsHttpMessageSignatureRejected("created is in the future")
  if now - created > MAXIMUM_SIGNATURE_AGE_SECONDS + ALLOWED_CLOCK_SKEW_SECONDS:
    raise AirsHttpMessageSignatureRejected("signature is older than %d s" % MAXIMUM_SIGNATURE_AGE_SECONDS)

  for required in REQUIRED_COVERED_COMPONENTS:
    if required not in components:
      raise AirsHttpMessageSignatureRejected("signature does not cover %s" % required)
  if body and "content-digest" not in components:
    raise AirsHttpMessageSignatureRejected("request has content but the signature does not cover content-digest")
  if "content-type" in lowered and "content-type" not in components:
    raise AirsHttpMessageSignatureRejected("Content-Type present but not covered")
  if len(set(components)) != len(components):
    raise AirsHttpMessageSignatureRejected("a component is covered twice")

  covered: List[Tuple[str, str]] = []
  for name in components:
    if name == "@method":
      covered.append((name, method.upper()))
    elif name == "@target-uri":
      covered.append((name, target_uri))
    elif name.startswith("@"):
      raise AirsHttpMessageSignatureRejected("derived component %s is not part of the AIRS profile" % name)
    else:
      if name not in lowered:
        raise AirsHttpMessageSignatureRejected("covered field %s is absent" % name)
      covered.append((name, _normalized_header_value(lowered[name])))
  if "content-digest" in components and not _content_digest_matches_body(lowered["content-digest"], body or b""):
    raise AirsHttpMessageSignatureRejected("Content-Digest does not match the received content")

  signature_value = signatures[AIRS_SIGNATURE_LABEL]
  if not (len(signature_value) >= 2 and signature_value[0] == ":" and signature_value[-1] == ":"):
    raise AirsHttpMessageSignatureRejected("Signature member is not a byte sequence")
  try:
    signature = base64.b64decode(signature_value[1:-1], validate=True)
  except (ValueError, TypeError):
    raise AirsHttpMessageSignatureRejected("Signature is not base64") from None

  serialized_parameters = signature_inputs[AIRS_SIGNATURE_LABEL]
  _verify_signature_with_confirmation_key(
    load_public_key_from_confirmation_jwk(confirmation_jwk), signature,
    build_airs_signature_base(covered, serialized_parameters))
  # replay check last, so an invalid signature cannot burn a victim's nonce
  if record_nonce_and_report_if_already_seen(
      nonce, int(created + MAXIMUM_SIGNATURE_AGE_SECONDS + ALLOWED_CLOCK_SKEW_SECONDS)):
    raise AirsHttpMessageSignatureRejected("nonce already used (replay)")
