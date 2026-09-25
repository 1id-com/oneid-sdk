"""AIRS proof of possession (registry-04 "HTTP Message Signatures", RFC 9421):
sign_request / verify_request round trips for every AIRS key type and every
rejection the profile requires (review 072 / OWN-038)."""

import base64
import json
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from oneid import airs_http_message_signatures as airs

TARGET_URI = "https://1id.com/api/v1/proof/sd-jwt/message?format=compact"
BODY = json.dumps({"message_binding": "abc"}).encode()


def b64url_uint(value, length):
  return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def jwk_and_signer(key_kind):
  if key_kind == "rsa":
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk = {"kty": "RSA", "n": b64url_uint(numbers.n, 256), "e": b64url_uint(numbers.e, 3)}
    return jwk, lambda base: private_key.sign(base, padding.PKCS1v15(), hashes.SHA256())
  if key_kind == "p256":
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url_uint(numbers.x, 32), "y": b64url_uint(numbers.y, 32)}
    return jwk, lambda base: airs.convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s(
      private_key.sign(base, ec.ECDSA(hashes.SHA256())))
  private_key = ed25519.Ed25519PrivateKey.generate()
  from cryptography.hazmat.primitives import serialization
  raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
  jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}
  return jwk, private_key.sign


class NonceLedger:
  def __init__(self):
    self.seen = set()

  def __call__(self, nonce, expires_at):
    already = nonce in self.seen
    self.seen.add(nonce)
    return already


class TestAirsHttpMessageSignatures(unittest.TestCase):
  def signed_request(self, key_kind="p256", body=BODY, **overrides):
    jwk, signer = jwk_and_signer(key_kind)
    headers = {"Authorization": "Bearer eyJhbGciOi.token.sig", "Content-Type": "application/json"}
    headers.update(airs.sign_request("POST", TARGET_URI, headers, body, signer, **overrides))
    return jwk, headers

  def verify(self, jwk, headers, method="POST", target_uri=TARGET_URI, body=BODY, ledger=None, now=None):
    airs.verify_request(method, target_uri, headers, body, jwk, ledger or NonceLedger(), now=now)

  def test_round_trip_for_every_airs_key_type(self):
    for key_kind in ("rsa", "p256", "ed25519"):
      with self.subTest(key_kind=key_kind):
        jwk, headers = self.signed_request(key_kind)
        self.verify(jwk, headers)

  def test_request_without_content_needs_no_content_digest(self):
    jwk, signer = jwk_and_signer("p256")
    headers = {"Authorization": "Bearer t"}
    headers.update(airs.sign_request("GET", "https://1id.com/api/v1/identity/devices", headers, None, signer))
    self.assertNotIn("Content-Digest", headers)
    airs.verify_request("GET", "https://1id.com/api/v1/identity/devices", headers, b"", jwk, NonceLedger())

  def test_bearer_only_presentation_is_rejected(self):
    jwk, _ = jwk_and_signer("p256")
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "bearer"):
      self.verify(jwk, {"Authorization": "Bearer t"})

  def test_each_covered_part_of_the_request_is_protected(self):
    jwk, headers = self.signed_request()
    tampered_cases = {
      "method": dict(method="PUT"),
      "target uri path": dict(target_uri=TARGET_URI.replace("message", "messages")),
      "target uri query": dict(target_uri=TARGET_URI + "&x=1"),
      "body": dict(body=BODY + b" "),
    }
    for label, change in tampered_cases.items():
      with self.subTest(label):
        with self.assertRaises(airs.AirsHttpMessageSignatureRejected):
          self.verify(jwk, headers, **change)
    for field, value in (("Authorization", "Bearer other.token"), ("Content-Type", "text/plain")):
      with self.subTest(field):
        with self.assertRaises(airs.AirsHttpMessageSignatureRejected):
          self.verify(jwk, dict(headers, **{field: value}))

  def test_another_key_or_the_right_key_with_a_foreign_signature_fails(self):
    _, headers = self.signed_request()
    other_jwk, _ = jwk_and_signer("p256")
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "does not verify"):
      self.verify(other_jwk, headers)

  def test_stale_future_and_replayed_signatures_are_rejected(self):
    now = time.time()
    jwk, headers = self.signed_request(created=int(now) - 120)
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "older"):
      self.verify(jwk, headers, now=now)
    jwk, headers = self.signed_request(created=int(now) + 60)
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "future"):
      self.verify(jwk, headers, now=now)
    jwk, headers = self.signed_request()
    ledger = NonceLedger()
    self.verify(jwk, headers, ledger=ledger)
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "replay"):
      self.verify(jwk, headers, ledger=ledger)

  def test_invalid_signature_does_not_burn_the_nonce(self):
    jwk, headers = self.signed_request()
    other_jwk, _ = jwk_and_signer("p256")
    ledger = NonceLedger()
    with self.assertRaises(airs.AirsHttpMessageSignatureRejected):
      self.verify(other_jwk, headers, ledger=ledger)
    self.assertEqual(ledger.seen, set())
    self.verify(jwk, headers, ledger=ledger)

  def test_profile_parameters_are_enforced(self):
    jwk, headers = self.signed_request()
    for label, old, new in (
      ("tag", 'tag="airs-pop"', 'tag="other"'),
      ("short nonce", 'nonce="', 'nonce="ab'),
      ("label", "airs=", "sig1="),
    ):
      with self.subTest(label):
        changed = dict(headers)
        changed["Signature-Input"] = headers["Signature-Input"].replace(old, new, 1)
        if label == "short nonce":
          changed["Signature-Input"] = __import__("re").sub(r'nonce="[^"]*"', 'nonce="abcd"', headers["Signature-Input"])
        if label == "label":
          changed["Signature"] = headers["Signature"].replace("airs=", "sig1=", 1)
        with self.assertRaises(airs.AirsHttpMessageSignatureRejected):
          self.verify(jwk, changed)

  def test_uncovered_content_digest_with_content_is_rejected(self):
    jwk, signer = jwk_and_signer("p256")
    headers = {"Authorization": "Bearer t"}
    headers.update(airs.sign_request("POST", TARGET_URI, headers, None, signer))  # signed as if no content
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "content-digest"):
      self.verify(jwk, headers, body=BODY)

  def test_other_signature_labels_are_ignored_but_airs_is_required(self):
    jwk, headers = self.signed_request()
    headers["Signature-Input"] = 'other=("@method");created=1;nonce="x", ' + headers["Signature-Input"]
    headers["Signature"] = "other=:AAAA:, " + headers["Signature"]
    self.verify(jwk, headers)

  def test_keyid_names_the_cnf_key_and_can_never_redirect_verification(self):
    jwk, signer = jwk_and_signer("p256")
    headers = {"Authorization": "Bearer t"}
    headers.update(airs.sign_request("GET", TARGET_URI, headers, None, signer, confirmation_jwk=jwk))
    self.assertIn('keyid="%s"' % airs.compute_rfc7638_jwk_sha256_thumbprint(jwk), headers["Signature-Input"])
    airs.verify_request("GET", TARGET_URI, headers, b"", jwk, NonceLedger())
    other_jwk, _ = jwk_and_signer("p256")
    with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "keyid"):
      airs.verify_request("GET", TARGET_URI, headers, b"", other_jwk, NonceLedger())

  def test_rfc7638_thumbprint_known_answer(self):
    # RFC 7638 s3.1 example key
    rfc7638_example_jwk = {
      "kty": "RSA", "e": "AQAB",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
           "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
           "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
           "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
    self.assertEqual(airs.compute_rfc7638_jwk_sha256_thumbprint(rfc7638_example_jwk),
                     "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

  def test_sdk_http_client_signs_every_request_that_carries_a_token(self):
    """End to end over a real local HTTP server: the SDK's _http client, given
    a Token as the Authorization value, sends a request that verify_request
    accepts -- including the declared-tier signer built by oneid.auth."""
    import http.server
    import threading
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import serialization
    from oneid import _http
    from oneid.auth import build_airs_request_signer_for_enrolled_key
    from oneid.identity import Token

    captured = {}

    class CapturingHandler(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
        captured["headers"] = dict(self.headers.items())
        captured["path"] = self.path
        captured["body"] = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

      def log_message(self, *args):
        pass

    server = http.server.HTTPServer(("127.0.0.1", 0), CapturingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
      private_key = ec.generate_private_key(ec.SECP256R1())
      private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
      numbers = private_key.public_key().public_numbers()
      jwk = {"kty": "EC", "crv": "P-256", "x": b64url_uint(numbers.x, 32), "y": b64url_uint(numbers.y, 32)}
      token = Token(access_token="header.payload.sig", token_type="Bearer",
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), refresh_token=None,
                    airs_request_signer=build_airs_request_signer_for_enrolled_key(
                      "declared", software_private_key_pem=private_pem),
                    confirmation_jwk=jwk)
      url = "http://127.0.0.1:%d/api/v1/proof/sd-jwt/message?x=1" % server.server_port
      response = _http.Client().post(url, json={"a": 1}, headers={"Authorization": token})
      self.assertEqual(response.status_code, 200)
      self.assertEqual(captured["headers"]["Authorization"], "Bearer header.payload.sig")
      airs.verify_request("POST", url, captured["headers"], captured["body"], jwk, NonceLedger())
      with self.assertRaisesRegex(ValueError, "cannot sign"):
        _http.Client().post(url, json={}, headers={"Authorization": Token(
          access_token="t", token_type="Bearer", expires_at=datetime.now(timezone.utc), refresh_token=None)})
    finally:
      server.shutdown()

  def test_drifting_agent_clock_is_corrected_with_the_tokens_issued_at(self):
    """A host 11 s fast (RoG, 2026-09-25) and one 45 s fast: the token's iat
    gives the issuer clock offset, sign_request_with_token uses it, and the
    request verifies on the relying party's clock."""
    from types import SimpleNamespace
    for local_clock_ahead_seconds in (11, 45):
      jwk, signer = jwk_and_signer("p256")
      issuer_now = time.time()
      payload = base64.urlsafe_b64encode(json.dumps({"iat": int(issuer_now)}).encode()).rstrip(b"=").decode()
      access_token = "h." + payload + ".s"
      offset = airs.server_clock_offset_seconds_from_access_token(
        access_token, received_at=issuer_now + local_clock_ahead_seconds)
      self.assertAlmostEqual(offset, -local_clock_ahead_seconds, delta=1)
      token = SimpleNamespace(airs_request_signer=signer, confirmation_jwk=jwk, server_clock_offset_seconds=offset)
      headers = {"Authorization": "Bearer " + access_token}
      real_time = time.time
      try:
        time.time = lambda: real_time() + local_clock_ahead_seconds  # the agent's fast clock
        headers.update(airs.sign_request_with_token("GET", TARGET_URI, headers, None, token))
      finally:
        time.time = real_time
      airs.verify_request("GET", TARGET_URI, headers, b"", jwk, NonceLedger())
      # without the correction a 45 s drift would be refused as future-dated
      if local_clock_ahead_seconds > airs.ALLOWED_CLOCK_SKEW_SECONDS:
        uncorrected = {"Authorization": "Bearer " + access_token}
        uncorrected.update(airs.sign_request("GET", TARGET_URI, uncorrected, None, signer,
                                             created=int(time.time() + local_clock_ahead_seconds)))
        with self.assertRaisesRegex(airs.AirsHttpMessageSignatureRejected, "future"):
          airs.verify_request("GET", TARGET_URI, uncorrected, b"", jwk, NonceLedger())

  def test_signature_base_known_answer(self):
    covered = [("@method", "POST"), ("@target-uri", "https://1id.com/api/v1/x?y=1"),
               ("authorization", "Bearer abc"), ("content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")]
    parameters = airs.serialize_airs_signature_parameters([name for name, _ in covered], 1790000000, "n0nce")
    self.assertEqual(
      airs.build_airs_signature_base(covered, parameters).decode(),
      '"@method": POST\n'
      '"@target-uri": https://1id.com/api/v1/x?y=1\n'
      '"authorization": Bearer abc\n'
      '"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n'
      '"@signature-params": ("@method" "@target-uri" "authorization" "content-digest")'
      ';created=1790000000;nonce="n0nce";tag="airs-pop"')
    self.assertEqual(airs.compute_content_digest_header_value_for_request_body(b'{"hello": "world"}'),
                     "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")


if __name__ == "__main__":
  unittest.main()
