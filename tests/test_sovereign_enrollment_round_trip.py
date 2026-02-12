"""
End-to-end test for sovereign-tier TPM enrollment.

This test exercises the COMPLETE enrollment round-trip:
  1. Go binary extracts EK cert + generates AK from the real TPM (requires admin)
  2. Python sends EK cert + AK data to server /enroll/begin
  3. Server runs MakeCredential, returns credential_blob + encrypted_secret
  4. Go binary runs ActivateCredential on the real TPM (requires admin)
  5. Python sends decrypted credential to server /enroll/activate
  6. Server verifies and issues the identity

REQUIREMENTS:
  - Must run on a machine with a TPM (e.g., the RoG laptop)
  - Must run as Administrator (elevation is needed for TPM access)
  - Must have the oneid-enroll binary built and in the cwd or PATH
  - Must have network access to the live 1id.com server

IMPORTANT: This test creates REAL AKs in the TPM and REAL identities on the server.
Run it sparingly -- TPM persistent handle space is finite (256 handles in our range).
"""

import base64
import json
import os
import subprocess
import sys
import unittest
import urllib.request
import urllib.error

# The test API base URL (live server)
API_BASE_URL = "https://1id.com"

# Path to the Go binary -- look in common locations
BINARY_PATHS = [
  os.path.join(os.path.dirname(__file__), "..", "..", "oneid-enroll", "oneid-enroll.exe"),
  os.path.join(os.path.dirname(__file__), "..", "..", "oneid-enroll", "oneid-enroll"),
  "oneid-enroll.exe",
  "oneid-enroll",
]


def _find_binary():
  """Find the oneid-enroll binary."""
  for path_candidate in BINARY_PATHS:
    abs_path = os.path.abspath(path_candidate)
    if os.path.exists(abs_path):
      return abs_path
  return None


def _server_is_reachable():
  """Quick check if the 1id.com server is reachable."""
  try:
    req = urllib.request.Request(f"{API_BASE_URL}/api/health", method="GET")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=5) as response:
      data = json.loads(response.read())
      return data.get("status") == "healthy"
  except Exception:
    return False


def _run_binary(command, args=None, timeout_seconds=60):
  """Run the Go binary and return parsed JSON output."""
  binary_path = _find_binary()
  if binary_path is None:
    raise unittest.SkipTest("oneid-enroll binary not found")

  cmd = [binary_path, command, "--json"]
  if args:
    cmd.extend(args)

  result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=timeout_seconds,
  )

  if result.stdout.strip():
    output = json.loads(result.stdout)
  else:
    output = {"returncode": result.returncode, "stderr": result.stderr}

  if result.returncode != 0:
    error_msg = output.get("error", result.stderr or f"exit code {result.returncode}")
    error_code = output.get("error_code", "UNKNOWN")
    raise RuntimeError(f"Binary command '{command}' failed [{error_code}]: {error_msg}")

  return output


def _api_request(method, path, json_body=None):
  """Make an HTTP request to the 1id.com API."""
  url = f"{API_BASE_URL}{path}"
  data = json.dumps(json_body).encode("utf-8") if json_body else None

  req = urllib.request.Request(url, data=data, method=method)
  req.add_header("Content-Type", "application/json")
  req.add_header("Accept", "application/json")

  try:
    with urllib.request.urlopen(req, timeout=30) as response:
      body = json.loads(response.read())
  except urllib.error.HTTPError as http_err:
    body = json.loads(http_err.read())
    if not body.get("ok", False):
      error_info = body.get("error", {})
      raise RuntimeError(
        f"API error [{error_info.get('code', 'UNKNOWN')}]: "
        f"{error_info.get('message', str(http_err))}"
      )
    raise

  if not body.get("ok", False):
    error_info = body.get("error", {})
    raise RuntimeError(
      f"API error [{error_info.get('code', 'UNKNOWN')}]: "
      f"{error_info.get('message', 'Unknown')}"
    )

  return body.get("data", {})


@unittest.skipUnless(_server_is_reachable(), "1id.com server not reachable")
@unittest.skipUnless(_find_binary(), "oneid-enroll binary not found")
class TestSovereignEnrollmentRoundTrip(unittest.TestCase):
  """Full round-trip test for sovereign-tier TPM enrollment."""

  def test_phase_1_extract_ek_and_generate_ak(self):
    """Phase 1: Extract EK cert and generate AK from the real TPM.

    This test verifies the Go binary can:
      - Read the EK certificate from TPM NV storage
      - Generate a new AK and persist it
      - Return both EK and AK data in the correct JSON format
    """
    # extract does NOT need --elevated when already running as admin.
    # If this test is run as admin, it should work directly.
    output = _run_binary("extract")

    # Verify EK data is present
    self.assertIn("ek_cert_pem", output, "Missing ek_cert_pem in extract output")
    self.assertIn("ek_public_pem", output, "Missing ek_public_pem in extract output")
    self.assertIn("ek_fingerprint", output, "Missing ek_fingerprint in extract output")

    # Verify AK data is present (new fields)
    self.assertIn("ak_public_pem", output, "Missing ak_public_pem in extract output")
    self.assertIn("ak_handle", output, "Missing ak_handle in extract output")
    self.assertIn("ak_tpmt_public_b64", output, "Missing ak_tpmt_public_b64 in extract output")
    self.assertIn("ak_tpm_name", output, "Missing ak_tpm_name in extract output")

    # Verify formats
    self.assertTrue(
      output["ek_cert_pem"].startswith("-----BEGIN CERTIFICATE-----"),
      "EK cert should be PEM format"
    )
    self.assertTrue(
      output["ak_public_pem"].startswith("-----BEGIN PUBLIC KEY-----"),
      "AK public key should be PEM format"
    )
    self.assertTrue(
      output["ak_handle"].startswith("0x8100"),
      "AK handle should be in the persistent range"
    )
    # TPMT_PUBLIC should be valid base64
    base64.b64decode(output["ak_tpmt_public_b64"])
    # TPM Name should be valid hex (34 bytes = 68 hex chars)
    bytes.fromhex(output["ak_tpm_name"])
    self.assertEqual(
      len(bytes.fromhex(output["ak_tpm_name"])),
      34,
      "TPM Name should be 34 bytes (2 alg + 32 hash)"
    )

    print(f"\n  EK fingerprint: {output['ek_fingerprint'][:16]}...")
    print(f"  EK issuer: {output.get('issuer_cn', 'N/A')}")
    print(f"  AK handle: {output['ak_handle']}")
    print(f"  AK TPM Name: {output['ak_tpm_name'][:16]}...")

  def test_full_sovereign_enrollment_round_trip(self):
    """Full end-to-end sovereign enrollment:
    extract -> begin -> activate -> complete.

    This is THE test that proves the entire TPM identity system works.
    """
    # === PHASE 1: Extract from TPM ===
    print("\n  Phase 1: Extracting EK cert + generating AK from TPM...")
    extract_result = _run_binary("extract")

    ek_cert_pem = extract_result["ek_cert_pem"]
    ak_public_pem = extract_result["ak_public_pem"]
    ak_tpmt_public_b64 = extract_result["ak_tpmt_public_b64"]
    ak_handle = extract_result["ak_handle"]

    print(f"  EK fingerprint: {extract_result['ek_fingerprint'][:16]}...")
    print(f"  AK handle: {ak_handle}")

    # === PHASE 2: Server enrollment begin (MakeCredential) ===
    print("  Phase 2: Sending to server /enroll/begin (MakeCredential)...")
    begin_response = _api_request("POST", "/api/v1/enroll/begin", json_body={
      "ek_certificate_pem": ek_cert_pem,
      "ak_public_key_pem": ak_public_pem,
      "ak_tpmt_public_b64": ak_tpmt_public_b64,
      "requested_handle": None,
      "operator_email": "tpm-test@1id.com",
    })

    self.assertIn("enrollment_session_id", begin_response)
    self.assertIn("credential_blob", begin_response)
    self.assertIn("encrypted_secret", begin_response)
    self.assertIn("trust_tier", begin_response)

    session_id = begin_response["enrollment_session_id"]
    credential_blob_b64 = begin_response["credential_blob"]
    encrypted_secret_b64 = begin_response["encrypted_secret"]
    trust_tier = begin_response["trust_tier"]

    print(f"  Session: {session_id}")
    print(f"  Trust tier: {trust_tier}")
    print(f"  Credential blob: {len(base64.b64decode(credential_blob_b64))} bytes")
    print(f"  Encrypted secret: {len(base64.b64decode(encrypted_secret_b64))} bytes")

    # === PHASE 3: TPM ActivateCredential ===
    print("  Phase 3: Running TPM2_ActivateCredential...")
    activate_result = _run_binary("activate", args=[
      "--credential-blob", credential_blob_b64,
      "--encrypted-secret", encrypted_secret_b64,
      "--ak-handle", ak_handle,
    ])

    self.assertIn("decrypted_credential", activate_result)
    decrypted_credential_b64 = activate_result["decrypted_credential"]
    decrypted_bytes = base64.b64decode(decrypted_credential_b64)
    print(f"  Decrypted credential: {len(decrypted_bytes)} bytes")

    # === PHASE 4: Complete enrollment ===
    print("  Phase 4: Completing enrollment via /enroll/activate...")
    activate_response = _api_request("POST", "/api/v1/enroll/activate", json_body={
      "enrollment_session_id": session_id,
      "decrypted_credential": decrypted_credential_b64,
    })

    self.assertIn("identity", activate_response)
    self.assertIn("credentials", activate_response)

    identity = activate_response["identity"]
    credentials = activate_response["credentials"]

    self.assertIn("internal_id", identity)
    self.assertIn("handle", identity)
    self.assertIn("trust_tier", identity)
    self.assertEqual(identity["trust_tier"], trust_tier)

    self.assertIn("client_id", credentials)
    self.assertIn("client_secret", credentials)

    print(f"\n  === ENROLLMENT SUCCESSFUL ===")
    print(f"  Identity: {identity['internal_id']}")
    print(f"  Handle: {identity['handle']}")
    print(f"  Trust tier: {identity['trust_tier']}")
    print(f"  TPM manufacturer: {identity.get('tpm_manufacturer', 'N/A')}")
    print(f"  Client ID: {credentials['client_id']}")


if __name__ == "__main__":
  unittest.main(verbosity=2)
