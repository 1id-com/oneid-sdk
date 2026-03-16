#!/usr/bin/env python3
"""Full end-to-end regression test suite for 1id.com.

Runs against live server. Uses requests (available on Python 3.8+).
Tests are numbered to match 042.1_1id_improvements_plan.md.

API envelope: {"ok": bool, "data": {...}, "error": {"code": ..., "message": ...}}
"""
import json
import os
import subprocess
import sys
import warnings
import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

BASE_URL = "https://1id.com/api/v1"
TIMEOUT = 15

SOVEREIGN_AGENT_ID = "1id-tkoie2ve"

passed_tests = []
failed_tests = []
skipped_tests = []

def test(number, name):
  def decorator(func):
    def wrapper():
      try:
        result = func()
        if result == "SKIP":
          skipped_tests.append(f"Test {number}: {name}")
          print(f"  [SKIP] Test {number}: {name}")
        else:
          passed_tests.append(f"Test {number}: {name}")
          print(f"  [PASS] Test {number}: {name}")
      except Exception as e:
        failed_tests.append(f"Test {number}: {name} -- {e}")
        print(f"  [FAIL] Test {number}: {name} -- {e}")
    wrapper._test_number = number
    return wrapper
  return decorator


def unwrap_api_response(response_json):
  """Extract data from the standard API envelope."""
  if isinstance(response_json, dict) and "data" in response_json:
    return response_json["data"]
  return response_json


# === Milestone 1: World Endpoint + SDK ===

@test(1, "API reachable (trust roots as canary)")
def test_api_reachable():
  r = requests.get(f"{BASE_URL}/trust/roots", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200, f"Expected 200, got {r.status_code}"

@test(2, "Trust roots endpoint returns PEM bundle")
def test_trust_roots():
  r = requests.get(f"{BASE_URL}/trust/roots", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200, f"Expected 200, got {r.status_code}"
  assert "BEGIN CERTIFICATE" in r.text, "No PEM certificates in response"

@test(6, "Public identity lookup returns valid JSON with core fields")
def test_identity_lookup_schema():
  r = requests.get(f"{BASE_URL}/identity/{SOVEREIGN_AGENT_ID}", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200, f"Expected 200, got {r.status_code}"
  data = unwrap_api_response(r.json())
  for required_field in ["agent_id", "trust_tier", "status", "registered_at"]:
    assert required_field in data, f"Missing field: {required_field}"
  assert data["agent_id"] == SOVEREIGN_AGENT_ID


# === Milestone 3: Device Management ===

@test(22, "Downgrade guard: unauthenticated /devices/add rejected")
def test_downgrade_guard():
  r = requests.post(
    f"{BASE_URL}/identity/devices/add",
    json={"attestation_type": "none"},
    headers={"Authorization": "Bearer invalid_token"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403), f"Expected 401 or 403, got {r.status_code}"

@test(26, "Dynamic trust tier visible in public lookup")
def test_dynamic_trust_tier():
  r = requests.get(f"{BASE_URL}/identity/{SOVEREIGN_AGENT_ID}", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200
  data = unwrap_api_response(r.json())
  assert data.get("trust_tier") == "sovereign", f"Expected sovereign, got {data.get('trust_tier')}"

@test(28, "Last-device burn rejection: unauthenticated blocked")
def test_last_device_burn_rejection():
  r = requests.post(
    f"{BASE_URL}/identity/devices/burn",
    json={"device_id": "nonexistent"},
    headers={"Authorization": "Bearer invalid_token"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# === Milestone 4: Hardware Lock ===

@test(10, "Lock endpoint rejects unauthenticated")
def test_lock_unauth():
  r = requests.post(
    f"{BASE_URL}/identity/lock-hardware",
    headers={"Authorization": "Bearer invalid_token"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"

@test(11, "Hardware lock visible in public lookup")
def test_hardware_lock_visible():
  r = requests.get(f"{BASE_URL}/identity/{SOVEREIGN_AGENT_ID}", verify=False, timeout=TIMEOUT)
  data = unwrap_api_response(r.json())
  assert data.get("hardware_locked") is True, f"Expected hardware_locked=True, got {data.get('hardware_locked')}"
  assert data.get("locked_at") is not None, "Expected locked_at timestamp"

@test(14, "PIV-bind after lock rejected (unauthenticated)")
def test_lock_blocks_piv_bind():
  r = requests.post(
    f"{BASE_URL}/identity/piv-bind/begin",
    json={},
    headers={"Authorization": "Bearer invalid_token"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# === Milestone 5: Operator Email ===

@test(15, "Operator email endpoint rejects unauthenticated")
def test_operator_email_unauth():
  r = requests.put(
    f"{BASE_URL}/identity/operator-email",
    json={"email": "test@example.com"},
    headers={"Authorization": "Bearer invalid_token"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403, 422), f"Expected 401/403/422, got {r.status_code}"


# === Milestone 8: Credential Pointers ===

@test(31, "Credential pointer consent: unauthenticated rejected")
def test_credential_pointer_consent_unauth():
  r = requests.post(
    f"{BASE_URL}/identity/credential-pointer-consent",
    json={"credential_type": "test_cert", "issuer_id": "test_issuer"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403, 422), f"Expected 401/403/422, got {r.status_code}"

@test(36, "Credential pointer listing (public, for known identity)")
def test_credential_pointer_public():
  r = requests.get(
    f"{BASE_URL}/identity/{SOVEREIGN_AGENT_ID}/credential-pointers",
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code == 200, f"Expected 200, got {r.status_code}"


# === Milestone 9: Peer Identity Verification ===

@test(42, "Trust roots: multiple root certificates returned")
def test_trust_root_count():
  r = requests.get(f"{BASE_URL}/trust/roots", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200
  cert_count = r.text.count("BEGIN CERTIFICATE")
  assert cert_count >= 2, f"Expected >= 2 root certs, got {cert_count}"

@test(45, "Trust root stability (two sequential fetches match)")
def test_trust_root_stability():
  r1 = requests.get(f"{BASE_URL}/trust/roots", verify=False, timeout=TIMEOUT)
  r2 = requests.get(f"{BASE_URL}/trust/roots", verify=False, timeout=TIMEOUT)
  assert r1.text == r2.text, "Trust roots changed between sequential fetches"


# === Milestone 10: Hardware Presence Enforcement ===

@test(39, "Bare client_credentials rejected for hardware-tier identity (JSON)")
def test_bare_creds_rejected_json():
  r = requests.post(
    f"{BASE_URL}/auth/token",
    json={"grant_type": "client_credentials", "client_id": SOVEREIGN_AGENT_ID, "client_secret": "dummy_secret"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code == 403, f"Expected 403, got {r.status_code}"
  envelope = r.json()
  error_code = (envelope.get("error") or {}).get("code", "")
  assert error_code == "HARDWARE_PROOF_REQUIRED", f"Expected HARDWARE_PROOF_REQUIRED, got: {error_code}"

@test("39b", "Bare client_credentials rejected for hardware-tier identity (form-encoded)")
def test_bare_creds_rejected_form():
  r = requests.post(
    f"{BASE_URL}/auth/token",
    data={"grant_type": "client_credentials", "client_id": SOVEREIGN_AGENT_ID, "client_secret": "dummy_secret"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code == 403, f"Expected 403, got {r.status_code}"

@test(40, "Stolen credentials rejected (wrong secret)")
def test_stolen_creds():
  r = requests.post(
    f"{BASE_URL}/auth/token",
    data={"grant_type": "client_credentials", "client_id": SOVEREIGN_AGENT_ID, "client_secret": "stolen_secret_value"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (401, 403), f"Expected 401 or 403, got {r.status_code}"

@test(41, "Public identity lookup has hardware lock fields")
def test_public_lookup_extended():
  r = requests.get(f"{BASE_URL}/identity/{SOVEREIGN_AGENT_ID}", verify=False, timeout=TIMEOUT)
  assert r.status_code == 200
  data = unwrap_api_response(r.json())
  assert "hardware_locked" in data, f"Missing hardware_locked. Keys: {list(data.keys())}"
  assert "trust_tier" in data, f"Missing trust_tier. Keys: {list(data.keys())}"
  assert "locked_at" in data, f"Missing locked_at. Keys: {list(data.keys())}"
  assert data["hardware_locked"] is True
  assert data["trust_tier"] == "sovereign"

@test(49, "Go binary linux-amd64 exists")
def test_go_binary_linux():
  go_binary = os.path.expanduser("~/Downloads/cursor/1id/websites/1id.com/sdk/oneid-enroll/build/oneid-enroll-linux-amd64")
  if not os.path.exists(go_binary):
    return "SKIP"
  assert os.path.getsize(go_binary) > 1_000_000, "Binary too small (< 1MB)"


# === SDK Export Validation ===

@test(50, "Python SDK exports valid (no dead code)")
def test_sdk_exports():
  sdk_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  sys.path.insert(0, sdk_path)
  try:
    from oneid import __all__ as exports
    for required_export in ["enroll", "get_or_create_identity", "status", "get_token"]:
      assert required_export in exports, f"Missing export: {required_export}"
    assert "record_privacy_consent" not in exports, "Dead code still exported: record_privacy_consent"
  except ImportError as e:
    if "_SpecialGenericAlias" in str(e) or "_Py_IncRef" in str(e):
      return "SKIP"
    raise


# === Hardware-Specific Tests (run from correct machines) ===

@test("38-tpm", "Challenge endpoint exists and is reachable")
def test_challenge_endpoint_exists():
  r = requests.post(
    f"{BASE_URL}/auth/challenge",
    json={"client_id": SOVEREIGN_AGENT_ID},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (200, 400, 403), f"Expected 200/400/403, got {r.status_code}"

@test("38b-tpm", "Verify endpoint exists and rejects invalid proof")
def test_verify_endpoint_rejects_invalid():
  r = requests.post(
    f"{BASE_URL}/auth/verify",
    json={"client_id": SOVEREIGN_AGENT_ID, "challenge_token": "fake", "signature": "fake"},
    verify=False, timeout=TIMEOUT,
  )
  assert r.status_code in (400, 401, 403), f"Expected 400/401/403, got {r.status_code}"


if __name__ == "__main__":
  print("=" * 60)
  print("1ID.COM FULL END-TO-END REGRESSION TEST")
  print("=" * 60)
  print()

  all_tests = [v for v in globals().values() if callable(v) and hasattr(v, "_test_number")]
  all_tests.sort(key=lambda f: str(f._test_number))
  for t in all_tests:
    t()

  print()
  print("=" * 60)
  total = len(passed_tests) + len(failed_tests) + len(skipped_tests)
  print(f"RESULTS: {len(passed_tests)} passed, {len(failed_tests)} failed, {len(skipped_tests)} skipped (of {total} tests)")
  print("=" * 60)
  if failed_tests:
    print("FAILURES:")
    for f in failed_tests:
      print(f"  - {f}")
  if skipped_tests:
    print("SKIPPED:")
    for s in skipped_tests:
      print(f"  - {s}")
  print()
  sys.exit(1 if failed_tests else 0)
