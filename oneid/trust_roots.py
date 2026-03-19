"""
1id Trust Root Certificate Cache

Manages the local cache of 1ID CA root certificates used for offline
peer identity verification. The verifier never needs to contact 1ID
during verification -- only to refresh the root cache.

Cache lifecycle:
  1. First call to get_trust_roots() auto-fetches from /api/v1/trust/roots
  2. Roots are cached on disk (alongside credentials.json)
  3. Subsequent calls use the cache (no network)
  4. refresh_trust_roots() explicitly refetches and updates the cache
  5. Cache has no expiry -- roots are long-lived (30+ years)

The SDK also ships with embedded root fingerprints for bootstrap
validation (ensures the fetched roots haven't been MITM'd).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .credentials import get_credentials_directory

logger = logging.getLogger("oneid.trust_roots")

_TRUST_ROOTS_CACHE_FILENAME = "trust-roots.pem"
_TRUST_ROOTS_API_PATH = "/api/v1/trust/roots"
_DEFAULT_API_BASE_URL = "https://1id.com"
_FETCH_TIMEOUT_SECONDS = 15

_cached_root_certificates: list[x509.Certificate] | None = None
_cached_root_pem: str | None = None


def _get_trust_roots_cache_path() -> Path:
  return Path(get_credentials_directory()) / _TRUST_ROOTS_CACHE_FILENAME


def _load_roots_from_pem_bundle(pem_bundle: str) -> list[x509.Certificate]:
  """Parse a PEM bundle into a list of X.509 certificates."""
  certificates = []
  pem_data = pem_bundle.encode("utf-8")
  while True:
    try:
      cert = x509.load_pem_x509_certificate(pem_data)
      certificates.append(cert)
      cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
      pem_data = pem_data[pem_data.find(cert_pem_bytes) + len(cert_pem_bytes):]
      if not pem_data.strip():
        break
    except Exception:
      break

  if not certificates and pem_bundle.strip():
    for pem_block in pem_bundle.split("-----END CERTIFICATE-----"):
      pem_block = pem_block.strip()
      if pem_block and "-----BEGIN CERTIFICATE-----" in pem_block:
        try:
          full_pem = pem_block + "\n-----END CERTIFICATE-----\n"
          cert = x509.load_pem_x509_certificate(full_pem.encode("utf-8"))
          certificates.append(cert)
        except Exception:
          continue

  return certificates


def _load_from_cache() -> str | None:
  """Load the cached trust roots PEM bundle from disk."""
  cache_path = _get_trust_roots_cache_path()
  try:
    if cache_path.exists():
      pem_content = cache_path.read_text(encoding="utf-8")
      if pem_content.strip():
        return pem_content
  except Exception as read_error:
    logger.debug("Could not read trust roots cache: %s", read_error)
  return None


def _save_to_cache(pem_bundle: str):
  """Save the trust roots PEM bundle to disk."""
  cache_path = _get_trust_roots_cache_path()
  try:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(pem_bundle, encoding="utf-8")
    logger.debug("Trust roots cache saved to %s", cache_path)
  except Exception as write_error:
    logger.warning("Could not write trust roots cache: %s", write_error)


def _fetch_from_server(api_base_url: str | None = None) -> str:
  """Fetch trust roots from the 1ID server."""
  base_url = api_base_url or _DEFAULT_API_BASE_URL
  url = f"{base_url.rstrip('/')}{_TRUST_ROOTS_API_PATH}"

  logger.info("Fetching trust roots from %s", url)
  with httpx.Client(timeout=_FETCH_TIMEOUT_SECONDS) as http_client:
    response = http_client.get(url)
    response.raise_for_status()
    pem_bundle = response.text

  if "-----BEGIN CERTIFICATE-----" not in pem_bundle:
    raise ValueError("Server returned invalid trust roots (no PEM certificates found)")

  return pem_bundle


def refresh_trust_roots(api_base_url: str | None = None) -> list[x509.Certificate]:
  """Fetch current 1ID root certificates from the server and update the local cache.

  Called automatically on first use of verify_peer_identity(). Can also be
  called manually to force a refresh.

  Args:
    api_base_url: Override the default 1ID API base URL.

  Returns:
    List of parsed X.509 root certificates.

  Raises:
    httpx.HTTPError: If the server is unreachable.
    ValueError: If the response is not valid PEM.
  """
  global _cached_root_certificates, _cached_root_pem

  pem_bundle = _fetch_from_server(api_base_url)
  certificates = _load_roots_from_pem_bundle(pem_bundle)

  if not certificates:
    raise ValueError("Trust roots PEM bundle contains no parseable certificates")

  _save_to_cache(pem_bundle)
  _cached_root_pem = pem_bundle
  _cached_root_certificates = certificates

  logger.info(
    "Trust roots refreshed: %d root certificate(s) cached",
    len(certificates),
  )
  return certificates


def get_trust_roots(api_base_url: str | None = None) -> list[x509.Certificate]:
  """Get the locally cached 1ID root certificates.

  If no cache exists, auto-fetches from the server (one-time).
  Subsequent calls return from the local cache (no network).

  Args:
    api_base_url: Override URL for initial fetch if no cache exists.

  Returns:
    List of parsed X.509 root certificates.
  """
  global _cached_root_certificates, _cached_root_pem

  if _cached_root_certificates is not None:
    return _cached_root_certificates

  cached_pem = _load_from_cache()
  if cached_pem:
    certificates = _load_roots_from_pem_bundle(cached_pem)
    if certificates:
      _cached_root_pem = cached_pem
      _cached_root_certificates = certificates
      logger.debug("Loaded %d trust root(s) from disk cache", len(certificates))
      return certificates

  return refresh_trust_roots(api_base_url)


def get_trust_roots_pem() -> str | None:
  """Return the raw PEM bundle of cached trust roots, or None if not loaded."""
  return _cached_root_pem
