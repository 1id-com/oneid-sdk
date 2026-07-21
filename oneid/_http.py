"""
Tiny synchronous HTTP client over the Python standard library.

This is a drop-in replacement for the small slice of `httpx` the SDK
uses, so the SDK depends only on the stdlib (+ cryptography) for HTTP --
the same `urllib` stack `hw-attest-verify` already uses. That removes
the httpx -> httpcore -> (h11, anyio, sniffio, certifi, idna) dependency
subtree entirely (and with it the transitive-version breakage that
motivated this change).

It intentionally mirrors ONLY the httpx surface the SDK touches, with
matching semantics:

  Client(timeout=<seconds>)            context manager
    .get(url, params=?, headers=?)
    .post(url, json=? | data=?, headers=?, params=?)
    .request(method=, url=, json=?, data=?, headers=?, params=?)
  Response
    .status_code, .text, .content, .json(), .raise_for_status()
  exceptions: HTTPError (base), TransportError, ConnectError,
              TimeoutException, HTTPStatusError(.response)

KEY SEMANTIC MATCH: like httpx and UNLIKE raw urllib, a 4xx/5xx response
is RETURNED as a normal Response (callers inspect .status_code / read
the error body); only transport failures raise. `.raise_for_status()`
is the explicit opt-in to raise on 4xx/5xx.

Uses the stdlib default opener, so HTTP(S)_PROXY / NO_PROXY env vars are
honoured (same as httpx) and TLS is verified against the system trust
store (same as hw-attest-verify).
"""

from __future__ import annotations

import json as _json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

_DEFAULT_TIMEOUT_SECONDS = 30.0
USER_AGENT_FALLBACK = "oneid-sdk-python"


class HTTPError(Exception):
  """Base for every error raised by this client (mirrors httpx.HTTPError)."""


class TransportError(HTTPError):
  """A connection/transport-level failure (mirrors httpx.TransportError)."""


class ConnectError(TransportError):
  """Could not establish a connection (mirrors httpx.ConnectError)."""


class TimeoutException(TransportError):
  """The request timed out (mirrors httpx.TimeoutException)."""


class HTTPStatusError(HTTPError):
  """Raised by Response.raise_for_status() on a 4xx/5xx response.

  Carries `.response` so callers can read `.response.status_code` and
  `.response.text` (mirrors httpx.HTTPStatusError)."""

  def __init__(self, message: str, *, response: "Response") -> None:
    super().__init__(message)
    self.response = response


class Response:
  """A minimal httpx.Response look-alike."""

  def __init__(self, status_code: int, content: bytes, url: str,
               headers: Optional[Dict[str, str]] = None) -> None:
    self.status_code = status_code
    self.content = content
    self.url = url
    self.headers = headers or {}

  @property
  def text(self) -> str:
    charset = "utf-8"
    ctype = self.headers.get("content-type", "") if self.headers else ""
    if "charset=" in ctype:
      charset = ctype.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
    return self.content.decode(charset, errors="replace")

  def json(self) -> Any:
    return _json.loads(self.content.decode("utf-8"))

  def raise_for_status(self) -> "Response":
    if 400 <= self.status_code:
      raise HTTPStatusError(
        "HTTP %d for %s" % (self.status_code, self.url), response=self)
    return self


def _build_url(url: str, params: Optional[Dict[str, Any]]) -> str:
  if not params:
    return url
  query = urllib.parse.urlencode(
    {k: v for k, v in params.items() if v is not None}, doseq=True)
  if not query:
    return url
  sep = "&" if ("?" in url) else "?"
  return url + sep + query


def _lower_header_keys(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
  return {k.lower(): v for k, v in (headers or {}).items()}


class Client:
  """Synchronous request client. Opens a connection per request (the SDK
  makes a handful of one-shot calls, so pooling is irrelevant)."""

  def __init__(self, timeout: Optional[float] = None) -> None:
    self.timeout = _DEFAULT_TIMEOUT_SECONDS if timeout is None else float(timeout)

  def __enter__(self) -> "Client":
    return self

  def __exit__(self, *exc_info) -> bool:
    return False

  def request(
    self,
    method: str,
    url: str,
    *,
    json: Any = None,
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
  ) -> Response:
    if json is not None and data is not None:
      raise ValueError("pass json= or data=, not both")

    final_url = _build_url(url, params)
    header_map = dict(headers or {})
    lowered = _lower_header_keys(headers)
    if "user-agent" not in lowered:
      header_map["User-Agent"] = USER_AGENT_FALLBACK

    body_bytes: Optional[bytes] = None
    if json is not None:
      body_bytes = _json.dumps(json).encode("utf-8")
      if "content-type" not in lowered:
        header_map["Content-Type"] = "application/json"
    elif data is not None:
      body_bytes = urllib.parse.urlencode(data).encode("utf-8")
      if "content-type" not in lowered:
        header_map["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(
      final_url, data=body_bytes, headers=header_map, method=method.upper())

    try:
      with urllib.request.urlopen(request, timeout=self.timeout) as raw:
        return Response(
          status_code=getattr(raw, "status", raw.getcode()),
          content=raw.read(),
          url=final_url,
          headers={k.lower(): v for k, v in raw.headers.items()},
        )
    except urllib.error.HTTPError as http_error:
      # A 4xx/5xx IS a response in httpx-land -- return it, do not raise.
      try:
        error_body = http_error.read()
      except Exception:
        error_body = b""
      return Response(
        status_code=http_error.code,
        content=error_body or b"",
        url=final_url,
        headers={k.lower(): v for k, v in (http_error.headers or {}).items()},
      )
    except socket.timeout as timeout_error:
      raise TimeoutException(
        "request to %s timed out after %ss" % (final_url, self.timeout)
      ) from timeout_error
    except urllib.error.URLError as url_error:
      reason = getattr(url_error, "reason", url_error)
      if isinstance(reason, (socket.timeout, TimeoutError)):
        raise TimeoutException(
          "request to %s timed out after %ss" % (final_url, self.timeout)
        ) from url_error
      raise ConnectError(
        "could not connect to %s: %s" % (final_url, reason)) from url_error
    except (TimeoutError, ssl.SSLError) as other_error:
      # TimeoutError can surface directly on some Python versions.
      if isinstance(other_error, TimeoutError):
        raise TimeoutException(
          "request to %s timed out after %ss" % (final_url, self.timeout)
        ) from other_error
      raise ConnectError(
        "TLS error connecting to %s: %s" % (final_url, other_error)
      ) from other_error
    except OSError as os_error:
      raise ConnectError(
        "could not connect to %s: %s" % (final_url, os_error)) from os_error

  def get(self, url: str, *, params: Optional[Dict[str, Any]] = None,
          headers: Optional[Dict[str, str]] = None) -> Response:
    return self.request("GET", url, params=params, headers=headers)

  def post(self, url: str, *, json: Any = None,
           data: Optional[Dict[str, Any]] = None,
           params: Optional[Dict[str, Any]] = None,
           headers: Optional[Dict[str, str]] = None) -> Response:
    return self.request("POST", url, json=json, data=data,
                        params=params, headers=headers)
