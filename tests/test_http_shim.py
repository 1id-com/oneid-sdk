"""
Tests for oneid/_http.py -- the stdlib-backed replacement for httpx.

These run against a REAL local HTTP server (stdlib http.server) so the
full urllib request path is exercised, not mocks. The critical semantics
under test are the ones the SDK relies on from httpx:

  1. 4xx/5xx responses are RETURNED (callers read .status_code and the
     error body) -- they must NOT raise.
  2. raise_for_status() raises HTTPStatusError carrying .response.
  3. json= sends application/json; data= sends form-urlencoded.
  4. params= are appended to the query string.
  5. Connection failures raise ConnectError; timeouts raise
     TimeoutException; both are subclasses of HTTPError so a bare
     `except httpx.HTTPError` catch-all still works.
"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from oneid import _http


class _RecordingRequestHandler(BaseHTTPRequestHandler):
  """Echoes request details back as JSON; special paths force errors."""

  def _read_body(self) -> bytes:
    length = int(self.headers.get("Content-Length", "0"))
    return self.rfile.read(length) if length else b""

  def _respond(self, status: int, body: bytes, content_type: str = "application/json") -> None:
    self.send_response(status)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def _echo(self) -> None:
    body = self._read_body()
    echo = {
      "method": self.command,
      "path": self.path,
      "content_type": self.headers.get("Content-Type", ""),
      "user_agent": self.headers.get("User-Agent", ""),
      "x_custom": self.headers.get("X-Custom", ""),
      "body": body.decode("utf-8", errors="replace"),
    }
    self._respond(200, json.dumps(echo).encode("utf-8"))

  def do_GET(self) -> None:
    if self.path.startswith("/error/"):
      status = int(self.path.split("/")[2])
      self._respond(status, json.dumps({"error": {"message": "boom"}}).encode("utf-8"))
    elif self.path.startswith("/slow"):
      time.sleep(5)
      self._respond(200, b"{}")
    elif self.path.startswith("/text"):
      self._respond(200, "h\u00e9llo".encode("utf-8"), content_type="text/plain; charset=utf-8")
    else:
      self._echo()

  def do_POST(self) -> None:
    if self.path.startswith("/error/"):
      status = int(self.path.split("/")[2])
      self._respond(status, json.dumps({"error": {"message": "boom"}}).encode("utf-8"))
    else:
      self._echo()

  def log_message(self, *args) -> None:  # silence test output
    pass


@pytest.fixture(scope="module")
def local_echo_server_base_url():
  server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingRequestHandler)
  server_thread = threading.Thread(target=server.serve_forever, daemon=True)
  server_thread.start()
  yield f"http://127.0.0.1:{server.server_port}"
  server.shutdown()


class TestBasicRequests:
  def test_get_returns_200_response(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.get(f"{local_echo_server_base_url}/hello")
    assert response.status_code == 200
    assert response.json()["method"] == "GET"
    assert response.json()["path"] == "/hello"

  def test_get_appends_params_to_query_string(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.get(
        f"{local_echo_server_base_url}/inbox",
        params={"limit": 20, "offset": 0, "unread_only": "true"},
      )
    path = response.json()["path"]
    assert path.startswith("/inbox?")
    assert "limit=20" in path and "offset=0" in path and "unread_only=true" in path

  def test_post_json_sends_json_content_type_and_body(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.post(
        f"{local_echo_server_base_url}/api",
        json={"a": 1, "b": "two"},
        headers={"X-Custom": "yes"},
      )
    echo = response.json()
    assert echo["method"] == "POST"
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == {"a": 1, "b": "two"}
    assert echo["x_custom"] == "yes"

  def test_post_data_sends_form_urlencoded(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.post(
        f"{local_echo_server_base_url}/token",
        data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "s"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
      )
    echo = response.json()
    assert echo["content_type"] == "application/x-www-form-urlencoded"
    assert "grant_type=client_credentials" in echo["body"]
    assert "client_id=x" in echo["body"]

  def test_generic_request_method_kwarg_call_style(self, local_echo_server_base_url):
    # client.py calls .request(method=..., url=..., json=..., headers=...)
    with _http.Client(timeout=5.0) as client:
      response = client.request(
        method="POST",
        url=f"{local_echo_server_base_url}/api/v1/enroll/declared",
        json={"key_algorithm": "ed25519"},
        headers={"User-Agent": "test-agent"},
      )
    assert response.status_code == 200
    assert response.json()["user_agent"] == "test-agent"

  def test_text_property_decodes_charset(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.get(f"{local_echo_server_base_url}/text")
    assert response.text == "h\u00e9llo"
    assert isinstance(response.content, bytes)

  def test_json_and_data_together_rejected(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      with pytest.raises(ValueError):
        client.post(f"{local_echo_server_base_url}/x", json={"a": 1}, data={"b": "2"})


class TestErrorStatusSemantics:
  """The load-bearing httpx behavior: 4xx/5xx is a Response, not a raise."""

  @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 500, 503])
  def test_error_status_is_returned_not_raised(self, local_echo_server_base_url, status):
    with _http.Client(timeout=5.0) as client:
      response = client.post(f"{local_echo_server_base_url}/error/{status}", json={})
    assert response.status_code == status
    # the error body must be readable, exactly like httpx
    assert response.json()["error"]["message"] == "boom"
    assert "boom" in response.text

  def test_raise_for_status_raises_with_response_attached(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.get(f"{local_echo_server_base_url}/error/503")
    with pytest.raises(_http.HTTPStatusError) as raised:
      response.raise_for_status()
    assert raised.value.response.status_code == 503
    assert "boom" in raised.value.response.text

  def test_raise_for_status_passes_on_2xx(self, local_echo_server_base_url):
    with _http.Client(timeout=5.0) as client:
      response = client.get(f"{local_echo_server_base_url}/ok")
    assert response.raise_for_status() is response


class TestTransportErrors:
  def test_connection_refused_raises_connect_error(self):
    # grab a port that is definitely closed
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    with _http.Client(timeout=2.0) as client:
      with pytest.raises(_http.ConnectError):
        client.get(f"http://127.0.0.1:{closed_port}/")

  def test_timeout_raises_timeout_exception(self, local_echo_server_base_url):
    with _http.Client(timeout=0.5) as client:
      with pytest.raises(_http.TimeoutException):
        client.get(f"{local_echo_server_base_url}/slow")

  def test_transport_errors_are_httperror_subclasses(self):
    # auth.py/client.py rely on `except httpx.HTTPError` as a catch-all
    assert issubclass(_http.ConnectError, _http.HTTPError)
    assert issubclass(_http.TimeoutException, _http.HTTPError)
    assert issubclass(_http.HTTPStatusError, _http.HTTPError)

  def test_unresolvable_host_raises_connect_error(self):
    with _http.Client(timeout=3.0) as client:
      with pytest.raises(_http.ConnectError):
        client.get("http://nonexistent.invalid./")
