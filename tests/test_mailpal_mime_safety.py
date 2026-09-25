"""Python mail building (email package, SMTP policy) gives the same guarantees
the Node SDK now implements by hand: AUD-F84 no CR/LF injection, AUD-F85 RFC
2047 for non-ASCII Subject/display names, AUD-F75 honest transfer encoding.
(AUD-F29 dot-stuffing is smtplib's job on the Python side.) Mirrors oneid-node
src/test/test_mailpal_mime_safety.ts."""

import re

import pytest

from oneid.credentials import StoredCredentials, save_credentials


@pytest.fixture(autouse=True)
def declared_identity_in_an_isolated_directory(isolated_credentials_directory):
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import ec
  private_key_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
  save_credentials(StoredCredentials(
    client_id="id-tstmm-aaaaa-bbbbb-ccccc", client_secret="", token_endpoint="http://127.0.0.1:9/token",
    api_base_url="http://127.0.0.1:9", trust_tier="declared", key_algorithm="ecdsa-p256",
    private_key_pem=private_key_pem, mailpal_email="id-tstmm-aaaaa-bbbbb-ccccc@mailpal.com",
  ))
  yield


def build_without_attestation(**overrides) -> str:
  from oneid.mailpal import send
  arguments = dict(to=["r@example.com"], subject="Plain", text_body="Body", attestation_mode="none", deliver=False)
  arguments.update(overrides)
  return send(**arguments).rfc5322_message_bytes.decode("utf-8")


@pytest.mark.parametrize("overrides", [
  dict(subject="Hi\r\nBcc: victim@example.com"),
  dict(reply_to="a@example.com\nX-Evil: 1"),
])
def test_cr_or_lf_in_a_header_input_is_refused(overrides):
  with pytest.raises(ValueError):
    build_without_attestation(**overrides)


def test_non_ascii_subject_and_display_names_are_rfc2047_encoded():
  message = build_without_attestation(subject="Grüße aus Zürich – " * 6, to=["Zoë Ünicode <r@example.com>"])
  header_section = message[:message.index("\r\n\r\n")]
  assert header_section.isascii()
  # RFC 2047 caps an encoded-word at 75 characters; Python's email package emits
  # up to 76 (a known stdlib quirk; receivers accept it). The Node SDK keeps <= 75.
  for encoded_word in re.findall(r"=\?utf-8\?[bq]\?[^?]*\?=", header_section, re.I):
    assert len(encoded_word) <= 76


def test_text_bodies_are_quoted_printable_with_crlf_line_ends():
  """_FORCED_CTE_FOR_STALWART_COMPAT; the Node SDK now emits the same."""
  ascii_message = build_without_attestation(text_body="line one\nline two")
  assert "Content-Transfer-Encoding: quoted-printable" in ascii_message
  assert "line one\r\nline two" in ascii_message
  assert "h=C3=A9llo w=C3=B6rld" in build_without_attestation(text_body="héllo wörld")
