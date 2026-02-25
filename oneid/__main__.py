"""
Command-line interface for the 1id.com SDK.

Usage:
    oneid whoami          -- Show enrolled identity info
    oneid token           -- Print a fresh bearer token (for scripting)
    oneid enroll          -- Enroll this machine (interactive)
    oneid status          -- Check if enrolled

Examples:
    # Enroll at declared tier
    oneid enroll --tier declared --email owner@example.com

    # Enroll at sovereign tier (requires TPM)
    oneid enroll --tier sovereign

    # Get a bearer token for scripting
    TOKEN=$(oneid token)
    curl -H "Authorization: Bearer $TOKEN" https://api.example.com/

    # Check who you are
    oneid whoami
"""

from __future__ import annotations

import argparse
import json
import sys

from . import _version


def _command_whoami(args: argparse.Namespace) -> int:
  """Show the current enrolled identity."""
  from . import whoami
  from .exceptions import NotEnrolledError

  try:
    identity = whoami()
  except NotEnrolledError as not_enrolled_error:
    print(f"Not enrolled: {not_enrolled_error}", file=sys.stderr)
    return 1

  output = {
    "internal_id": identity.internal_id,
    "handle": identity.handle,
    "display_name": identity.display_name,
    "trust_tier": identity.trust_tier.value if hasattr(identity.trust_tier, "value") else str(identity.trust_tier),
    "key_algorithm": identity.key_algorithm.value if hasattr(identity.key_algorithm, "value") else str(identity.key_algorithm),
    "enrolled_at": identity.enrolled_at.isoformat() if identity.enrolled_at else None,
  }

  if args.json:
    print(json.dumps(output, indent=2))
  else:
    print(f"Identity:   {output['internal_id']}")
    print(f"Handle:     {output['handle']}")
    if output["display_name"]:
      print(f"Name:       {output['display_name']}")
    print(f"Trust tier: {output['trust_tier']}")
    print(f"Algorithm:  {output['key_algorithm']}")
    if output["enrolled_at"]:
      print(f"Enrolled:   {output['enrolled_at']}")

  return 0


def _command_token(args: argparse.Namespace) -> int:
  """Print a fresh OAuth2 bearer token to stdout."""
  from . import get_token
  from .exceptions import AuthenticationError, NotEnrolledError

  try:
    token = get_token(force_refresh=args.refresh)
  except NotEnrolledError as not_enrolled_error:
    print(f"Not enrolled: {not_enrolled_error}", file=sys.stderr)
    return 1
  except AuthenticationError as auth_error:
    print(f"Authentication failed: {auth_error}", file=sys.stderr)
    return 1

  if args.json:
    output = {
      "access_token": token.access_token,
      "token_type": token.token_type,
      "expires_in": token.expires_in,
    }
    print(json.dumps(output, indent=2))
  else:
    # Raw token only -- suitable for $(oneid token) in shell scripts
    print(token.access_token)

  return 0


def _command_enroll(args: argparse.Namespace) -> int:
  """Enroll this machine with 1id.com."""
  from . import enroll, credentials_exist
  from .exceptions import EnrollmentError, AlreadyEnrolledError

  if credentials_exist() and not args.force:
    print(
      "Already enrolled. Use --force to re-enroll (this will replace your current identity).",
      file=sys.stderr,
    )
    return 1

  if args.force and credentials_exist():
    from .credentials import delete_credentials
    delete_credentials()

  request_tier = args.tier or "declared"

  try:
    identity = enroll(
      request_tier=request_tier,
      operator_email=args.email,
      requested_handle=args.handle,
    )
  except AlreadyEnrolledError as already_enrolled_error:
    print(f"Already enrolled: {already_enrolled_error}", file=sys.stderr)
    return 1
  except EnrollmentError as enrollment_error:
    print(f"Enrollment failed: {enrollment_error}", file=sys.stderr)
    return 1

  print(f"Enrolled successfully!")
  print(f"Identity:   {identity.internal_id}")
  print(f"Handle:     {identity.handle}")
  print(f"Trust tier: {identity.trust_tier.value if hasattr(identity.trust_tier, 'value') else identity.trust_tier}")
  
  if args.handle:
    print(f"\nNote: Vanity handle '{args.handle}' was requested.")
    print(f"Check the log output above for payment instructions.")
    print(f"Or visit: https://1id.com/handle/purchase?name={args.handle}")

  return 0


def _command_status(args: argparse.Namespace) -> int:
  """Check enrollment status."""
  from . import credentials_exist
  from .credentials import get_credentials_file_path

  credentials_file_path = get_credentials_file_path()

  if credentials_exist():
    print(f"Enrolled: yes")
    print(f"Credentials: {credentials_file_path}")
    # Try to show identity info too
    try:
      from . import whoami
      identity = whoami()
      print(f"Identity: {identity.internal_id}")
      print(f"Tier: {identity.trust_tier.value if hasattr(identity.trust_tier, 'value') else identity.trust_tier}")
    except Exception:
      print("Identity: (unable to read)")
    return 0
  else:
    print(f"Enrolled: no")
    print(f"Expected credentials at: {credentials_file_path}")
    return 1


def build_argument_parser() -> argparse.ArgumentParser:
  """Build the CLI argument parser."""
  parser = argparse.ArgumentParser(
    prog="oneid",
    description="1id.com -- Hardware-anchored identity for AI agents",
  )
  parser.add_argument(
    "--version",
    action="version",
    version=f"oneid {_version.__version__}",
  )

  subparsers = parser.add_subparsers(dest="command", help="Available commands")

  # -- whoami --
  whoami_parser = subparsers.add_parser("whoami", help="Show enrolled identity info")
  whoami_parser.add_argument("--json", action="store_true", help="Output as JSON")

  # -- token --
  token_parser = subparsers.add_parser("token", help="Print a fresh bearer token")
  token_parser.add_argument("--json", action="store_true", help="Output as JSON (includes expiry)")
  token_parser.add_argument("--refresh", action="store_true", help="Force token refresh")

  # -- enroll --
  enroll_parser = subparsers.add_parser("enroll", help="Enroll this machine with 1id.com")
  enroll_parser.add_argument("--tier", type=str, default="declared", help="Trust tier: sovereign, declared, etc. (default: declared)")
  enroll_parser.add_argument("--email", type=str, default=None, help="Operator email for handle purchases")
  enroll_parser.add_argument("--handle", type=str, default=None, help="Requested vanity handle")
  enroll_parser.add_argument("--force", action="store_true", help="Re-enroll even if already enrolled (replaces current identity)")

  # -- status --
  subparsers.add_parser("status", help="Check enrollment status")

  return parser


def main() -> int:
  """CLI entry point."""
  parser = build_argument_parser()
  args = parser.parse_args()

  if args.command is None:
    parser.print_help()
    return 0

  command_dispatch = {
    "whoami": _command_whoami,
    "token": _command_token,
    "enroll": _command_enroll,
    "status": _command_status,
  }

  handler = command_dispatch.get(args.command)
  if handler is None:
    parser.print_help()
    return 1

  return handler(args)


if __name__ == "__main__":
  sys.exit(main())
