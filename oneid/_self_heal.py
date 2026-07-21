"""
Best-effort runtime dependency self-heal.

Philosophy (operator's, 2026-07-21): let a user `pip install oneid` and
then have the SDK pull the RIGHT packages itself, rather than block the
install or force a manual upgrade. The dependency floors in
pyproject.toml already make a FRESH `pip install` resolve good versions;
this module additionally repairs an ALREADY-installed environment whose
transitive deps are too old (the common case when `oneid` was upgraded
in place but a pinned/cached transitive dep like httpcore was left
behind).

Currently repairs: httpcore. httpx pulls httpcore transitively and
httpcore < 1.0.9 has a bug that breaks our HTTPS calls (observed on
1.0.7). We check the INSTALLED version via importlib.metadata WITHOUT
importing httpcore, so the upgrade (and a subsequent fresh import) can
happen in the same process, before httpx is first used.

Safety contract:
  * runs at most once per process;
  * NEVER raises -- any failure is logged and swallowed, so import always
    succeeds even offline / in a locked or system-managed environment;
  * scoped to specific known-bad transitive deps only (no arbitrary
    upgrades);
  * opt out with ONEID_NO_SELF_HEAL=1 (or =true).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger("oneid.self_heal")

# (distribution name, minimum-good version) pairs to repair in place.
_REQUIRED_MINIMUMS = [
  ("httpcore", (1, 0, 9)),
]

_already_ran = False


def _parse_version(text):
  """Parse 'X.Y.Z...' into a tuple of leading integer components. Any
  non-numeric suffix (rc/post/dev) stops the parse -- good enough for a
  >= floor comparison and dependency-free (no `packaging`)."""
  parts = []
  for token in text.split("."):
    number = ""
    for ch in token:
      if ch.isdigit():
        number += ch
      else:
        break
    if number == "":
      break
    parts.append(int(number))
  return tuple(parts)


def _installed_version(distribution_name):
  try:
    from importlib.metadata import version, PackageNotFoundError
  except ImportError:  # pragma: no cover  (Python < 3.8)
    return None
  try:
    return version(distribution_name)
  except PackageNotFoundError:
    return None
  except Exception:
    return None


def _pip_upgrade(spec):
  """Best-effort `pip install --upgrade <spec>` in THIS interpreter.
  Returns True on success. Never raises."""
  try:
    result = subprocess.run(
      [sys.executable, "-m", "pip", "install", "--upgrade", spec],
      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180,
    )
    if result.returncode == 0:
      return True
    logger.warning("oneid self-heal: `pip install --upgrade %s` exited %d:\n%s",
                   spec, result.returncode,
                   (result.stdout or b"").decode("utf-8", "replace")[-600:])
    return False
  except Exception as pip_error:  # network down, no pip, sandbox, ...
    logger.warning("oneid self-heal: could not run pip to upgrade %s: %s",
                   spec, pip_error)
    return False


def ensure_healthy_dependencies():
  """Check each known-bad transitive dep and repair in place if too old.
  Call this BEFORE importing httpx/httpcore so a fresh import picks up
  the upgraded module within the same process."""
  global _already_ran
  if _already_ran:
    return
  _already_ran = True

  if os.environ.get("ONEID_NO_SELF_HEAL", "").lower() in ("1", "true", "yes"):
    return

  for distribution_name, minimum in _REQUIRED_MINIMUMS:
    current = _installed_version(distribution_name)
    if current is None:
      # not installed yet; the pyproject floor will bring it in when
      # httpx is resolved. Nothing to repair.
      continue
    if _parse_version(current) >= minimum:
      continue

    floor = ".".join(str(n) for n in minimum)
    logger.warning(
      "oneid: %s %s is older than the required %s (known to break HTTPS "
      "calls); attempting an automatic in-place upgrade. Set "
      "ONEID_NO_SELF_HEAL=1 to disable.", distribution_name, current, floor)
    upgraded = _pip_upgrade("%s>=%s" % (distribution_name, floor))
    if not upgraded:
      logger.warning(
        "oneid: automatic upgrade of %s failed. Please run manually:\n"
        "    %s -m pip install --upgrade \"%s>=%s\"",
        distribution_name, sys.executable, distribution_name, floor)
    else:
      # If the module was already imported elsewhere, the running process
      # keeps the old copy; warn so the caller can restart if needed.
      if distribution_name in sys.modules:
        logger.warning(
          "oneid: upgraded %s to >=%s, but it was already imported; "
          "restart the process to load the fixed version.",
          distribution_name, floor)
