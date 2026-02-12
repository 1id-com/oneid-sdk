"""
Exception hierarchy for the 1id.com SDK.

All exceptions inherit from OneIDError. Enrollment-specific exceptions
inherit from EnrollmentError. The hierarchy is designed so callers can
catch at any level of specificity:

    try:
        oneid.enroll(request_tier="sovereign")
    except oneid.NoHSMError:
        # Specific: no TPM/YubiKey found
    except oneid.EnrollmentError:
        # Broader: any enrollment failure
    except oneid.OneIDError:
        # Broadest: any 1id SDK error

CRITICAL DESIGN RULE: request_tier is a REQUIREMENT, not a preference.
These exceptions are raised when the requested tier CANNOT be satisfied.
The SDK NEVER silently falls back to a lower tier.
"""


class OneIDError(Exception):
  """Base exception for all 1id.com SDK errors.

  All SDK-specific exceptions inherit from this class, so callers
  can catch all 1id errors with a single except clause if desired.

  Attributes:
      message: Human-readable error description.
      error_code: Machine-readable error code string (e.g., 'NO_HSM_FOUND').
                  May be None for generic errors.
  """

  def __init__(self, message: str = "An error occurred in the 1id SDK", error_code: str | None = None) -> None:
    super().__init__(message)
    self.message = message
    self.error_code = error_code


class EnrollmentError(OneIDError):
  """Base exception for all enrollment failures.

  Raised when the enrollment process fails for any reason.
  More specific subclasses indicate the exact cause.
  """

  pass


class NoHSMError(EnrollmentError):
  """Requested trust tier requires an HSM but none was found.

  This is raised when the caller requests a tier like 'sovereign' or
  'sovereign-portable' but the machine has no TPM, YubiKey, or other
  supported hardware security module.

  The caller's code should decide what to do: try a different tier,
  ask a human, or crash. The SDK will NEVER silently fall back.
  """

  def __init__(self, message: str = "No hardware security module found") -> None:
    super().__init__(message, error_code="NO_HSM_FOUND")


class UACDeniedError(EnrollmentError):
  """User denied the elevation prompt (clicked No on UAC/sudo/pkexec).

  HSM operations require administrator/root privileges. This exception
  is raised when the user explicitly denies the elevation request.
  """

  def __init__(self, message: str = "User denied elevation prompt") -> None:
    super().__init__(message, error_code="UAC_DENIED")


class HSMAccessError(EnrollmentError):
  """HSM was found but could not be accessed.

  This can happen when:
  - The TPM is locked or in an error state
  - The YubiKey is plugged in but PIN-locked
  - Another process holds exclusive access to the HSM
  - The HSM driver is malfunctioning
  """

  def __init__(self, message: str = "HSM found but access failed") -> None:
    super().__init__(message, error_code="HSM_ACCESS_ERROR")


class AlreadyEnrolledError(EnrollmentError):
  """This HSM is already enrolled with a different identity.

  The EK fingerprint (TPM) or attestation fingerprint (YubiKey) is
  already registered in the 1id.com EK Registry. One HSM can only
  be bound to one identity. This is the anti-Sybil mechanism.
  """

  def __init__(self, message: str = "This HSM is already enrolled with a different identity") -> None:
    super().__init__(message, error_code="EK_ALREADY_REGISTERED")


class HandleTakenError(EnrollmentError):
  """Requested vanity handle is already in use by another identity.

  Handles are unique. If the desired handle is taken, the caller
  should pick a different handle or enroll without one.
  """

  def __init__(self, message: str = "Requested handle is already in use") -> None:
    super().__init__(message, error_code="HANDLE_TAKEN")


class HandleInvalidError(EnrollmentError):
  """Requested handle violates naming rules.

  Handle rules:
  - Alphanumeric characters and hyphens only
  - Cannot start or end with a hyphen
  - Minimum 1 character, maximum 64 characters
  - Case-insensitive (stored lowercase)
  """

  def __init__(self, message: str = "Requested handle violates naming rules") -> None:
    super().__init__(message, error_code="HANDLE_INVALID")


class HandleRetiredError(EnrollmentError):
  """Requested handle was previously used and is permanently retired.

  Retired handles can NEVER be reused by anyone. This is by design:
  once a handle is cancelled or its grace period expires, it goes
  to the void forever to prevent impersonation.
  """

  def __init__(self, message: str = "Handle was previously used and is permanently retired") -> None:
    super().__init__(message, error_code="HANDLE_RETIRED")


class AuthenticationError(OneIDError):
  """Token acquisition or refresh failed.

  Raised when the OAuth2 client_credentials grant fails, the
  refresh token is invalid, or the token endpoint is unreachable.
  """

  def __init__(self, message: str = "Authentication failed") -> None:
    super().__init__(message, error_code="AUTH_FAILED")


class NetworkError(OneIDError):
  """Could not reach the 1id.com API server.

  Raised when HTTP requests to 1id.com fail due to DNS resolution
  failure, connection timeout, TLS errors, or other network issues.
  """

  def __init__(self, message: str = "Could not reach 1id.com") -> None:
    super().__init__(message, error_code="NETWORK_ERROR")


class NotEnrolledError(OneIDError):
  """No enrollment credentials found on this machine.

  Raised when get_token() or whoami() is called but no credentials
  file exists. The agent must enroll first.
  """

  def __init__(self, message: str = "Not enrolled -- call oneid.enroll() first") -> None:
    super().__init__(message, error_code="NOT_ENROLLED")


class BinaryNotFoundError(OneIDError):
  """The oneid-enroll Go binary could not be found or downloaded.

  This is raised when a tier requiring HSM operations is requested
  but the Go helper binary is not available and cannot be downloaded.
  """

  def __init__(self, message: str = "oneid-enroll binary not found and could not be downloaded") -> None:
    super().__init__(message, error_code="BINARY_NOT_FOUND")


class RateLimitExceededError(EnrollmentError):
  """Too many enrollment attempts from this IP address.

  The server rate-limits declared-tier enrollment to prevent Sybil attacks.
  Default limits: 1 per hour, 10 per day per IP address.
  The caller should wait before retrying.
  """

  def __init__(self, message: str = "Rate limit exceeded -- too many enrollment attempts") -> None:
    super().__init__(message, error_code="RATE_LIMIT_EXCEEDED")


# -- Mapping from server API error codes to exception classes --

SERVER_ERROR_CODE_TO_EXCEPTION_CLASS: dict[str, type[OneIDError]] = {
  "EK_ALREADY_REGISTERED": AlreadyEnrolledError,
  "EK_CERT_INVALID": EnrollmentError,
  "EK_CERT_CHAIN_UNTRUSTED": EnrollmentError,
  "HANDLE_TAKEN": HandleTakenError,
  "HANDLE_INVALID": HandleInvalidError,
  "HANDLE_RETIRED": HandleRetiredError,
  "RATE_LIMIT_EXCEEDED": RateLimitExceededError,
  "RATE_LIMITED": RateLimitExceededError,
}


def raise_from_server_error_response(error_code: str, error_message: str) -> None:
  """Raise the appropriate exception for a server error response.

  Maps the server's error.code field to the correct SDK exception class.
  Falls back to EnrollmentError for unrecognized error codes.

  Args:
      error_code: The error.code string from the server JSON response.
      error_message: The error.message string from the server JSON response.

  Raises:
      OneIDError: The appropriate subclass based on error_code.
  """
  exception_class = SERVER_ERROR_CODE_TO_EXCEPTION_CLASS.get(error_code, EnrollmentError)
  raise exception_class(error_message)
