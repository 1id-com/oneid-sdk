"""
Tests for the 1id.com SDK exception hierarchy.

Verifies:
- All exceptions inherit correctly
- Error codes are set correctly
- Exception messages are meaningful
- Server error code mapping works
- Exceptions can be caught at any level of specificity
"""

import pytest

import oneid
from oneid.exceptions import (
  AlreadyEnrolledError,
  AuthenticationError,
  BinaryNotFoundError,
  EnrollmentError,
  HandleInvalidError,
  HandleRetiredError,
  HandleTakenError,
  HSMAccessError,
  NetworkError,
  NoHSMError,
  NotEnrolledError,
  OneIDError,
  UACDeniedError,
  raise_from_server_error_response,
)


class TestExceptionHierarchy:
  """Verify the exception inheritance chain."""

  def test_all_exceptions_inherit_from_oneid_error(self):
    """Every SDK exception must be catchable as OneIDError."""
    all_exception_classes = [
      EnrollmentError, NoHSMError, UACDeniedError, HSMAccessError,
      AlreadyEnrolledError, HandleTakenError, HandleInvalidError,
      HandleRetiredError, AuthenticationError, NetworkError,
      NotEnrolledError, BinaryNotFoundError,
    ]
    for exception_class in all_exception_classes:
      instance = exception_class()
      assert isinstance(instance, OneIDError), (
        f"{exception_class.__name__} does not inherit from OneIDError"
      )

  def test_enrollment_errors_inherit_from_enrollment_error(self):
    """All enrollment-specific exceptions must be catchable as EnrollmentError."""
    enrollment_exception_classes = [
      NoHSMError, UACDeniedError, HSMAccessError,
      AlreadyEnrolledError, HandleTakenError, HandleInvalidError,
      HandleRetiredError,
    ]
    for exception_class in enrollment_exception_classes:
      instance = exception_class()
      assert isinstance(instance, EnrollmentError), (
        f"{exception_class.__name__} does not inherit from EnrollmentError"
      )

  def test_auth_error_is_not_enrollment_error(self):
    """AuthenticationError should NOT be catchable as EnrollmentError."""
    assert not isinstance(AuthenticationError(), EnrollmentError)

  def test_network_error_is_not_enrollment_error(self):
    """NetworkError should NOT be catchable as EnrollmentError."""
    assert not isinstance(NetworkError(), EnrollmentError)


class TestExceptionErrorCodes:
  """Verify that each exception has the correct error_code."""

  def test_no_hsm_error_code(self):
    assert NoHSMError().error_code == "NO_HSM_FOUND"

  def test_uac_denied_error_code(self):
    assert UACDeniedError().error_code == "UAC_DENIED"

  def test_hsm_access_error_code(self):
    assert HSMAccessError().error_code == "HSM_ACCESS_ERROR"

  def test_already_enrolled_error_code(self):
    assert AlreadyEnrolledError().error_code == "EK_ALREADY_REGISTERED"

  def test_handle_taken_error_code(self):
    assert HandleTakenError().error_code == "HANDLE_TAKEN"

  def test_handle_invalid_error_code(self):
    assert HandleInvalidError().error_code == "HANDLE_INVALID"

  def test_handle_retired_error_code(self):
    assert HandleRetiredError().error_code == "HANDLE_RETIRED"

  def test_auth_error_code(self):
    assert AuthenticationError().error_code == "AUTH_FAILED"

  def test_network_error_code(self):
    assert NetworkError().error_code == "NETWORK_ERROR"

  def test_not_enrolled_error_code(self):
    assert NotEnrolledError().error_code == "NOT_ENROLLED"

  def test_binary_not_found_error_code(self):
    assert BinaryNotFoundError().error_code == "BINARY_NOT_FOUND"


class TestExceptionMessages:
  """Verify that default messages are meaningful."""

  def test_each_exception_has_a_nonempty_default_message(self):
    """Every exception must have a useful default message."""
    all_classes = [
      NoHSMError, UACDeniedError, HSMAccessError, AlreadyEnrolledError,
      HandleTakenError, HandleInvalidError, HandleRetiredError,
      AuthenticationError, NetworkError, NotEnrolledError, BinaryNotFoundError,
    ]
    for cls in all_classes:
      instance = cls()
      assert len(str(instance)) > 5, (
        f"{cls.__name__} has an unhelpfully short default message: '{str(instance)}'"
      )

  def test_custom_message_preserved(self):
    """Custom messages should override the default."""
    custom_msg = "TPM is on fire"
    error = HSMAccessError(custom_msg)
    assert str(error) == custom_msg
    assert error.message == custom_msg


class TestServerErrorCodeMapping:
  """Verify that server error codes map to the correct SDK exceptions."""

  def test_ek_already_registered_maps_correctly(self):
    with pytest.raises(AlreadyEnrolledError):
      raise_from_server_error_response("EK_ALREADY_REGISTERED", "Already enrolled")

  def test_handle_taken_maps_correctly(self):
    with pytest.raises(HandleTakenError):
      raise_from_server_error_response("HANDLE_TAKEN", "Handle taken")

  def test_handle_invalid_maps_correctly(self):
    with pytest.raises(HandleInvalidError):
      raise_from_server_error_response("HANDLE_INVALID", "Bad handle")

  def test_handle_retired_maps_correctly(self):
    with pytest.raises(HandleRetiredError):
      raise_from_server_error_response("HANDLE_RETIRED", "Handle retired")

  def test_unknown_error_code_falls_back_to_enrollment_error(self):
    with pytest.raises(EnrollmentError):
      raise_from_server_error_response("NEVER_HEARD_OF_THIS", "Mystery error")

  def test_server_error_message_preserved_in_exception(self):
    """The server's error message should appear in the raised exception."""
    server_message = "Handle 'clawdia' is already in use by 1id_abc12345"
    with pytest.raises(HandleTakenError) as exc_info:
      raise_from_server_error_response("HANDLE_TAKEN", server_message)
    assert server_message in str(exc_info.value)


class TestExceptionImportsFromOneidPackage:
  """Verify that all exceptions are importable from the top-level oneid package."""

  def test_all_exceptions_importable_from_oneid(self):
    """Users should be able to do 'import oneid; except oneid.NoHSMError'."""
    assert oneid.OneIDError is OneIDError
    assert oneid.EnrollmentError is EnrollmentError
    assert oneid.NoHSMError is NoHSMError
    assert oneid.UACDeniedError is UACDeniedError
    assert oneid.HSMAccessError is HSMAccessError
    assert oneid.AlreadyEnrolledError is AlreadyEnrolledError
    assert oneid.HandleTakenError is HandleTakenError
    assert oneid.HandleInvalidError is HandleInvalidError
    assert oneid.HandleRetiredError is HandleRetiredError
    assert oneid.AuthenticationError is AuthenticationError
    assert oneid.NetworkError is NetworkError
    assert oneid.NotEnrolledError is NotEnrolledError
    assert oneid.BinaryNotFoundError is BinaryNotFoundError


class TestExceptionCatchingPatterns:
  """Test the usage patterns shown in the SDK documentation."""

  def test_catch_specific_then_broad(self):
    """Pattern from docs: catch NoHSMError, then EnrollmentError, then OneIDError."""
    caught_class_name = None

    try:
      raise NoHSMError("No TPM on this Mac")
    except NoHSMError:
      caught_class_name = "NoHSMError"
    except EnrollmentError:
      caught_class_name = "EnrollmentError"
    except OneIDError:
      caught_class_name = "OneIDError"

    assert caught_class_name == "NoHSMError"

  def test_broad_catch_gets_specific_exception(self):
    """Catching EnrollmentError should catch NoHSMError."""
    with pytest.raises(EnrollmentError):
      raise NoHSMError("No TPM")

  def test_broadest_catch_gets_all(self):
    """Catching OneIDError should catch everything."""
    for exception_class in [NoHSMError, AuthenticationError, NetworkError, NotEnrolledError]:
      with pytest.raises(OneIDError):
        raise exception_class()
