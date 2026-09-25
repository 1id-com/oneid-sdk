"""Device-management server error codes raise the typed exceptions (same set as
the Node SDK), and register_operator_email() exists in Python as in Node.
Mirrors oneid-node src/test/test_device_management_exceptions.ts."""

from unittest import mock

import pytest

import oneid
from oneid import devices


@pytest.mark.parametrize("error_code, expected_class", [
  ("DOWNGRADE_REJECTED", devices.DowngradeRejectedError),
  ("COLOCATION_REQUIRED", devices.ColocationRequiredError),
  ("SESSION_EXPIRED", devices.ColocationSessionExpiredError),
  ("TIMING_VIOLATION", devices.ColocationTimingViolationError),
  ("TPM_RESET_DETECTED", devices.ColocationBindingError),
  ("DEVICE_ALREADY_BOUND", devices.DeviceAlreadyBoundError),
  ("LAST_DEVICE_BURN_REJECTED", devices.LastDeviceBurnRejectedError),
  ("HARDWARE_LOCKED", devices.HardwareLockedError),
  ("ALREADY_LOCKED", devices.IdentityAlreadyLockedError),
  ("DECLARED_TIER_CANNOT_LOCK", devices.DeclaredTierCannotBeLockedError),
  ("TOO_MANY_ACTIVE_DEVICES", devices.TooManyActiveDevicesForLockError),
])
def test_server_code_raises_the_typed_device_exception(error_code, expected_class):
  with pytest.raises(expected_class) as raised:
    devices._raise_from_device_api_error({"code": error_code, "message": "from server"})
  assert isinstance(raised.value, devices.DeviceManagementError)


def test_register_operator_email_puts_the_address_and_invalidates_the_world_cache():
  with mock.patch.object(devices, "_make_authenticated_request",
                         return_value={"operator_email_registered": True}) as request, \
       mock.patch("oneid.world.invalidate_world_cache") as invalidate:
    assert oneid.register_operator_email("human@example.com") is True
  request.assert_called_once_with("PUT", "/api/v1/identity/operator-email",
                                  json_body={"operator_email": "human@example.com"}, credentials=None)
  invalidate.assert_called_once()
