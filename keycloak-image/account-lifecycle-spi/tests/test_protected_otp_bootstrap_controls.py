"""Offline classifier controls; no Java/native resources or credentials."""

import copy
import unittest

from protected_otp_bootstrap import REQUIRED, classify


class BootstrapClassifier(unittest.TestCase):
    def valid(self):
        return {
            "executed": 1, "failures": 1, "errors": 0, "skipped": 0,
            "bothProvidersStable": True, "bootstrapWorkflowStable": True,
            "nativeImageIds": ["same", "same"],
            "readinessObservation": {
                **dict.fromkeys(REQUIRED, True),
                "sourceApproveStatus": 201, "sourceCreateStatus": 201,
                "sourceOwnedReadStatus": 200, "otpPrepareStatus": 403,
            },
        }

    def test_actual_preconditioned_single_route_denial_is_red(self):
        self.assertEqual("GENUINE_PROTECTED_PENDING_OTP_PREPARE_RED", classify(self.valid()))

    def test_missing_any_native_precondition_is_setup(self):
        for key in REQUIRED:
            with self.subTest(key=key):
                value = self.valid()
                value["readinessObservation"].pop(key)
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(value))

    def test_zero_skipped_setup_or_multiple_failures_are_never_red(self):
        for change in [dict(executed=0), dict(skipped=1), dict(errors=1),
                       dict(failures=2), dict(bothProvidersStable=False),
                       dict(bootstrapWorkflowStable=False)]:
            with self.subTest(change=change):
                value = self.valid()
                value.update(change)
                self.assertNotEqual("GENUINE_PROTECTED_PENDING_OTP_PREPARE_RED", classify(value))

    def test_wrong_source_status_or_image_is_setup(self):
        baseline = self.valid()
        for key in ("sourceApproveStatus", "sourceCreateStatus", "sourceOwnedReadStatus"):
            with self.subTest(key=key):
                value = copy.deepcopy(baseline)
                value["readinessObservation"][key] = 403
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(value))
        baseline["nativeImageIds"] = ["first", "other"]
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(baseline))

    def test_success_requires_no_failed_assertion_and_actual_200(self):
        value = self.valid()
        value["readinessObservation"]["otpPrepareStatus"] = 200
        self.assertEqual("BEHAVIOR_FAILURE", classify(value))
        value["failures"] = 0
        self.assertEqual("GREEN", classify(value))
        value["readinessObservation"]["otpPrepareStatus"] = 404
        self.assertNotEqual("GREEN", classify(value))
