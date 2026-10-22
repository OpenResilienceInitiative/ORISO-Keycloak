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

    def test_expired_original_prepare_retry_requires_verified_causal_result(self):
        value = self.valid()
        value["readinessObservation"].update(otpPrepareStatus=200,
            preparedReceiptMacVerified=True, expiredOriginalPrepareRetryStatus=403)
        self.assertEqual("GENUINE_PROTECTED_PENDING_OTP_EXPIRED_PREPARE_RETRY_RED", classify(value))
        value["readinessObservation"].pop("preparedReceiptMacVerified")
        self.assertEqual("BEHAVIOR_FAILURE", classify(value))

    def test_email_denial_requires_actual_pending_and_smtp_preconditions(self):
        value = self.valid()
        observation = value["readinessObservation"]
        observation.update(otpPrepareStatus=200, emailPendingCreateOwnedReadAndPrepareVerified=True,
            emailActualSmtpConfigured=True, emailCanonicalAdminAndStockDenialVerified=True,
            emailNoCredentialOrMailBeforeStart=True, emailStartStatus=403)
        self.assertEqual("GENUINE_PROTECTED_PENDING_OTP_EMAIL_START_RED", classify(value))
        observation["emailActualSmtpConfigured"] = False
        self.assertEqual("BEHAVIOR_FAILURE", classify(value))

    def test_fenced_email_cleanup_red_requires_actual_cancel_recovery_and_old_write_refusal(self):
        value = self.valid()
        seen = value["readinessObservation"]
        seen.update(otpPrepareStatus=200, emailPendingCreateOwnedReadAndPrepareVerified=True,
            emailActualSmtpConfigured=True, emailCanonicalAdminAndStockDenialVerified=True,
            emailNoCredentialOrMailBeforeStart=True, emailFinishActiveDisabledAndExactRetryVerified=True,
            fencedEmailCancelStatus=200, fencedEmailRecoveryStatus=200,
            fencedEmailTwoGenerationFenceVerified=True, fencedEmailOldStartStatus=409,
            fencedEmailOldWriteAndSmtpUnchanged=True, fencedEmailCompensateStatus=409)
        self.assertEqual("GENUINE_FENCED_PENDING_EMAIL_COMPENSATION_RED", classify(value))
        seen["fencedEmailOldWriteAndSmtpUnchanged"] = False
        self.assertEqual("BEHAVIOR_FAILURE", classify(value))

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
        self.assertNotEqual("GREEN", classify(value))
        value["readinessObservation"].update(appMutationStatus=201,
            preparedReceiptMacVerified=True, appNativeCredentialAndDisabledStateVerified=True,
            exactAppRetryPreservesOneCredential=True, completedPhaseRefusesNewEnrollment=True,
            expiredOriginalPrepareRetryPreservesExactCausalReceipt=True,
            emailFinishActiveDisabledAndExactRetryVerified=True,
            fencedEmailPendingCompensationExactRetryVerified=True)
        self.assertEqual("GREEN", classify(value))
        value["readinessObservation"]["otpPrepareStatus"] = 404
        self.assertNotEqual("GREEN", classify(value))
