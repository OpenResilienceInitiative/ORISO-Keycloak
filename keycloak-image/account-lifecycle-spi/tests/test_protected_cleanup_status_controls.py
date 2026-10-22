"""Source-only classifier controls; missing setup never receives public RED credit."""
import copy
import unittest
from protected_cleanup_status_readiness import classify, REQUIRED

class CleanupStatusControls(unittest.TestCase):
    def summary(self, status=404, failures=1):
        return {"executed": 1, "errors": 0, "skipped": 0, "failures": failures,
                "nativeImageIds": ["same", "same"],
                "readinessObservation": {**dict.fromkeys(REQUIRED, True), "cleanupStatus": status}}

    def test_missing_route_after_all_native_preconditions_is_red(self):
        self.assertEqual("GENUINE_FIXED_CLEANUP_STATUS_ROUTE_MISSING_RED", classify(self.summary()))

    def test_each_absent_precondition_refuses_credit(self):
        for name in REQUIRED:
            value = self.summary()
            value["readinessObservation"][name] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(value))

    def test_success_requires_both_independent_exact_proofs_and_denials(self):
        value = self.summary(200, 0)
        self.assertNotEqual("GREEN", classify(value))
        value["readinessObservation"].update(exactIndependentTerminalAndOriginalRestrictionVerified=True,
                                            savedReplayAndAuthenticationDenialsVerified=True)
        self.assertEqual("GREEN", classify(value))

    def test_zero_cases_or_ambiguous_transport_never_counts_as_red(self):
        value = self.summary()
        value["executed"] = 0
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(value))
        self.assertNotEqual("GENUINE_FIXED_CLEANUP_STATUS_ROUTE_MISSING_RED", classify(self.summary(503)))
