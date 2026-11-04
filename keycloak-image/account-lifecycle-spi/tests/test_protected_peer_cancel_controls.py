"""Offline controls for the finite actual peer cancellation classifier."""

import unittest

from protected_peer_cancel_readiness import CANCEL_REQUIRED, classify


def complete():
    return {"executed": 1, "errors": 0, "skipped": 0, "failures": 1,
            "nativeImageIds": ["synthetic-same-image"] * 2,
            "readinessObservation": {**{k: True for k in CANCEL_REQUIRED},
                "sourceApproveStatus": 201, "sourceCreateStatus": 201,
                "sourceCommitStatus": 200, "sourceConsumedStatus": 200,
                "peerApproveStatus": 201, "outOfReachCancelStatuses": [403] * 4,
                "peerCancelStatus": 403}}


class PeerCancellationControls(unittest.TestCase):
    def test_actual403_only_after_all_current_native_preconditions_is_red(self):
        self.assertEqual("GENUINE_COMMITTED_PEER_HUMAN_CANCEL_RED", classify(complete()))

    def test_all_native_and_reach_preconditions_are_mandatory(self):
        for name in CANCEL_REQUIRED:
            with self.subTest(name=name):
                s = complete(); s["readinessObservation"][name] = False
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(s))

    def test_zero_setup_error_skip_or_unqualified_peer_is_not_red(self):
        for field, value in (("executed", 0), ("errors", 1), ("skipped", 1)):
            with self.subTest(field=field):
                s = complete(); s[field] = value
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(s))
        s = complete(); s["readinessObservation"]["peerApproveStatus"] = 403
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(s))

    def test_wrong_status_or_incomplete_denial_is_not_security_red(self):
        for value in (401, 404, 405, 409, 500, 503):
            with self.subTest(status=value):
                s = complete(); s["readinessObservation"]["peerCancelStatus"] = value
                self.assertEqual("BEHAVIOR_FAILURE", classify(s))
        s = complete(); s["readinessObservation"]["outOfReachCancelStatuses"] = [403, 403, 200]
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(s))

    def test_green_requires_immutable_cancel_receipt_and_retry(self):
        s = complete(); s["failures"] = 0; s["readinessObservation"]["peerCancelStatus"] = 200
        self.assertEqual("BEHAVIOR_FAILURE", classify(s))
        s["readinessObservation"]["immutableHumanCancelReceiptAndRetriesVerified"] = True
        self.assertEqual("GREEN", classify(s))

    def test_both_native_boots_must_use_the_same_image(self):
        s = complete(); s["nativeImageIds"] = ["one", "other"]
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(s))


if __name__ == "__main__":
    unittest.main()
