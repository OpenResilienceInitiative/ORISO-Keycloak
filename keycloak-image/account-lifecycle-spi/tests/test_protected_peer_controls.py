"""Offline classification controls; never start a native fixture."""

import copy
import unittest

import protected_peer_readiness as peer


def complete():
    return {
        "executed": 1,
        "errors": 0,
        "skipped": 0,
        "failures": 1,
        "nativeImageIds": ["sha256:synthetic-same-image"] * 2,
        "readinessObservation": {
            **{name: True for name in peer.REQUIRED},
            "sourceApproveStatus": 201,
            "sourceCreateStatus": 201,
            "sourceCommitStatus": 200,
            "sourceConsumedStatus": 200,
            "peerApproveStatus": 403,
        },
    }


class PeerClassificationControls(unittest.TestCase):
    def test_only_actual403_after_all_native_preconditions_is_feature_red(self):
        self.assertEqual(
            "GENUINE_COMMITTED_OWN_TENANT_PEER_APPROVAL_RED", peer.classify(complete())
        )

    def test_wrong_human_or_missing_route_cannot_be_feature_red(self):
        for status in (0, 400, 401, 404, 405, 409, 500, 503):
            with self.subTest(status=status):
                observed = complete()
                observed["readinessObservation"]["peerApproveStatus"] = status
                self.assertEqual("BEHAVIOR_FAILURE", peer.classify(observed))

    def test_every_native_precondition_is_mandatory(self):
        for name in peer.REQUIRED:
            with self.subTest(name=name):
                observed = complete()
                observed["readinessObservation"][name] = False
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", peer.classify(observed))

    def test_uncommitted_origin_or_failed_native_step_is_not_feature_red(self):
        for name in ("sourceApproveStatus", "sourceCreateStatus", "sourceCommitStatus", "sourceConsumedStatus"):
            with self.subTest(name=name):
                observed = complete()
                observed["readinessObservation"][name] = 403
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", peer.classify(observed))

    def test_zero_cases_errors_or_skips_are_fixture_failures(self):
        for field, value in (("executed", 0), ("errors", 1), ("skipped", 1)):
            with self.subTest(field=field):
                observed = complete()
                observed[field] = value
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", peer.classify(observed))

    def test_same_image_two_boots_are_required(self):
        for images in ([], ["one"], ["one", "different"], ["one"] * 3):
            with self.subTest(images=images):
                observed = complete()
                observed["nativeImageIds"] = images
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", peer.classify(observed))

    def test_green_requires201_and_exact_native_peer_receipt(self):
        observed = complete()
        observed["failures"] = 0
        observed["readinessObservation"]["peerApproveStatus"] = 201
        self.assertEqual("BEHAVIOR_FAILURE", peer.classify(observed))
        observed["readinessObservation"]["exactPeerIssuedReceiptVerified"] = True
        self.assertEqual("GREEN", peer.classify(observed))
        changed = copy.deepcopy(observed)
        changed["readinessObservation"]["peerApproveStatus"] = 403
        self.assertEqual("BEHAVIOR_FAILURE", peer.classify(changed))


if __name__ == "__main__":
    unittest.main()
