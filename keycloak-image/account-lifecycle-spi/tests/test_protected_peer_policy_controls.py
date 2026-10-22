"""Offline classification counterexamples for actual peer-policy restart evidence."""

import unittest
import protected_peer_policy_readiness as policy


def complete():
    return {"executed": 1, "failures": 1, "errors": 0, "skipped": 0,
        "nativeImageIds": ["synthetic-same-image"] * 3,
        "readinessObservation": {**{name: True for name in policy.PRECOMMIT},
            "policyChange": "removed", "sourceApproveStatus": 201, "sourceCreateStatus": 201,
            "sourceCommitStatus": 200, "sourceConsumedStatus": 200, "peerApproveStatus": 201,
            "childCreateStatus": 201, "changedPolicyPrimaryApproveStatus": 201,
            "changedPolicyParentApproveStatus": 403, "childCommitStatus": 409}}


class PeerPolicyControls(unittest.TestCase):
    def test_only_actual403_or409_frozen_commit_after_all_native_preconditions_is_red(self):
        for code in (403, 409):
            s = complete(); s["readinessObservation"]["childCommitStatus"] = code
            self.assertEqual("GENUINE_FROZEN_PEER_APPROVAL_COMMIT_AFTER_POLICY_CHANGE_RED", policy.classify(s))

    def test_withdrawn_old_peer201_is_a_distinct_authority_failure(self):
        s = complete(); s["readinessObservation"]["changedPolicyParentApproveStatus"] = 201
        self.assertEqual("GENUINE_WITHDRAWN_PEER_RETAINS_NEW_APPROVAL_AUTHORITY_RED", policy.classify(s))

    def test_all_native_profile_and_finite_config_preconditions_are_required(self):
        for name in policy.PRECOMMIT:
            s = complete(); s["readinessObservation"][name] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_unknown_commit_status_is_never_feature_red(self):
        for code in (0, 400, 401, 404, 405, 500, 503):
            s = complete(); s["readinessObservation"]["childCommitStatus"] = code
            self.assertEqual("BEHAVIOR_FAILURE", policy.classify(s))

    def test_setup_error_skip_or_missing_case_is_not_a_product_counterfactual(self):
        for key, value in (("executed", 0), ("errors", 1), ("skipped", 1)):
            s = complete(); s[key] = value
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_three_equal_actual_image_ids_are_required(self):
        for images in ([], ["one"] * 2, ["one", "one", "different"], ["one"] * 4):
            s = complete(); s["nativeImageIds"] = images
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_green_requires_child_macs_saved_retries_and_new_current_human_authority(self):
        for mode, child_status in (("removed", 403), ("revised", 201)):
            s = complete(); s["failures"] = 0
            o = s["readinessObservation"]
            o.update(policyChange=mode, childCommitStatus=200, changedPolicyChildApproveStatus=child_status,
                withdrawnParentNewApprovalDenied=True, childCommitAndConsumedAllMACBindingsVerified=True,
                savedParentAndChildTerminalRetriesUnchanged=True, freshChildNativeHumanAfterRestartVerified=True,
                policyChangeChildAuthorityVerified=True)
            self.assertEqual("GREEN", policy.classify(s))
            for key in ("childCommitAndConsumedAllMACBindingsVerified", "savedParentAndChildTerminalRetriesUnchanged",
                        "freshChildNativeHumanAfterRestartVerified", "policyChangeChildAuthorityVerified"):
                changed = {**s, "readinessObservation": {**o, key: False}}
                self.assertEqual("BEHAVIOR_FAILURE", policy.classify(changed))


if __name__ == "__main__":
    unittest.main()
