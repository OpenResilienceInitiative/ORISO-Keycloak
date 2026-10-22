"""Closed counterexamples for the held-realm HTTP evidence classifier."""
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch
import protected_auth_lock_readiness as lock


def complete(blocked=True):
    return {"executed": 1, "errors": 0, "skipped": 0, "failures": int(blocked),
        "nativeImageIds": ["same-owned-image"] * 2,
        "readinessObservation": {**{key: True for key in lock.PRECONDITIONS},
            "routeObservations": [{"route": name, "unlockedStatus": 401 if index < 2 else 403,
                "afterReleaseStatus": 401 if index < 2 else 403,
                "actualRealmLockOwned": True, "actualRollbackNoCommitVerified": True,
                "completedBeforeRelease": not blocked, "matchingBlockedRequest": blocked}
                for index, name in enumerate(lock.ROUTES)]}}


class AuthLockControls(unittest.TestCase):
    def test_fixed_selector_observation_accepts_only_the_seven_boolean_fields(self):
        value = {"schema": 1, "index": 0, "phase": "RELEASED", "runtimeH2Pinned": True,
            "nativeTransactionOwned": True, "actualRealmRowHeld": True,
            "matchingBlockedRequest": False, "workerFailed": False,
            "selectorObservation": {key: False for key in lock.SELECTOR_FIELDS}}
        with patch.object(lock, "inspect_owned", return_value={"Config": {"Labels": {"oriso-protected-receiver-test": "true"}}}):
            with patch.object(lock.subprocess, "run", return_value=SimpleNamespace(stdout=lock.PREFIX + json.dumps(value), stderr="")):
                self.assertEqual([value], lock.records(object()))
            for selector in ({**value["selectorObservation"], "extra": False},
                             {**value["selectorObservation"], "realmTableObserved": "untrusted-value"}):
                changed = {**value, "selectorObservation": selector}
                with patch.object(lock.subprocess, "run", return_value=SimpleNamespace(stdout=lock.PREFIX + json.dumps(changed), stderr="")):
                    with self.assertRaises(AssertionError):
                        lock.records(object())

    def test_exact_owned_block_and_post_release_denial_is_counterfactual_red(self):
        self.assertEqual("GENUINE_UNAUTHENTICATED_PROTECTED_REQUEST_WAITS_FOR_REALM_ROW_RED", lock.classify(complete()))

    def test_no_block_all_denials_complete_while_lock_held_is_green(self):
        self.assertEqual("GREEN", lock.classify(complete(False)))

    def test_every_native_runtime_or_http_precondition_is_mandatory(self):
        for key in lock.PRECONDITIONS:
            value = complete();value["readinessObservation"][key] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", lock.classify(value))

    def test_missing_case_error_skip_wrong_image_or_incomplete_route_inventory_is_inconclusive(self):
        for key, bad in [("executed", 0), ("errors", 1), ("skipped", 1), ("nativeImageIds", ["one", "different"])]:
            value = complete();value[key] = bad
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", lock.classify(value))
        for rows in [[], complete()["readinessObservation"]["routeObservations"][:-1]]:
            value = complete();value["readinessObservation"]["routeObservations"] = rows
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", lock.classify(value))

    def test_pending_http_without_actual_matching_blocker_is_never_red(self):
        value = complete()
        for row in value["readinessObservation"]["routeObservations"]:
            row["matchingBlockedRequest"] = False
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", lock.classify(value))

    def test_timeout_unknown503_wrong_denial_or_unowned_lock_is_never_red(self):
        for key, bad in [("afterReleaseStatus", None), ("afterReleaseStatus", 503), ("unlockedStatus", 400),
                         ("actualRealmLockOwned", False), ("actualRollbackNoCommitVerified", False)]:
            value = complete();value["readinessObservation"]["routeObservations"][0][key] = bad
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", lock.classify(value))

    def test_no_qualified_failure_is_not_red_and_green_cannot_contain_one_block(self):
        value = complete();value["failures"] = 0
        self.assertEqual("BEHAVIOR_FAILURE", lock.classify(value))
        value = complete(False);value["readinessObservation"]["routeObservations"][0]["matchingBlockedRequest"] = True
        self.assertEqual("BEHAVIOR_FAILURE", lock.classify(value))


if __name__ == "__main__":
    unittest.main()
