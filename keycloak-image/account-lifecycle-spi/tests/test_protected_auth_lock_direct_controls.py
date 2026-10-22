"""Fixed evidence contract for the separately named direct public HTTP proof."""
import unittest
import protected_auth_lock_readiness as original
import protected_auth_lock_direct_readiness as direct
from test_protected_auth_lock_controls import complete


def observed():
    value = complete()
    for row in value["readinessObservation"]["routeObservations"]:
        row["matchingBlockedRequest"] = False
        row["selectorObservation"] = {k: k != "idPredicateObserved" for k in original.SELECTOR_FIELDS}
    return value


class DirectAuthLockControls(unittest.TestCase):
    def test_direct_owned_wait_counterfactual_is_separate_from_unchanged_strict_input(self):
        value = observed()
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", original.classify(value))
        self.assertEqual("GENUINE_DIRECT_AUTH_DENIAL_WAITED_FOR_OWNED_REALM_LOCK_RED", direct.classify(value))

    def test_each_actual_holder_waiter_state_realm_and_bound_uuid_fact_is_required(self):
        for key in direct.BLOCKER_FACTS:
            value = observed();value["readinessObservation"]["routeObservations"][0]["selectorObservation"][key] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", direct.classify(value))

    def test_every_native_positive_and_postrelease_authentication_status_remains_required(self):
        for key in original.PRECONDITIONS:
            value = observed();value["readinessObservation"][key] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", direct.classify(value))
        for status in [None, 400, 500, 503]:
            value = observed();value["readinessObservation"]["routeObservations"][0]["afterReleaseStatus"] = status
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", direct.classify(value))

    def test_completed_authentication_denials_while_actual_lock_is_held_are_green(self):
        self.assertEqual("GREEN", direct.classify(complete(False)))

    def test_skip_missing_route_or_setup_error_is_never_security_red(self):
        for key, bad in [("executed", 0), ("errors", 1), ("skipped", 1)]:
            value = observed();value[key] = bad
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", direct.classify(value))
        value = observed();value["readinessObservation"]["routeObservations"].pop()
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", direct.classify(value))

    def test_wait_without_assertion_or_contradictory_matching_block_cannot_be_green(self):
        value = observed();value["failures"] = 0
        self.assertEqual("BEHAVIOR_FAILURE", direct.classify(value))
        value = complete(False);value["readinessObservation"]["routeObservations"][0]["matchingBlockedRequest"] = True
        self.assertEqual("BEHAVIOR_FAILURE", direct.classify(value))


if __name__ == "__main__":
    unittest.main()
