"""Direct public denial-before-held-row-release proof, separate from the SQL-printer recognizer."""
from protected_auth_lock_readiness import (
    AuthLockReadiness, PRECONDITIONS, ROUTES,
)

BLOCKER_FACTS = {"holderWaiterObserved", "distinctSessionObserved", "blockedStateObserved",
    "realmTableObserved", "forUpdateObserved", "exactBoundRealmParameterObserved"}


def classify(summary):
    o = summary.get("readinessObservation", {})
    rows = o.get("routeObservations", [])
    images = summary.get("nativeImageIds", [])
    if not (summary.get("executed") == 1 and summary.get("errors") == 0 and summary.get("skipped") == 0
            and all(o.get(k) is True for k in PRECONDITIONS)
            and len(images) == 2 and len(set(images)) == 1
            and len(rows) == 9 and [r.get("route") for r in rows] == list(ROUTES)):
        return "INPUT_OR_FIXTURE_ERROR"
    waited = False
    for row in rows:
        expected = 401 if row["route"] in {"approve", "human-cancel"} else 403
        if (row.get("unlockedStatus") != expected or row.get("afterReleaseStatus") != expected
                or row.get("actualRealmLockOwned") is not True
                or row.get("actualRollbackNoCommitVerified") is not True):
            return "INPUT_OR_FIXTURE_ERROR"
        if row.get("completedBeforeRelease") is not True:
            # This new direct-HTTP proof requires the actual linked native waiter,
            # held REALM and bound actual UUID; it does not parse an ID printer grammar.
            if not all(row.get("selectorObservation", {}).get(k) is True for k in BLOCKER_FACTS):
                return "INPUT_OR_FIXTURE_ERROR"
            waited = True
    if waited and summary.get("failures") == 1:
        return "GENUINE_DIRECT_AUTH_DENIAL_WAITED_FOR_OWNED_REALM_LOCK_RED"
    if not waited and summary.get("failures") == 0 and all(r.get("matchingBlockedRequest") is False for r in rows):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class DirectAuthLockReadiness(AuthLockReadiness):
    # Reuse the actual nine public calls and all owned native/JPA/HTTP/rollback
    # assertions byte-for-byte. The strict SQL recognizer source remains unchanged.
    test_bad_authentication_finishes_before_the_owned_realm_lock_is_released = (
        AuthLockReadiness.test_untrusted_public_requests_reject_before_waiting_for_the_realm_row)
