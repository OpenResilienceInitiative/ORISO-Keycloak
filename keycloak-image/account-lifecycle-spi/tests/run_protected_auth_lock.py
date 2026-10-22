#!/usr/bin/env python3
"""One fixed native held-lock/public-HTTP counterfactual, with no product hook."""
from protected_auth_lock_readiness import AuthLockFixture, AuthLockReadiness, classify, companion_evidence
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(main(fixture=AuthLockFixture, test_class=AuthLockReadiness,
        test_method="test_untrusted_public_requests_reject_before_waiting_for_the_realm_row",
        case="authentication-before-realm-lock", suite_name="protected-auth-before-lock",
        classify_result=classify, extension_evidence=companion_evidence))
