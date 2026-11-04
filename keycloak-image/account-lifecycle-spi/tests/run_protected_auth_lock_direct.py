#!/usr/bin/env python3
"""Separately named direct HTTP counterfactual; old strict-recognizer INPUT stays INPUT."""
from protected_auth_lock_readiness import AuthLockFixture, companion_evidence
from protected_auth_lock_direct_readiness import DirectAuthLockReadiness, classify
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(main(fixture=AuthLockFixture, test_class=DirectAuthLockReadiness,
        test_method="test_bad_authentication_finishes_before_the_owned_realm_lock_is_released",
        case="direct-authentication-before-realm-lock", suite_name="protected-direct-auth-before-lock",
        classify_result=classify, extension_evidence=companion_evidence))
