#!/usr/bin/env python3
"""Two fixed finite peer-policy restart cases; no product control endpoint."""

import os
from protected_peer_readiness import PeerFixture
from protected_peer_policy_readiness import PeerPolicyReadiness, classify
from run_protected_readiness import main

CASES = {
    "committed-peer-policy-withdrawal": "test_removed_policy_preserves_frozen_child_commit_without_role_only_delegation",
    "committed-peer-policy-revision": "test_revised_policy_preserves_frozen_child_commit_and_exact_new_policy_binding",
}

if __name__ == "__main__":
    case = os.environ.get("PROTECTED_INSTALLATION_CASE")
    if case not in CASES:
        raise SystemExit("One fixed peer-policy proof case is required")
    raise SystemExit(main(fixture=PeerFixture, test_class=PeerPolicyReadiness,
        test_method=CASES[case], case=case, suite_name="protected-committed-peer-policy",
        classify_result=classify, extension_evidence=lambda: {"expectedNativeBoots": 3}))
