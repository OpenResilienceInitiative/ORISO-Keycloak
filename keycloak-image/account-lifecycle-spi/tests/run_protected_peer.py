#!/usr/bin/env python3
"""One source-bound committed-human peer approval tracer; no selectable authority."""

from protected_peer_readiness import PeerFixture, PeerReadiness, classify
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            fixture=PeerFixture,
            test_class=PeerReadiness,
            test_method="test_committed_tenant_admin_approves_own_tenant_peer_without_person_config",
            case="committed-own-tenant-peer",
            suite_name="protected-committed-peer",
            classify_result=classify,
            extension_evidence=lambda: {"expectedNativeBoots": 2},
        )
    )
