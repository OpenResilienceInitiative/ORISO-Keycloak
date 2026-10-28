#!/usr/bin/env python3
"""One actual native peer cancellation tracer, retaining the two-boot resource gate."""

from protected_peer_readiness import PeerFixture
from protected_peer_cancel_readiness import PeerCancellation, classify
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(main(
        fixture=PeerFixture,
        test_class=PeerCancellation,
        test_method="test_committed_peer_cancels_only_current_own_tenant_profile_and_mode",
        case="committed-own-tenant-peer-cancel",
        suite_name="protected-committed-peer-cancel",
        classify_result=classify,
        extension_evidence=lambda: {"expectedNativeBoots": 2},
    ))
