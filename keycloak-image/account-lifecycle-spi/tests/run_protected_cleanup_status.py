#!/usr/bin/env python3
"""Finite two-boot cleanup-status public proof using the existing owned runner."""
from protected_binding_readiness import NativeFixture
from protected_cleanup_status_readiness import CleanupStatusReadiness, classify
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(main(
        fixture=NativeFixture,
        test_class=CleanupStatusReadiness,
        test_method="test_independent_cleanup_status_binds_the_original_restriction_and_native_terminal",
        case="independent-cleanup-status",
        suite_name="protected-cleanup-status",
        classify_result=classify,
        extension_evidence=lambda: {"expectedNativeBoots": 2},
    ))
