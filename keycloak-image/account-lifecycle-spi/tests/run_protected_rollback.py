#!/usr/bin/env python3
"""Fixed actual native rollback-only receiving case; no policy selector input."""

from protected_rollback_readiness import (
    RollbackFixture,
    RollbackReadiness,
    classify_rollback,
    companion_evidence,
)
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            fixture=RollbackFixture,
            test_class=RollbackReadiness,
            test_method="test_normal_native_validation_rollback_cannot_enable_approval",
            case="binding-rollback-only-unavailable",
            suite_name="protected-native-rollback-readiness",
            classify_result=classify_rollback,
            extension_evidence=companion_evidence,
        )
    )
