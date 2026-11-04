#!/usr/bin/env python3
"""Fixed actual-native failed-prepare public readiness control."""

from protected_commit_readiness import CommitReadiness, classify
from protected_rollback_readiness import RollbackFixture, companion_evidence
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            fixture=RollbackFixture,
            test_class=CommitReadiness,
            test_method="test_native_prepare_failure_keeps_approval_unavailable",
            case="binding-commit-failure-unavailable",
            suite_name="protected-native-commit-failure-readiness",
            classify_result=classify,
            extension_evidence=companion_evidence,
        )
    )
