#!/usr/bin/env python3
"""Fixed corrected-binding public restart control; no selectable product mode."""

from protected_corrected_readiness import CorrectedReadiness, classify
from run_protected_readiness import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            test_class=CorrectedReadiness,
            test_method="test_corrected_binding_restart_restores_native_human_approval",
            case="binding-corrected-restart-available",
            suite_name="protected-corrected-binding-readiness",
            classify_result=classify,
            extension_evidence=lambda: {"fourthBootDeadlineSeconds": 180},
        )
    )
