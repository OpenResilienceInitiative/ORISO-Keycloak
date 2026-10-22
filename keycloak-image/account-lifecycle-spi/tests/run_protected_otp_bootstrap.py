#!/usr/bin/env python3
"""One real pending-account OTP tracer, paired providers and immutable evidence."""

import hashlib
import os
from pathlib import Path

from protected_otp_bootstrap import BootstrapFixture, BootstrapRead, classify
from run_protected import source_manifest
from run_protected_readiness import main


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    otp = root / "keycloak-image/otp-config-spi"
    workflow = root / ".github/workflows/scenario-c-protected-otp-bootstrap-proof.yml"
    jar = Path(os.environ.get("OTP_C_TEST_JAR", ""))
    before = source_manifest(otp)
    workflow_before = digest(workflow)
    jar_before = digest(jar) if jar.is_file() else None

    def paired_evidence():
        return {
            "otpSourceManifest": before,
            "otpJarSHA256": jar_before,
            "bothProvidersStable": bool(jar_before) and jar.is_file()
            and jar_before == digest(jar) and before == source_manifest(otp),
            "bootstrapWorkflowSHA256": workflow_before,
            "bootstrapWorkflowStable": workflow_before == digest(workflow),
            "expectedNativeBoots": 2,
            "boundary": "Native pending provenance only; User SQL and browser pairing remain separate.",
        }

    raise SystemExit(main(
        fixture=BootstrapFixture, test_class=BootstrapRead,
        test_method="test_actual_pending_protected_claim_prepares_original_otp_route",
        case="protected-pending-otp-prepare", suite_name="protected-pending-otp",
        classify_result=classify, extension_evidence=paired_evidence,
    ))
