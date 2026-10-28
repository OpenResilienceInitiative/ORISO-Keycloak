#!/usr/bin/env python3
"""Actual native SEND/cancel serialization with a separate default-SMTP observer JAR."""
import hashlib
import os
from pathlib import Path

from protected_otp_bootstrap import BootstrapFixture, BootstrapRead, classify
from run_protected import source_manifest
from run_protected_readiness import main

WRITER_FACTS = ("inflightCancelBlockedByActualWriter", "inflightWriterCommittedAfterDefaultSmtp",
                "inflightBarrierDidNotExpire", "inflightCompanionJarStable", "inflightOneActualSmtp")


def classify_writer(summary):
    observed = summary.get("readinessObservation", {})
    rows = observed.get("inflightWriterEvents", [])
    base = classify(summary)
    sample = observed.get("inflightNativeWaitSample", [])
    if (len(sample) != 1 or sample[0].get("rowCount") != 1 or not all(sample[0].get(key) is True for key in (
            "nativeBlockedState", "capturedBlockerMatches", "otherSession", "selectStatement",
            "onlyRealmTable", "singlePrimaryKeyPredicate", "onlyForUpdateAndExactRealmBind"))):
        return "INPUT_OR_FIXTURE_ERROR"
    if not all(observed.get(k) is True for k in WRITER_FACTS):
        return "INPUT_OR_FIXTURE_ERROR"
    phases = ("ENTERED", "BLOCKED", "SMTP_RETURNED", "COMMITTED")
    if tuple(row.get("phase") for row in rows) != phases:
        return "INPUT_OR_FIXTURE_ERROR"
    for index, row in enumerate(rows):
        if (row.get("cancelBlockedByCapturedWriter") is not (index > 0)
                or row.get("defaultSmtpReturned") is not (index >= 2)
                or row.get("writerCommitted") is not (index == 3)):
            return "INPUT_OR_FIXTURE_ERROR"
    if any(row.get("observerFailed") or not all(row.get(k) is True for k in (
        "actualNativeWriterTransaction", "exactPrivateSendingOrigin", "runtimeH2Pinned", "exactNativeDefaultDelegate")) for row in rows):
        return "INPUT_OR_FIXTURE_ERROR"
    if not any(row["phase"] == "BLOCKED" and row["cancelBlockedByCapturedWriter"] for row in rows):
        return "INPUT_OR_FIXTURE_ERROR"
    return base


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    module = root / "keycloak-image/account-lifecycle-spi"
    otp = root / "keycloak-image/otp-config-spi"
    workflow = root / ".github/workflows/scenario-c-protected-otp-writer-proof.yml"
    companion = Path(os.environ.get("OTP_WRITER_PROOF_JAR", ""))
    if not companion.is_file():
        raise SystemExit("Exact disposable native writer observer is required")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    jar = Path(os.environ["OTP_C_TEST_JAR"])
    theme = root / "keycloak-image/themes/oriso"
    themes = lambda: {str(p.relative_to(root)): digest(p) for p in sorted(theme.rglob("*")) if p.is_file()}
    before, theme_before = source_manifest(otp), themes()
    companion_before, jar_before, workflow_before = digest(companion), digest(jar), digest(workflow)
    companion_sources = {str(p.relative_to(root)): digest(p) for p in sorted((module / "tests/native-otp-writer-fixture").rglob("*")) if p.is_file()}
    for name in ("build_otp_writer_companion.py", "otp_writer_fixture.py", "run_protected_otp_writer.py"):
        path = module / "tests" / name
        companion_sources[str(path.relative_to(root))] = digest(path)
    def evidence():
        return {"otpSourceManifest": before, "themeSourceManifest": theme_before,
                "themeSourceStable": bool(theme_before) and theme_before == themes(),
                "otpJarSHA256": jar_before, "bothProvidersStable": jar_before == digest(jar) and before == source_manifest(otp),
                "bootstrapWorkflowSHA256": workflow_before, "bootstrapWorkflowStable": workflow_before == digest(workflow),
                "writerCompanionSourceManifest": companion_sources, "writerCompanionJarSHA256": companion_before,
                "nativeDelegateObservation": BootstrapRead.observation.get("nativeDelegateObservation"),
                "writerCompanionJarStable": companion_before == digest(companion), "expectedNativeBoots": 2,
                "boundary": "Fixture-only SMTP observer delegates actual pinned default provider; native product authority/JARs unchanged. No final product-image or User cleanup release credit."}
    raise SystemExit(main(fixture=BootstrapFixture, test_class=BootstrapRead,
        test_method="test_actual_pending_protected_claim_prepares_original_otp_route",
        case="protected-pending-otp-inflight-writer", suite_name="protected-pending-otp-writer",
        classify_result=classify_writer, extension_evidence=evidence))
