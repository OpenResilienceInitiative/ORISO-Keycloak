#!/usr/bin/env python3
"""One executed controlled-restart/login proof; unrelated startup is not RED."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import time
import unittest

from lifecycle_fixture import IMAGE
from protected_binding_readiness import BindingReadiness, NativeFixture
from protected_resources import evidence as resource_evidence
from run_protected import (
    ProofDeadlineReached,
    SanitizedResult,
    cleanup_owned,
    digest,
    source_manifest,
    unit_evidence,
    write_xml,
)

CASE = "binding-drift-login-available"


def classify(summary):
    o = summary.get("readinessObservation", {})
    required = (
        "allFiveCurrentNativeClientLinksVerified",
        "sameJarValidBindingHumanApproveAndNoAccountVerified",
        "validNativeHumanRealmSessionAndRuntimeVerified",
        "exactNativeGroupNameOnlyDriftVerified",
        "actualPublishedMappingObserved",
        "sameImageJarConfigVolumeAndResourceCapsVerified",
        "thirdBootObservationFinished",
    )
    images = summary.get("nativeImageIds", [])
    valid = (
        summary.get("executed") == 1
        and summary.get("errors") == 0
        and summary.get("skipped") == 0
        and all(o.get(key) is True for key in required)
        and len(images) == 3
        and len(set(images)) == 1
        and o.get("validBindingApproveStatus") == 201
    )
    if not valid:
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 0:
        if (
            o.get("driftBootHumanLoginStatus") == 200
            and o.get("driftBootNativeUserinfoAndCurrentSessionVerified") is True
            and o.get("unreadyProtectedApprovalStatus") == 503
            and o.get("unreadyResponseNoStore") is True
            and o.get("postDriftRealmHumanGroupAndAccountCountUnchanged") is True
        ):
            return "GREEN"
        return "INPUT_OR_FIXTURE_ERROR"
    if (
        summary.get("failures") == 1
        and o.get("driftBootHumanLoginStatus") == 200
        and o.get("driftBootNativeUserinfoAndCurrentSessionVerified") is True
        and o.get("unreadyProtectedApprovalStatus") == 503
        and o.get("unreadyResponseNoStore") is False
    ):
        return "GENUINE_PROTECTED_UNAVAILABLE_NO_STORE_RED"
    if (
        summary.get("failures") == 1
        and o.get("classifiedNativeBindingExitAndLoginUnavailable") is True
        and o.get("nonzeroNativeExitWithoutOom") is True
        and o.get("driftBootHumanLoginStatus") != 200
        and o.get("protectedValidationSourceFrames")
        == {
            "factory": True,
            "installation": True,
            "profile": True,
            "forbidden": True,
        }
    ):
        return "GENUINE_PROTECTED_BINDING_ABORTS_NATIVE_LOGIN_RED"
    return "BEHAVIOR_FAILURE"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parent.parent
    workflow = module.parent.parent / ".github/workflows/scenario-c-protected-proof.yml"
    jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
    before, workflow_before = source_manifest(module), digest(workflow)
    summary = {
        "schema": 1,
        "suite": "protected-binding-readiness",
        "case": CASE,
        "classification": "INPUT_OR_FIXTURE_ERROR",
        "sourceManifest": before,
        "workflowSHA256": workflow_before,
        "gitRevision": os.environ.get("GITHUB_SHA"),
        "keycloakImageIndex": IMAGE,
        "executed": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "totalNativeDeadlineSeconds": 600,
        "thirdBootDeadlineSeconds": 180,
    }
    result = None
    started = time.monotonic()
    try:
        if not jar.is_file():
            raise AssertionError("Actual packaged JAR required")
        summary["jarSHA256"] = digest(jar)
        summary["unitEvidence"] = unit_evidence(module / "target/surefire-reports")
        suite = unittest.TestSuite(
            [
                BindingReadiness(
                    "test_binding_drift_keeps_native_login_and_protected_unavailable"
                )
            ]
        )

        def deadline(signum, frame):
            raise ProofDeadlineReached("Finite600s native proof deadline")

        previous = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 600)
        try:
            result = SanitizedResult()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                suite.run(result)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        summary.update(
            {
                "executed": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "cases": {
                    key: {k: v for k, v in val.items() if k != "started"}
                    for key, val in result.cases.items()
                },
                "nativeImageIds": getattr(NativeFixture, "native_image_ids", []),
                "readinessObservation": BindingReadiness.observation,
                "phase": getattr(NativeFixture, "phase", "not-started"),
            }
        )
        summary["classification"] = classify(summary)
    except Exception as error:
        summary["gateErrorType"] = type(error).__name__
        summary["errors"] = max(1, summary["errors"])
    finally:
        try:
            summary["cleanup"] = cleanup_owned(NativeFixture)
        except Exception as error:
            summary["cleanup"] = {"errorType": type(error).__name__}
            summary["classification"] = "CLEANUP_UNVERIFIED"
        summary["resourceEvidence"] = resource_evidence()
        summary["sourceStable"] = before == source_manifest(module)
        summary["workflowStable"] = workflow_before == digest(workflow)
        summary["jarStable"] = jar.is_file() and summary.get("jarSHA256") == digest(jar)
        if not all(
            summary[key] for key in ("sourceStable", "workflowStable", "jarStable")
        ):
            summary["classification"] = "INPUT_CHANGED_OR_MISSING"
        summary["durationSeconds"] = round(time.monotonic() - started, 3)
        write_xml(report.with_suffix(".xml"), result, summary["classification"])
        report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "case",
                    "classification",
                    "executed",
                    "failures",
                    "errors",
                    "skipped",
                )
            }
        )
    )
    return 0 if summary["classification"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
