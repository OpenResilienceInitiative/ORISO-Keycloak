#!/usr/bin/env python3
"""One strict protected HTTP counterfactual, with sanitized bounded evidence."""

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from protected_resources import evidence as resource_evidence
from lifecycle_fixture import IMAGE


class ProofDeadlineReached(RuntimeError):
    pass


class SanitizedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.cases = {}

    def startTest(self, test):
        super().startTest(test)
        self.cases[test.id()] = {"status": "success", "started": time.monotonic()}

    def stopTest(self, test):
        self.cases[test.id()]["seconds"] = (
            time.monotonic() - self.cases[test.id()]["started"]
        )
        super().stopTest(test)

    def record(self, test, status, exception_type=None):
        value = self.cases.setdefault(test.id(), {})
        value["status"] = status
        if exception_type is not None:
            value["exceptionType"] = exception_type.__name__

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failure", err[0])

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "error", err[0])
        if (
            err[0] is KeyError
            and len(err[1].args) == 1
            and err[1].args[0]
            in {
                "sub",
                "iss",
                "azp",
                "tenantId",
                "aud",
                "realm_access",
                "roles",
                "exp",
                "sid",
                "enabled",
                "standardFlowEnabled",
                "serviceAccountsEnabled",
                "fullScopeAllowed",
                "id",
                "attributes",
                "name",
            }
        ):
            self.cases[test.id()]["missingField"] = err[1].args[0]

    def addSkip(self, test, reason):
        super().addSkip(test, "No skipped native proof is accepted")
        self.record(test, "skipped")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err:
            self.record(
                test,
                "failure" if issubclass(err[0], AssertionError) else "error",
                err[0],
            )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest(module):
    return {
        str(path.relative_to(module)): digest(path)
        for path in sorted(module.rglob("*"))
        if path.is_file()
        and not {"target", "__pycache__", "proof-output"}.intersection(
            path.relative_to(module).parts
        )
        and path.suffix != ".pyc"
    }


def unit_evidence(folder):
    files = sorted(folder.glob("TEST-*.xml"))
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for path in files:
        suite = ET.parse(path).getroot()
        for key in totals:
            totals[key] += int(suite.attrib.get(key, "0"))
    if totals != {"tests": 13, "failures": 0, "errors": 0, "skipped": 0}:
        raise AssertionError("Required13unit XML gate did not pass")
    return {"totals": totals, "xmlSHA256": {path.name: digest(path) for path in files}}


def cleanup_owned(fixture):
    result = {
        "container": "NOT_STARTED",
        "volume": "NOT_STARTED",
        "hostData": "NOT_STARTED",
    }
    if fixture is None:
        return result
    name = getattr(fixture, "name", None)
    if name is not None:
        if not re.fullmatch(r"oriso-c-lifecycle-[a-f0-9]{10}", name):
            raise AssertionError("Unexpected owned container identity")
        ids = subprocess.run(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                "name=^" + name + "$",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.split()
        if ids:
            label = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{{ index .Config.Labels "oriso-protected-receiver-test" }}',
                    name,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            if label != "true":
                raise AssertionError("Owned container label mismatch")
            subprocess.run(
                ["docker", "rm", "-fv", *ids],
                check=True,
                capture_output=True,
                timeout=30,
            )
        result["container"] = "REMOVED_OR_ALREADY_ABSENT"
    volume = getattr(fixture, "native_volume", None)
    if volume is not None:
        if not re.fullmatch(r"oriso-protected-h2-[a-f0-9]{32}", volume):
            raise AssertionError("Unexpected owned volume identity")
        names = subprocess.run(
            [
                "docker",
                "volume",
                "ls",
                "--format",
                "{{.Name}}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.splitlines()
        if volume in names:
            label = subprocess.run(
                [
                    "docker",
                    "volume",
                    "inspect",
                    "--format",
                    '{{ index .Labels "oriso-protected-receiver-test" }}',
                    volume,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            if label != "true":
                raise AssertionError("Owned volume label mismatch")
            subprocess.run(
                ["docker", "volume", "rm", volume],
                check=True,
                capture_output=True,
                timeout=30,
            )
        result["volume"] = "REMOVED_OR_ALREADY_ABSENT"
    data = getattr(fixture, "data", None)
    if data is not None:
        data = Path(data)
        if data.parent.resolve() != Path(
            tempfile.gettempdir()
        ).resolve() or not data.name.startswith("oriso-protected-native-"):
            raise AssertionError("Unexpected owned native data path")
        if data.exists():
            shutil.rmtree(data)
        result["hostData"] = "REMOVED_OR_ALREADY_ABSENT"
    return result


def write_xml(path, result, classification):
    cases = result.cases if result is not None else {}
    suite = ET.Element(
        "testsuite",
        name="protected-human-approval-counterfactual",
        tests=str(len(cases) or 1),
        failures=str(sum(v["status"] == "failure" for v in cases.values())),
        errors=str(
            sum(v["status"] == "error" for v in cases.values()) or (0 if cases else 1)
        ),
        skipped=str(sum(v["status"] == "skipped" for v in cases.values())),
    )
    for identifier, value in cases.items():
        classname, _, name = identifier.rpartition(".")
        case = ET.SubElement(
            suite,
            "testcase",
            classname=classname,
            name=name,
            time=f"{value.get('seconds', 0):.6f}",
        )
        if value["status"] != "success":
            ET.SubElement(
                case,
                value["status"],
                message="Sanitized native outcome; see JSON classification",
            )
    if not cases:
        case = ET.SubElement(
            suite, "testcase", classname="protected-proof", name="input-or-fixture-gate"
        )
        ET.SubElement(case, "error", message=classification)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parent.parent
    repository = module.parent.parent
    workflow = repository / ".github/workflows/scenario-c-protected-proof.yml"
    jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
    started = time.monotonic()
    result = None
    fixture = None
    before = source_manifest(module)
    workflow_before = digest(workflow)
    summary = {
        "schema": 1,
        "suite": "one-protected-human-approval",
        "classification": "INPUT_OR_FIXTURE_ERROR",
        "sourceManifest": before,
        "workflowSHA256": workflow_before,
        "python": sys.version.split()[0],
        "productionImplementationClaim": False,
        "keycloakImageIndex": IMAGE,
        "discovered": 0,
        "executed": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    try:
        if not jar.is_file():
            raise AssertionError("Actual packaged provider JAR required")
        summary["jarSHA256"] = digest(jar)
        summary["unitEvidence"] = unit_evidence(module / "target/surefire-reports")
        import test_protected_invitations as tests

        fixture = tests.ProtectedInvitations
        suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
        discovered = suite.countTestCases()
        summary["discovered"] = discovered
        if discovered != 1:
            raise AssertionError(
                "Exactly one first protected HTTP counterfactual required"
            )

        def deadline(signum, frame):
            raise ProofDeadlineReached("Finite600s native proof deadline")

        previous = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 600)
        try:
            result = SanitizedResult()
            # No raw exception, response, token or request body enters CI output/artifacts.
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
                    key: {k: v for k, v in value.items() if k != "started"}
                    for key, value in result.cases.items()
                },
                "nativeHumanPreconditions": getattr(fixture, "preconditions", []),
                "phase": getattr(fixture, "phase", "not-started"),
                "fixtureDiagnostic": getattr(fixture, "fixture_diagnostic", None),
                "approvalObservation": getattr(fixture, "approval_observation", None),
                "nativeImageIds": getattr(fixture, "native_image_ids", []),
                "setupNativePrecondition": getattr(fixture, "setup_precondition", None),
            }
        )
        native = summary["nativeHumanPreconditions"]
        observation = summary["approvalObservation"] or {}
        valid_preconditions = (
            len(native) == 2
            and [v["stage"] for v in native] == ["seed", "configured"]
            and all(
                v["nativeUserinfoValidatedToken"] and v["currentNativeSession"]
                for v in native
            )
            and observation.get("configurationChecked") is True
            and summary["setupNativePrecondition"] is not None
            and summary["setupNativePrecondition"]["nativeSubjectMatched"] is True
            and summary["setupNativePrecondition"]["exactRoleUnionMatched"] is True
            and summary["setupNativePrecondition"]["audiences"]
            == [
                "agencyservice",
                "consultingtypeservice",
                "tenantservice",
                "userservice",
            ]
            and len(summary["nativeImageIds"]) == 2
            and summary["nativeImageIds"][0] == summary["nativeImageIds"][1]
        )
        if (
            result.wasSuccessful()
            and result.testsRun == discovered
            and not result.skipped
            and valid_preconditions
            and observation.get("actualStatus") == 201
            and observation.get("noAccountCreated") is True
        ):
            summary["classification"] = "GREEN"
        elif (
            valid_preconditions
            and result.testsRun == 1
            and len(result.failures) == 1
            and not result.errors
            and not result.skipped
            and observation.get("actualStatus") in (404, 405)
            and observation.get("noAccountCreated") is True
        ):
            summary["classification"] = "GENUINE_COUNTERFACTUAL_RED"
        elif not valid_preconditions:
            summary["classification"] = "FIXTURE_PRECONDITION_FAILURE"
        elif not result.errors and result.testsRun == 1 and not result.skipped:
            summary["classification"] = "BEHAVIOR_FAILURE_NOT_EXPECTED_COUNTERFACTUAL"
    except Exception as error:
        summary["gateErrorType"] = type(error).__name__
        summary["errors"] = max(1, summary["errors"])
    finally:
        try:
            summary["cleanup"] = cleanup_owned(fixture)
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
        summary["gitRevision"] = os.environ.get("GITHUB_SHA")
        write_xml(report.with_suffix(".xml"), result, summary["classification"])
        report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                key: summary.get(key)
                for key in (
                    "classification",
                    "executed",
                    "failures",
                    "errors",
                    "skipped",
                    "durationSeconds",
                )
            }
        )
    )
    return 0 if summary["classification"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
