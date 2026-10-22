#!/usr/bin/env python3
"""Sanitized first scoped OTP diagnostic: five actual GET cases, first app mutation plus legacy five-route control."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import traceback
import unittest
import zipfile
import xml.etree.ElementTree as ET

from run_native import XmlResult

ROOT = Path(__file__).resolve().parents[3]
MODULES = [ROOT / "keycloak-image/account-lifecycle-spi", ROOT / "keycloak-image/otp-config-spi"]
WORKFLOW = ROOT / ".github/workflows/scenario-c-scoped-otp-proof.yml"
POSITIVE = "test_otp_scoped.ScopedOtpRead.test_canonical_admin_current_self_reads_setup_without_native_grants"
APP_POSITIVE = "test_otp_scoped.ScopedOtpRead.test_current_self_app_enrollment_retry_never_replaces_later_credentials"
DELETE_POSITIVE = "test_otp_scoped.ScopedOtpRead.test_current_self_delete_retry_never_removes_a_later_enrollment"
EMAIL_START_POSITIVE = "test_otp_scoped.ScopedOtpRead.test_current_self_email_start_uses_foreground_delivery_and_exact_retry_never_resends"
EMAIL_FINISH_POSITIVE = "test_otp_scoped.ScopedOtpRead.test_current_self_finishes_exact_native_pending_email_credential"


def sources():
    result = {}
    for module in MODULES:
        for path in sorted(module.rglob("*")):
            if path.is_file() and "target" not in path.parts and "__pycache__" not in path.parts and path.suffix != ".pyc":
                result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    result[str(WORKFLOW.relative_to(ROOT))] = hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()
    return result


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def units(report):
    expected = {}
    parameterized = {
        "de.onlineberatung.authenticator.OtpMailAuthenticatorParameterizedTest": 5,
        "de.onlineberatung.RealmOtpResourceProviderParameterizedTest": 5,
    }
    for path in (MODULES[1] / "src/test/java").rglob("*Test.java"):
        text = path.read_text()
        methods = re.findall(r"@Test(?:\([^)]*\))?\s+public\s+void\s+(\w+)\s*\(", text)
        if methods:
            package = re.search(r"package\s+([\w.]+);", text).group(1)
            name = package + "." + path.stem
            repeat = 1
            if "@RunWith(Parameterized.class)" in text:
                if name not in parameterized:
                    raise ValueError("Unreviewed parameterized unit inventory")
                repeat = parameterized[name]
            expected[name] = {method: repeat for method in methods}
    output = ET.Element("testsuites")
    actual = {}
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    consistent = True
    method_inventory = True
    for path in sorted((MODULES[1] / "target/surefire-reports").glob("TEST-*.xml")):
        original = ET.parse(path).getroot()
        name = original.get("name")
        if name in actual:
            raise ValueError("Duplicate unit suite")
        rows = original.findall("testcase")
        actual[name] = len(rows)
        observed = {}
        unique = set()
        for row in rows:
            full = row.get("name", "")
            method = full.split("[", 1)[0]
            observed[method] = observed.get(method, 0) + 1
            method_inventory &= row.get("classname") == name and full not in unique
            unique.add(full)
        method_inventory &= observed == expected.get(name)
        clean = ET.SubElement(output, "testsuite", name=name or "unknown")
        local = dict.fromkeys(counts, 0)
        for row in rows:
            case = ET.SubElement(clean, "testcase", classname=row.get("classname", name), name=row.get("name", "unknown"))
            local["tests"] += 1
            for kind, key in [("failure", "failures"), ("error", "errors"), ("skipped", "skipped")]:
                if row.find(kind) is not None:
                    local[key] += 1
                    ET.SubElement(case, kind, message="Sensitive diagnostic omitted")
        for key, value in local.items():
            consistent &= original.get(key) is None or int(original.get(key)) == value
            clean.set(key, str(value))
            counts[key] += value
    accepted = bool(expected and set(expected) == set(actual) and method_inventory and consistent and not any(counts[k] for k in ("failures", "errors", "skipped")))
    report.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(output).write(report.with_suffix(".xml"), encoding="utf-8", xml_declaration=True)
    save(report, {**counts, "accepted": accepted, "expected_source_methods": expected, "actual_suites": actual, "source_manifest": sources(), "consistent_counts": consistent, "exact_method_inventory": method_inventory, "boundary": "All actual OTP Java units, not native scoped acceptance"})
    return 0 if accepted else 1


def method_outcomes(result):
    return {
        "failures": sum(x["status"] == "failure" for x in result.cases.values()),
        "errors": sum(x["status"] == "error" for x in result.cases.values()),
        "skipped": sum(x["status"] == "skipped" for x in result.cases.values()),
        "failure_observations": len(result.failures),
        "error_observations": len(result.errors),
        "skipped_observations": len(result.skipped),
    }


def missing(report, status):
    save(report, {"status": status, "executed": 0, "floor": 17, "failures": 0, "errors": 1, "skipped": 0, "accepted": False, "genuine_scoped_read_red": False, "genuine_scoped_app_setup_red": False, "source_manifest": sources()})
    root = ET.Element("testsuite", name="scoped-otp", tests="1", failures="0", errors="1", skipped="0")
    ET.SubElement(ET.SubElement(root, "testcase", classname="scoped-otp.fixture", name="not_executed"), "error", message=status)
    ET.ElementTree(root).write(report.with_suffix(".xml"), encoding="utf-8", xml_declaration=True)


def native(report):
    if platform.system() != "Linux" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Requires fresh Linux hosted runner")
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")))
    if available < 4 * 1024 * 1024:
        raise ValueError("Four GiB headroom and two GiB reserve required")
    jars = {key: Path(os.environ.get(key, "")) for key in ("LIFECYCLE_C_TEST_JAR", "OTP_C_TEST_JAR")}
    if not all(path.is_file() for path in jars.values()):
        raise ValueError("Both actual compiled providers required")
    hashes = {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in jars.items()}
    with zipfile.ZipFile(jars["LIFECYCLE_C_TEST_JAR"]) as lifecycle:
        if "org/oriso/keycloak/lifecycle/ScopedOtpAccess.class" not in lifecycle.namelist():
            raise ValueError("Actual installed shared scoped access class required")
    with zipfile.ZipFile(jars["OTP_C_TEST_JAR"]) as otp:
        if any(name.startswith("org/oriso/keycloak/lifecycle/") for name in otp.namelist()):
            raise ValueError("Provided shared classes must not be bundled into OTP")
    before = sources()
    import test_otp_scoped
    spec = importlib.util.spec_from_file_location("test_scenario_c_otp_permissions", MODULES[1] / "tests/test_scenario_c_otp_permissions.py")
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(test_otp_scoped.ScopedOtpRead),
        unittest.defaultTestLoader.loadTestsFromTestCase(legacy.LegacyOtpPermissions),
    ])
    if suite.countTestCases() != 17:
        raise ValueError("Exact prior15 plus foreign-email refusal and uncertain-SMTP methods required")
    original = subprocess.run

    def bounded(args, *values, **options):
        if isinstance(args, list) and args[:2] == ["docker", "run"]:
            args = args.copy()
            index = next(i for i, item in enumerate(args) if item.startswith("quay.io/keycloak/keycloak@sha256:"))
            if "--memory" not in args:
                args[index:index] = ["--memory", "1g", "--cpus", "2"]
            # Legacy keeps default-off policy, but loads the same provided dependency pair.
            lifecycle = str(jars["LIFECYCLE_C_TEST_JAR"].resolve())
            if not any(item.startswith(lifecycle + ":") for item in args):
                index = next(i for i, item in enumerate(args) if item.startswith("quay.io/keycloak/keycloak@sha256:"))
                args[index:index] = ["-v", lifecycle + ":/opt/keycloak/providers/account-lifecycle-spi.jar:ro"]
        return original(args, *values, **options)

    class Outcome(XmlResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.assertion_cases = set()
            self.failure_locations = []
        def location(self, case, error):
            frames = []
            for frame in traceback.extract_tb(error[2]):
                path = Path(frame.filename).resolve()
                if path.is_relative_to(ROOT):
                    frames.append({"path": str(path.relative_to(ROOT)), "function": frame.name,
                                   "line": frame.lineno})
            self.failure_locations.append({"case": case.id(), "exception_type": error[0].__name__,
                                           "frames": frames})
        def addFailure(self, case, error):
            self.location(case, error)
            if issubclass(error[0], AssertionError):
                self.assertion_cases.add(case.id())
            super().addFailure(case, error)
        def addError(self, case, error):
            self.location(case, error)
            super().addError(case, error)

    subprocess.run = bounded
    try:
        hidden = io.StringIO()
        with contextlib.redirect_stdout(hidden), contextlib.redirect_stderr(hidden):
            result = unittest.TextTestRunner(stream=hidden, verbosity=0, resultclass=Outcome).run(suite)
    finally:
        subprocess.run = original
    report.parent.mkdir(parents=True, exist_ok=True)
    result.write_xml(report.with_suffix(".xml"), "scoped-otp")
    failures = {case.id() for case, _ in result.failures}
    outcome_counts = method_outcomes(result)
    phases = test_otp_scoped.ScopedOtpRead.phase_receipts
    preconditions = any(x.get("case") == POSITIVE and x.get("phase") == "scoped-otp-preconditions" and all(x.get(k) is True for k in ("canonical_admin", "exact_three_audiences", "stock_native_denied", "actual_self_human", "committed_ordinary_target")) for x in phases)
    red = bool(preconditions and failures == {POSITIVE} and POSITIVE in result.assertion_cases and len(result.failures) == 1 and not result.errors and not result.skipped and result.testsRun == 17 and any(x.get("case") == POSITIVE and x.get("phase") == "scoped-otp-http" and x.get("status") == 403 and x.get("expected_status") == 200 for x in phases))
    app_preconditions = any(x.get("case") == APP_POSITIVE and x.get("phase") == "scoped-otp-app-setup-preconditions" and all(x.get(k) is True for k in ("canonical_admin", "stock_native_denied", "actual_self_human", "committed_ordinary_target", "scoped_setup_read", "frozen_current_state", "reviewed_app_selector")) for x in phases)
    app_red = bool(app_preconditions and failures == {APP_POSITIVE} and APP_POSITIVE in result.assertion_cases and len(result.failures) == 1 and not result.errors and not result.skipped and result.testsRun == 17 and any(x.get("case") == APP_POSITIVE and x.get("phase") == "scoped-otp-app-setup-http" and x.get("status") == 403 and x.get("expected_status") == 201 for x in phases))
    delete_preconditions = any(x.get("case") == DELETE_POSITIVE and x.get("phase") == "scoped-otp-delete-preconditions" and all(x.get(k) is True for k in ("canonical_admin", "stock_native_denied", "actual_self_human", "committed_ordinary_target", "actual_prior_scoped_enrollment", "frozen_current_state")) for x in phases)
    delete_red = bool(delete_preconditions and failures == {DELETE_POSITIVE} and DELETE_POSITIVE in result.assertion_cases and len(result.failures) == 1 and not result.errors and not result.skipped and result.testsRun == 17 and any(x.get("case") == DELETE_POSITIVE and x.get("phase") == "scoped-otp-delete-http" and x.get("status") == 403 and x.get("expected_status") == 200 for x in phases))
    email_finish_preconditions = any(x.get("case") == EMAIL_FINISH_POSITIVE and x.get("phase") == "scoped-otp-email-finish-preconditions" and all(x.get(k) is True for k in ("canonical_admin", "stock_native_denied", "actual_self_human", "committed_ordinary_target", "installer_owned_pending_fixture", "exact_one_inactive_native_credential", "frozen_current_state", "reviewed_email_finish_selector")) for x in phases)
    email_finish_red = bool(email_finish_preconditions and failures == {EMAIL_FINISH_POSITIVE} and EMAIL_FINISH_POSITIVE in result.assertion_cases and len(result.failures) == 1 and not result.errors and not result.skipped and result.testsRun == 17 and any(x.get("case") == EMAIL_FINISH_POSITIVE and x.get("phase") == "scoped-otp-email-finish-http" and x.get("status") == 403 and x.get("expected_status") == 201 for x in phases))
    email_start_preconditions = any(x.get("case") == EMAIL_START_POSITIVE and x.get("phase") == "scoped-otp-email-start-preconditions" and all(x.get(k) is True for k in ("canonical_admin", "exact_three_audiences", "stock_native_denied", "actual_self_human", "committed_ordinary_target", "frozen_current_state", "no_prior_otp", "real_smtp_configured", "reviewed_email_start_selector")) for x in phases)
    email_start_red = bool(email_start_preconditions and failures == {EMAIL_START_POSITIVE} and EMAIL_START_POSITIVE in result.assertion_cases and len(result.failures) == 1 and not result.errors and not result.skipped and result.testsRun == 17 and any(x.get("case") == EMAIL_START_POSITIVE and x.get("phase") == "scoped-otp-email-start-http" and x.get("status") == 403 and x.get("expected_status") == 202 for x in phases))
    stable = before == sources() and hashes == {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in jars.items()}
    accepted = bool(stable and result.wasSuccessful() and result.testsRun == 17 and not result.skipped)
    save(report, {"github_sha": os.environ.get("GITHUB_SHA"), "source_manifest": before, "source_and_jars_stable": stable, "jar_sha256": hashes, "executed": result.testsRun, "floor": 17, **outcome_counts, "failure_locations": result.failure_locations, "failed_cases": sorted(failures), "phase_receipts": phases, "genuine_scoped_read_red": red and stable, "genuine_scoped_app_setup_red": app_red and stable, "genuine_scoped_delete_red": delete_red and stable, "genuine_scoped_email_finish_red": email_finish_red and stable, "genuine_scoped_email_start_red": email_start_red and stable, "accepted": accepted, "status": "GREEN" if accepted else "SCOPED_READ403_RED" if red and stable else "SCOPED_APP_SETUP403_RED" if app_red and stable else "SCOPED_DELETE403_RED" if delete_red and stable else "SCOPED_EMAIL_FINISH403_RED" if email_finish_red and stable else "SCOPED_EMAIL_START403_RED" if email_start_red and stable else "UNVERIFIED_NOT_SCOPED_READ_RED", "boundary": "Original scopedGET5+app3+firstdelete1+emailfinish1+defaultofflegacy1+canonicalextra1+emailinvalid1+emailexpired1+foregroundemailstart1+foreignemail1+unknownSMTP1; other origins/failure fences/User/image/fullC remain open"})
    print(json.dumps({"executed": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped), "accepted": accepted, "genuine_scoped_read_red": red and stable}))
    return 0 if accepted else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["units", "native", "finalize"])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "finalize":
            if not args.report.is_file():
                missing(args.report, "EARLIER_SETUP_FAILURE_NOT_RED")
            code = 0
        else:
            code = units(args.report) if args.mode == "units" else native(args.report)
    except Exception as failure:
        missing(args.report, "SETUP_" + type(failure).__name__ + "_NOT_RED")
        code = 1
    raise SystemExit(code)
