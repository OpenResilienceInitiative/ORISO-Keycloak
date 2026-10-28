#!/usr/bin/env python3
"""Strict hosted M1 diagnostic gate; sanitized evidence never changes a failed exit."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

from run_native import XmlResult

EXPECTED_UNITS = {
    "org.oriso.keycloak.lifecycle.LifecycleJsonTest": 13,
    "org.oriso.keycloak.lifecycle.MaintenanceRequestTest": 21,
    "org.oriso.keycloak.lifecycle.GeneralPolicyTest": 8,
    "org.oriso.keycloak.lifecycle.ScopedOtpRequestTest": 11,
    "org.oriso.keycloak.lifecycle.ProtectedPeerPolicyTest": 12,
    "org.oriso.keycloak.lifecycle.InstallationStatusTest": 2,
    "org.oriso.keycloak.lifecycle.OriginalNativeBirthTest": 2,
    "org.oriso.keycloak.lifecycle.MaintenanceRoleChangeTest": 4,
    "org.oriso.keycloak.lifecycle.AdminAccountDeletionTest": 2,
}
NATIVE_FLOOR = 9


def source_manifest(module):
    return {
        str(path.relative_to(module)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(module.rglob("*"))
        if path.is_file() and "target" not in path.parts
        and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sanitize_units(reports, destination):
    """Keep every method outcome; drop properties, tracebacks, messages and all output."""
    root = ET.Element("testsuites")
    actual = {}
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    consistent_counts = True
    case_ids = set()
    unique_cases = True
    for path in sorted(reports.glob("TEST-*.xml")):
        original = ET.parse(path).getroot()
        name = original.get("name", "")
        if name in actual:
            raise ValueError("Duplicate unit suite")
        cases = original.findall("testcase")
        actual[name] = len(cases)
        suite = ET.SubElement(root, "testsuite", name=name)
        suite_counts = {key: 0 for key in counts}
        for case in cases:
            case_id = (case.get("classname", name), case.get("name", ""))
            if case_id in case_ids:
                unique_cases = False
            case_ids.add(case_id)
            clean = ET.SubElement(suite, "testcase", classname=case.get("classname", name),
                                  name=case.get("name", ""), time=case.get("time", "0"))
            suite_counts["tests"] += 1
            for kind in ("failure", "error", "skipped"):
                if case.find(kind) is not None:
                    suite_counts[{"failure": "failures", "error": "errors", "skipped": "skipped"}[kind]] += 1
                    ET.SubElement(clean, kind, message="Unit outcome did not pass; sensitive diagnostics omitted")
        for key, value in suite_counts.items():
            if original.get(key) is not None and int(original.get(key)) != value:
                consistent_counts = False
            suite.set(key, str(value))
            counts[key] += value
    destination.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(destination, encoding="utf-8", xml_declaration=True)
    accepted = consistent_counts and unique_cases and actual == EXPECTED_UNITS and counts["tests"] == 75 and not any(
        counts[key] for key in ("failures", "errors", "skipped"))
    return {"suite_counts": actual, **counts, "required_suites": EXPECTED_UNITS,
            "required_total": 75, "consistent_declared_counts": consistent_counts,
            "unique_cases": unique_cases, "accepted": accepted,
            "diagnostic_boundary": "Java schema units only; not native maintenance acceptance"}


def missing_native(report, reason):
    module_root = Path(__file__).resolve().parent.parent
    workflow = module_root.parents[1] / ".github/workflows/scenario-c-maintenance-proof.yml"
    summary = {"suite": "maintenance", "status": reason, "discovered": 0, "executed": 0,
               "floor": NATIVE_FLOOR, "failures": 0, "errors": 1, "skipped": 0,
               "accepted": False, "genuine_read_red": False, "genuine_delete_red": False,
               "source_manifest": source_manifest(module_root),
               "workflow_sha256": hashlib.sha256(workflow.read_bytes()).hexdigest() if workflow.is_file() else None,
               "github_sha": os.environ.get("GITHUB_SHA"), "jar_sha256": None}
    write_json(report, summary)
    suite = ET.Element("testsuite", name="maintenance", tests="0", failures="0", errors="1", skipped="0")
    case = ET.SubElement(suite, "testcase", classname="maintenance.fixture", name="native_not_executed")
    suite.set("tests", "1")
    ET.SubElement(case, "error", message=reason)
    ET.ElementTree(suite).write(report.with_suffix(".xml"), encoding="utf-8", xml_declaration=True)
    return summary


def native(report, workflow):
    module_root = Path(__file__).resolve().parent.parent
    jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
    if not jar.is_file() or not workflow.is_file():
        missing_native(report, "MISSING_ACTUAL_JAR_OR_WORKFLOW_NOT_BEHAVIOR_RED")
        return 1
    before = source_manifest(module_root)
    jar_before = hashlib.sha256(jar.read_bytes()).hexdigest()
    workflow_before = hashlib.sha256(workflow.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("test_maintenance", module_root / "tests/test_maintenance.py")
    imported = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imported)
    suite = unittest.defaultTestLoader.loadTestsFromModule(imported)
    discovered = suite.countTestCases()
    if discovered < NATIVE_FLOOR:
        missing_native(report, "BELOW_REQUIRED_CASE_FLOOR_NOT_BEHAVIOR_RED")
        return 1
    result = unittest.TextTestRunner(verbosity=2, resultclass=XmlResult).run(suite)
    report.parent.mkdir(parents=True, exist_ok=True)
    result.write_xml(report.with_suffix(".xml"), "maintenance")
    phases = imported.MaintenancePermissions.phase_receipts + imported.HumanMaintenance.phase_receipts
    committed = {item["case"] for item in phases if item["phase"] == "ordinary-committed"}
    requests = [item for item in phases if item["phase"] == "maintenance-http"]
    stock_denials = [item for item in phases if item["phase"] == "stock-native-denied"]
    failures = {case.id() for case, _ in result.failures}
    denial_operations = {"read", "profile", "password", "roles", "membership", "delete"}
    verified_denial_cases = {
        case for case in committed if {
            item["operation"] for item in stock_denials
            if item["case"] == case and item["status"] == 403
        } == denial_operations
    }
    def red(command):
        return any(item["command"] == command and item["actor"] == "ACCOUNT_ADMIN"
                   and item["expected_status"] == 200 and item["status"] == 404
                   and item["case"] in committed and item["case"] in failures for item in requests)
    native_humans = {item["case"] for item in phases if item["phase"] == "human-native-preconditions"
                     and all(item.get(key) is True for key in ["exact_subject", "exact_issuer", "exact_client", "current_tenant", "current_roles", "live_session"])}
    human_requests = [item for item in phases if item["phase"] == "human-maintenance-http"]
    human_read_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures and item["command"] == "read"
        and item["expected_status"] == 200 and item["status"] in {403, 404} for item in human_requests)
    human_locale_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures and item["command"] == "locale"
        and item["expected_status"] == 200 and item["status"] == 404 for item in human_requests)
    human_profile_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures and item["command"] == "profile"
        and item["expected_status"] == 200 and item["status"] == 404 for item in human_requests)
    password_preconditions = {item["case"] for item in phases
        if item["phase"] == "human-password-proof-preconditions"
        and all(item.get(key) is True for key in ("original_password_verified", "exact_self_read", "current_native_session"))}
    human_password_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures & password_preconditions
        and item["command"] == "password" and item["expected_status"] == 200
        and item["status"] == 404 for item in human_requests)
    self_password_preconditions = {item["case"] for item in phases
        if item["phase"] == "human-self-password-proof-preconditions"
        and all(item.get(key) is True for key in ("original_password_verified", "exact_self_read",
            "current_native_session", "existing_public_form_requires_old_password"))}
    human_self_password_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures & self_password_preconditions
        and item["command"] == "self-password" and item["expected_status"] == 200
        and item["status"] == 404 for item in human_requests)
    deadline_preconditions = {item["case"] for item in phases
        if item["phase"] == "human-password-deadline-preconditions"
        and all(item.get(key) is True for key in ("original_password_verified", "exact_self_read",
            "current_native_session", "original_deadline_still_future"))}
    human_password_deadline_red = not result.errors and not result.skipped and any(
        item["case"] in native_humans & committed & failures & deadline_preconditions
        and item["phase"] == "human-password-deadline-positive-reply"
        and item["status"] == 400 and item.get("original_deadline_still_future") is True for item in phases)
    availability_case = "test_maintenance.MaintenancePermissions.test_creator_exact_username_availability_exposes_only_a_boolean"
    availability_preconditions = any(item.get("case") == availability_case
        and item.get("phase") == "username-availability-preconditions"
        and all(item.get(key) is True for key in ("canonical_creator", "exact_two_audiences",
            "stock_native_denied", "exact_committed_native_username")) for item in phases)
    availability_red = bool(availability_preconditions and failures == {availability_case}
        and len(result.failures) == 1 and not result.errors and not result.skipped
        and result.testsRun == NATIVE_FLOOR and any(item.get("case") == availability_case
            and item.get("phase") == "username-availability-http"
            and item.get("actor") == "ACCOUNT_CREATE" and item.get("status") == 404 for item in phases))
    after = source_manifest(module_root)
    summary = {
        "suite": "maintenance", "floor": NATIVE_FLOOR, "discovered": discovered,
        "executed": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "failed_case_ids": sorted(failures),
        "error_case_ids": [case.id() for case, _ in result.errors],
        "jar_sha256": jar_before, "jar_stable": jar_before == hashlib.sha256(jar.read_bytes()).hexdigest(),
        "source_manifest": before, "source_stable": before == after,
        "workflow_sha256": workflow_before,
        "workflow_stable": workflow_before == hashlib.sha256(workflow.read_bytes()).hexdigest(),
        "github_sha": os.environ.get("GITHUB_SHA"), "python": sys.version.split()[0],
        "keycloak_image": imported.IMAGE if hasattr(imported, "IMAGE") else __import__("lifecycle_fixture").IMAGE,
        "phase_receipts": phases, "stock_native_denials": stock_denials,
        "same_bearer_stock_denial_cases": sorted(verified_denial_cases),
        "genuine_read_red": red("read"), "genuine_delete_red": red("delete"),
        "genuine_human_read_red": bool(human_read_red), "genuine_human_locale_red": bool(human_locale_red),
        "genuine_username_availability_red": availability_red,
        "genuine_human_profile_red": bool(human_profile_red),
        "genuine_human_self_password_red": bool(human_self_password_red),
        "genuine_human_password_deadline_red": bool(human_password_deadline_red),
        "genuine_human_password_red": bool(human_password_red),
        "diagnostic_boundary": "Receiver bounded read/delete and first native human locale diagnostic; domain caller, OTP, MariaDB and full Scenario C remain open",
    }
    summary["accepted"] = bool(result.wasSuccessful() and result.testsRun == discovered
        and not result.skipped and summary["jar_stable"] and summary["source_stable"] and summary["workflow_stable"])
    summary["status"] = "GREEN" if summary["accepted"] else (
        "BEHAVIOR_RED" if summary["genuine_read_red"] or summary["genuine_delete_red"] or human_read_red or human_locale_red or availability_red or human_profile_red or human_password_red or human_self_password_red or human_password_deadline_red
        else "FAILED_WITHOUT_CONFIRMED_READ_OR_DELETE_RED")
    write_json(report, summary)
    print(json.dumps({key: value for key, value in summary.items() if key != "source_manifest"}, sort_keys=True))
    return 0 if summary["accepted"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["units", "native", "finalize"])
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--workflow", type=Path)
    args = parser.parse_args()
    if args.mode == "units":
        module = Path(__file__).resolve().parent.parent
        summary = sanitize_units(module / "target/surefire-reports", args.report.with_suffix(".xml"))
        summary["source_manifest"] = source_manifest(module)
        write_json(args.report, summary)
        print(json.dumps({k: v for k, v in summary.items() if k != "source_manifest"}, sort_keys=True))
        return 0 if summary["accepted"] else 1
    if args.mode == "finalize":
        if not args.report.is_file():
            missing_native(args.report, "NOT_EXECUTED_AFTER_EARLIER_STEP_FAILURE_NOT_BEHAVIOR_RED")
        return 0
    if args.workflow is None:
        parser.error("Native mode requires the actual source workflow")
    try:
        return native(args.report, args.workflow)
    except Exception as failure:
        # Never serialize a native exception, HTTP body, command, proof or credential.
        missing_native(args.report, "UNCONFIRMED_RUNNER_EXCEPTION_" + type(failure).__name__)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
