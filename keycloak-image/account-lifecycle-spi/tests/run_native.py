#!/usr/bin/env python3
"""Strict finite native gate: actual JAR, case floor, and zero skipped cases."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
import time
import xml.etree.ElementTree as ET


class XmlResult(unittest.TextTestResult):
    """Retain complete per-method outcomes without response or exception data."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = {}

    def startTest(self, test):
        self.cases[test.id()] = {"started": time.monotonic(), "status": "success"}
        super().startTest(test)

    def stopTest(self, test):
        self.cases[test.id()]["elapsed"] = (
            time.monotonic() - self.cases[test.id()]["started"]
        )
        super().stopTest(test)

    def addFailure(self, test, err):
        self.cases[test.id()]["status"] = "failure"
        super().addFailure(test, err)

    def addError(self, test, err):
        self.cases.setdefault(test.id(), {"started": time.monotonic()})[
            "status"
        ] = "error"
        super().addError(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.cases[test.id()]["status"] = (
                "failure" if issubclass(err[0], test.failureException) else "error"
            )
        super().addSubTest(test, subtest, err)

    def addSkip(self, test, reason):
        self.cases.setdefault(test.id(), {"started": time.monotonic()})[
            "status"
        ] = "skipped"
        super().addSkip(test, reason)

    def write_xml(self, path, name):
        cases = getattr(self, "cases", {})
        counts = {
            key: sum(item["status"] == key for item in cases.values())
            for key in ("failure", "error", "skipped")
        }
        suite = ET.Element(
            "testsuite",
            name=name,
            tests=str(len(cases)),
            failures=str(counts["failure"]),
            errors=str(counts["error"]),
            skipped=str(counts["skipped"]),
        )
        for identifier, item in cases.items():
            classname, _, method = identifier.rpartition(".")
            case = ET.SubElement(
                suite,
                "testcase",
                classname=classname,
                name=method,
                time=f"{item.get('elapsed', 0):.6f}",
            )
            if item["status"] != "success":
                ET.SubElement(
                    case,
                    item["status"],
                    message="Native gate did not pass; inspect protected local execution log",
                )
        ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", choices=["lifecycle", "mariadb"])
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
    if not jar.is_file():
        raise SystemExit("Existing actual provider JAR required")
    root = Path(__file__).resolve().parent
    name = "test_lifecycle" if args.suite == "lifecycle" else "test_lifecycle_mariadb"
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    initial_jar_hash = hashlib.sha256(jar.read_bytes()).hexdigest()
    source_root = root.parent
    source_before = {
        str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in source_root.rglob("*")
        if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts
    }
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    discovered = suite.countTestCases()
    floor = 38 if args.suite == "lifecycle" else 9
    if discovered < floor:
        raise SystemExit("Native case inventory below required floor")
    result = unittest.TextTestRunner(verbosity=2, resultclass=XmlResult).run(suite)
    result.write_xml(Path(args.report).with_suffix(".xml"), args.suite)
    final_jar_hash = hashlib.sha256(jar.read_bytes()).hexdigest()
    source_after = {
        str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in source_root.rglob("*")
        if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts
    }
    summary = {
        "lock_wait_receipts": getattr(
            getattr(module, "MariaDbLifecycleProof", None), "lock_wait_receipts", []
        ),
        "driver_latches": getattr(
            getattr(module, "MariaDbLifecycleProof", None), "driver_latches", []
        ),
        "jar_stable": initial_jar_hash == final_jar_hash,
        "source_stable": source_before == source_after,
        "source_manifest": source_before,
        "suite": args.suite,
        "python": sys.version.split()[0],
        "discovered": discovered,
        "executed": result.testsRun,
        "floor": floor,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "failed_case_ids": [case.id() for case, _ in result.failures],
        "error_case_ids": [case.id() for case, _ in result.errors],
        "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
        "source_hashes": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [
                root / (name + ".py"),
                root / "lifecycle_fixture.py",
                root / "mariadb_fixture.py",
            ]
        },
    }
    Path(args.report).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return not (
        result.wasSuccessful()
        and result.testsRun == discovered
        and not result.skipped
        and summary["jar_stable"]
        and summary["source_stable"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
