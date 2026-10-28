#!/usr/bin/env python3
"""Offline evidence-gate tests. Never starts Java, Docker or a native fixture."""
import ast
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from run_maintenance import EXPECTED_UNITS, missing_native, sanitize_units, source_manifest


class MaintenanceEvidenceGate(unittest.TestCase):
    def test_existing_consultant_profile_is_the_default_native_human_fixture(self):
        from maintenance_human_fixture import HumanMaintenanceFixture
        self.assertEqual(
            {"kind": "CONSULTANT", "group": "consultant", "roles": ["consultant", "group-chat-consultant"], "id": "consultant-v1"},
            HumanMaintenanceFixture.reviewed_human_profile(),
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = self.root / "raw"
        self.reports.mkdir()

    def units(self, skipped=False, error=False):
        for name, count in EXPECTED_UNITS.items():
            suite = ET.Element("testsuite", name=name)
            ET.SubElement(suite, "properties").text = "private-do-not-copy"
            ET.SubElement(suite, "system-out").text = "private-do-not-copy"
            for index in range(count):
                case = ET.SubElement(suite, "testcase", classname=name, name="case_" + str(index), time="0.001")
                if index == 0 and skipped:
                    ET.SubElement(case, "skipped", message="private-do-not-copy")
                if index == 0 and error:
                    ET.SubElement(case, "error", message="private-do-not-copy").text = "private-do-not-copy"
            ET.ElementTree(suite).write(self.reports / ("TEST-" + name + ".xml"))

    def test_exact_composed_forty_seven_successes_are_required(self):
        self.units()
        result = sanitize_units(self.reports, self.root / "safe.xml")
        self.assertTrue(result["accepted"])
        self.assertEqual(75, result["tests"])

    def test_missing_reports_cannot_pass(self):
        self.assertFalse(sanitize_units(self.reports, self.root / "safe.xml")["accepted"])

    def test_one_skipped_method_refuses_the_gate(self):
        self.units(skipped=True)
        result = sanitize_units(self.reports, self.root / "safe.xml")
        self.assertFalse(result["accepted"])
        self.assertGreater(result["skipped"], 0)

    def test_failure_diagnostics_properties_and_output_are_not_published(self):
        self.units(error=True)
        result = sanitize_units(self.reports, self.root / "safe.xml")
        self.assertFalse(result["accepted"])
        self.assertNotIn("private-do-not-copy", (self.root / "safe.xml").read_text())
        self.assertEqual(75, len(ET.parse(self.root / "safe.xml").findall(".//testcase")))

    def test_suite_counters_cannot_hide_a_failure_without_a_method_node(self):
        self.units()
        report = next(self.reports.glob("TEST-*.xml"))
        tree = ET.parse(report)
        tree.getroot().set("errors", "1")
        tree.write(report)
        result = sanitize_units(self.reports, self.root / "safe.xml")
        self.assertFalse(result["accepted"])
        self.assertFalse(result["consistent_declared_counts"])

    def test_duplicate_suite_cannot_replace_the_expected_count(self):
        self.units()
        source = self.reports / ("TEST-" + next(iter(EXPECTED_UNITS)) + ".xml")
        (self.reports / "TEST-duplicate.xml").write_bytes(source.read_bytes())
        with self.assertRaises(ValueError):
            sanitize_units(self.reports, self.root / "safe.xml")

    def test_duplicate_method_cannot_replace_a_required_case(self):
        self.units()
        report = next(self.reports.glob("TEST-*.xml"))
        tree = ET.parse(report)
        cases = tree.getroot().findall("testcase")
        cases[1].set("name", cases[0].get("name"))
        tree.write(report)
        self.assertFalse(sanitize_units(self.reports, self.root / "safe.xml")["accepted"])

    def test_native_source_contains_all_six_prepared_methods(self):
        tree = ast.parse(Path(__file__).with_name("test_maintenance.py").read_text())
        methods = [item for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "MaintenancePermissions" for item in node.body
                   if isinstance(item, ast.FunctionDef) and item.name.startswith("test_")]
        self.assertEqual(6, len(methods))

    def test_binding_drift_requires_actual_exit_source_and_unchanged_native_runtime(self):
        from maintenance_readiness import classify
        base = {"validHumanReadStatus": 200, "reviewedUnusedProfileInstalled": True,
                "exactUnusedGroupNameOnlyDrift": True, "primaryHumanAndOrdinaryMappingUnchanged": True,
                "sameJarImageConfigVolumeAndCaps": True, "bindingValidationSourceWitness": True,
                "nativeExitedNonzeroWithoutOom": True, "driftHumanLoginStatus": 0}
        self.assertEqual("GENUINE_HUMAN_BINDING_ABORTS_NATIVE_LOGIN_RED", classify(base))
        for key in ("reviewedUnusedProfileInstalled", "exactUnusedGroupNameOnlyDrift",
                    "primaryHumanAndOrdinaryMappingUnchanged", "sameJarImageConfigVolumeAndCaps",
                    "bindingValidationSourceWitness", "nativeExitedNonzeroWithoutOom"):
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify(dict(base, **{key: False})))
        self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify({}))
        green = dict(base, nativeExitedNonzeroWithoutOom=False, bindingValidationSourceWitness=False,
                     driftHumanLoginStatus=200, selfStatus=503, otpStatus=503,
                     bothUnavailableNoStore=True, ordinaryMachineCreationReadDeleteVerified=True,
                     wrongActorAndProofDeniedBeforeReadiness=True, exactNativeBindingCorrectionVerified=True,
                     correctedBeforeRestartSelfStatus=503, correctedBeforeRestartOtpStatus=503,
                     correctedRestartHumanLoginStatus=200, correctedRestartSelfStatus=200,
                     correctedRestartOtpStatus=200, fourthBootSameImageJarConfigVolumeAndCaps=True)
        self.assertEqual("GREEN", classify(green))
        self.assertEqual("BEHAVIOR_FAILURE", classify(dict(green, bothUnavailableNoStore=False)))
        self.assertEqual("BEHAVIOR_FAILURE", classify(dict(green, ordinaryMachineCreationReadDeleteVerified=False)))
        for key in ("exactNativeBindingCorrectionVerified", "fourthBootSameImageJarConfigVolumeAndCaps"):
            self.assertEqual("BEHAVIOR_FAILURE", classify(dict(green, **{key: False})))
        self.assertEqual("BEHAVIOR_FAILURE", classify(dict(green, correctedBeforeRestartSelfStatus=200)))
        self.assertEqual("BEHAVIOR_FAILURE", classify(dict(green, correctedRestartSelfStatus=503)))

    def test_native_mount_identity_ignores_docker_listing_order_but_preserves_ownership(self):
        from maintenance_readiness import mounts
        first = [{"Type": "bind", "Source": "/actual/provider.jar", "Destination": "/providers/a.jar", "RW": False},
                 {"Type": "volume", "Name": "owned-volume", "Source": "/actual/owned", "Destination": "/data", "RW": True}]
        self.assertEqual(mounts(first), mounts(list(reversed(first))))
        changed = [dict(first[0], Source="/foreign/provider.jar"), first[1]]
        self.assertNotEqual(mounts(first), mounts(changed))
        self.assertNotEqual(mounts(first), mounts([dict(first[0], RW=True), first[1]]))

    def test_manifests_exclude_compiled_outputs_but_bind_real_source(self):
        (self.root / "target").mkdir()
        (self.root / "target/private.jar").write_bytes(b"compiled")
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__/private.pyc").write_bytes(b"compiled")
        (self.root / "Source.java").write_text("public class Source {}")
        self.assertEqual({"Source.java"}, set(source_manifest(self.root)))

    def test_unexecuted_native_gate_is_an_explicit_error(self):
        report = self.root / "maintenance-native.json"
        result = missing_native(report, "MISSING_FIXTURE_NOT_BEHAVIOR_RED")
        self.assertFalse(result["accepted"])
        self.assertFalse(result["genuine_read_red"])
        self.assertEqual(0, result["executed"])
        self.assertEqual(1, result["errors"])
        self.assertEqual("1", ET.parse(report.with_suffix(".xml")).getroot().get("errors"))


if __name__ == "__main__":
    unittest.main()
