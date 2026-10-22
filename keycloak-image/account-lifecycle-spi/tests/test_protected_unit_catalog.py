"""Synthetic evidence controls only; no JVM or native resource is started."""

from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from run_maintenance import EXPECTED_UNITS
from run_protected import unit_evidence


class ProtectedUnitCatalog(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, count in EXPECTED_UNITS.items():
            suite = ET.Element(
                "testsuite", name=name, tests=str(count), failures="0", errors="0", skipped="0"
            )
            for index in range(count):
                ET.SubElement(suite, "testcase", classname=name, name=f"case{index}")
            ET.ElementTree(suite).write(self.root / f"TEST-{name}.xml")

    def test_all_composed_units_are_required_and_accepted(self):
        self.assertEqual(46, unit_evidence(self.root)["totals"]["tests"])

    def test_missing_peer_suite_cannot_pass_the_composed_catalogue(self):
        path = self.root / "TEST-org.oriso.keycloak.lifecycle.ProtectedPeerPolicyTest.xml"
        if path.exists():
            path.unlink()
        with self.assertRaises(AssertionError):
            unit_evidence(self.root)

    def test_missing_maintenance_suite_cannot_leave_only_old_thirteen(self):
        for name in EXPECTED_UNITS:
            if not name.endswith("LifecycleJsonTest"):
                (self.root / f"TEST-{name}.xml").unlink()
        with self.assertRaises(AssertionError):
            unit_evidence(self.root)

    def test_failed_skipped_or_inconsistent_suite_cannot_pass(self):
        for outcome in ("failure", "skipped", "inconsistent"):
            with self.subTest(outcome=outcome):
                path = next(self.root.glob("TEST-*.xml"))
                original = path.read_bytes()
                suite = ET.fromstring(original)
                if outcome == "inconsistent":
                    suite.set("tests", "999")
                else:
                    ET.SubElement(suite.find("testcase"), outcome)
                ET.ElementTree(suite).write(path)
                with self.assertRaises(AssertionError):
                    unit_evidence(self.root)
                path.write_bytes(original)

    def test_extra_or_duplicate_suite_cannot_replace_required_sources(self):
        path = next(self.root.glob("TEST-*.xml"))
        (self.root / "TEST-extra.xml").write_bytes(path.read_bytes())
        with self.assertRaises((ValueError, AssertionError)):
            unit_evidence(self.root)


if __name__ == "__main__":
    unittest.main()
