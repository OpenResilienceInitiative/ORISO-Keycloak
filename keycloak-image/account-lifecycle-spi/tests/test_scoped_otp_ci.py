"""No JVM/native fixtures: reject missing, skipped and inconsistent unit evidence."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location(
    "scoped_otp_proof", Path(__file__).with_name("run_scoped_otp.py")
)


class ScopedOtpEvidenceTest(unittest.TestCase):
    def gate(self, *, missing=False, skipped=False, mismatch=False, extra=False, failure=False, duplicate=False, foreign_class=False):
        proof = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(proof)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            otp = root / "otp"
            source = otp / "src/test/java"
            source.mkdir(parents=True)
            (source / "OnlyTest.java").write_text(
                "package fixture; class OnlyTest { @Test public void exact() {} }"
            )
            reports = otp / "target/surefire-reports"
            reports.mkdir(parents=True)
            if not missing:
                suite = ET.Element("testsuite", name="fixture.OnlyTest", tests="99" if mismatch else "1")
                case = ET.SubElement(suite, "testcase", classname="fixture.OnlyTest", name="exact")
                if duplicate:
                    ET.SubElement(suite, "testcase", classname="fixture.OnlyTest", name="exact")
                if foreign_class:
                    case.set("classname", "foreign.Class")
                if skipped:
                    ET.SubElement(case, "skipped")
                if failure:
                    ET.SubElement(case, "failure", message="sensitive-token").text = "password"
                ET.ElementTree(suite).write(reports / "TEST-fixture.xml")
                if extra:
                    suite.set("name", "unreviewed.OtherTest")
                    ET.ElementTree(suite).write(reports / "TEST-extra.xml")
            proof.ROOT, proof.MODULES = root, [root / "lifecycle", otp]
            proof.WORKFLOW = root / "workflow.yml"
            proof.WORKFLOW.write_text("permissions: {contents: read}\n")
            path = root / "evidence/result.json"
            code = proof.units(path)
            result = json.loads(path.read_text())
            xml = path.with_suffix(".xml").read_text()
            return code, result, xml

    def test_method_failures_and_cleanup_observations_are_both_preserved(self):
        from types import SimpleNamespace
        proof = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(proof)
        actual = SimpleNamespace(cases={"first": {"status": "failure"}, "second": {"status": "failure"},
                                       "third": {"status": "success"}},
                                 failures=[1, 2, 3], errors=[], skipped=[])
        result = proof.method_outcomes(actual)
        self.assertEqual(2, result["failures"])
        self.assertEqual(3, result["failure_observations"])
        self.assertEqual(0, result["errors"])

    def test_completion_fixture_requires_its_exact_class_and_registration_without_product_classes(self):
        proof = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(proof)
        exact = ["META-INF/", "META-INF/MANIFEST.MF", "META-INF/beans.xml",
                 "org/oriso/keycloak/lifecycle/ScopedOtpReadyCompletionFixture.class"]
        proof.validate_ready_fixture_entries(exact)
        for entries in [[], exact[:-1], exact + [exact[-1]],
                        exact + ["org/oriso/keycloak/lifecycle/ScopedOtpAccess.class"]]:
            with self.assertRaises(ValueError):
                proof.validate_ready_fixture_entries(entries)

    def test_actual_source_suite_passes(self):
        code, result, _ = self.gate()
        self.assertEqual(0, code)
        self.assertTrue(result["accepted"])
        self.assertEqual(1, result["tests"])

    def test_missing_fixture_cannot_pass(self):
        self.assertEqual(1, self.gate(missing=True)[0])

    def test_skipped_case_cannot_pass(self):
        self.assertEqual(1, self.gate(skipped=True)[0])

    def test_declared_count_mismatch_cannot_pass(self):
        self.assertEqual(1, self.gate(mismatch=True)[0])

    def test_unreviewed_suite_cannot_replace_inventory(self):
        self.assertEqual(1, self.gate(extra=True)[0])

    def test_failed_case_remains_failed_without_sensitive_diagnostics(self):
        code, result, xml = self.gate(failure=True)
        self.assertEqual(1, code)
        self.assertEqual(1, result["failures"])
        self.assertNotIn("sensitive-token", xml)
        self.assertNotIn("password", xml)

    def test_duplicate_method_cannot_replace_inventory(self):
        self.assertEqual(1, self.gate(duplicate=True)[0])

    def test_foreign_class_cannot_supply_the_expected_method(self):
        self.assertEqual(1, self.gate(foreign_class=True)[0])

    def test_protected_read_red_requires_real_committed_peer_and_separate_operation_grant(self):
        from protected_account_operations import classify
        required = ('actualNativeCommitAndConsumedApprovalVerified', 'actualPeerTokenIssuerClientAudienceAndGrantsVerified',
                    'actualPeerUserinfoAndCurrentSessionVerified', 'sameRuntimeWithoutPerPersonBindingOrRestartVerified',
                    'canonicalAdminThreeAudiencesAndNative403', 'explicitSeparateSelfOperationGrantInstalled')
        value = dict.fromkeys(required, True)
        value['protectedSelfOtpReadStatus'] = 403
        self.assertEqual('GENUINE_PROTECTED_SELF_OTP_READ403_RED', classify(value))
        for key in required:
            self.assertEqual('INPUT_OR_FIXTURE_ERROR', classify(dict(value, **{key: False})))
        value['protectedSelfOtpReadStatus'] = 200
        self.assertEqual('BEHAVIOR_FAILURE', classify(value))
        read = dict(value, closedOriginalOtpSetupResultVerified=True)
        self.assertEqual('GENUINE_PROTECTED_SELF_MAINTENANCE_READ403_RED',
                         classify(dict(read, protectedSelfMaintenanceReadStatus=403)))
        self.assertEqual('BEHAVIOR_FAILURE', classify(dict(read, protectedSelfMaintenanceReadStatus=200)))
        app = dict(read, protectedSelfMaintenanceReadStatus=200,
                   closedProtectedCurrentStateVerified=True,
                   newPlatformCommittedConsumedNative0AndRealSessionVerified=True,
                   newPlatformExplicitRootSelfGrantWithoutPersonBindingVerified=True,
                   newPlatformSelfOriginalReadAndStateVerified=True,
                   protectedAppCurrentStateAndOriginalSetupSecretVerified=True)
        self.assertEqual('GENUINE_NEW_PLATFORM_SELF_OTP_READ403_RED', classify(dict(app, newPlatformSelfOtpReadStatus=403)))
        self.assertEqual('INPUT_OR_FIXTURE_ERROR', classify(dict(app, newPlatformExplicitRootSelfGrantWithoutPersonBindingVerified=False)))
        self.assertEqual('INPUT_OR_FIXTURE_ERROR', classify(dict(app,
                         protectedAppCurrentStateAndOriginalSetupSecretVerified=False)))
        self.assertEqual('GENUINE_PROTECTED_SELF_OTP_APP403_RED', classify(dict(app, protectedSelfAppSetupStatus=403)))
        self.assertEqual('GREEN', classify(dict(app, protectedSelfAppSetupStatus=201,
                                               protectedSelfAppNativeEffectAndExactRetryVerified=True)))
