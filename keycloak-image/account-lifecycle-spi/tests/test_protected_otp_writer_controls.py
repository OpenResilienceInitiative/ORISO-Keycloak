"""Offline controls only; cannot establish a native SMTP/locking acceptance result."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
from run_protected_otp_writer import classify_writer, WRITER_FACTS


class WriterControls(unittest.TestCase):
    def valid(self):
        facts = dict.fromkeys(WRITER_FACTS, True)
        facts["inflightWriterEvents"] = []
        for phase in ("ENTERED", "BLOCKED", "SMTP_RETURNED", "COMMITTED"):
            facts["inflightWriterEvents"].append(dict(schema=1, phase=phase,
                actualNativeWriterTransaction=True, exactPrivateSendingOrigin=True,
                runtimeH2Pinned=True, exactNativeDefaultDelegate=True,
                cancelBlockedByCapturedWriter=phase != "ENTERED", defaultSmtpReturned=phase in {"SMTP_RETURNED", "COMMITTED"},
                writerCommitted=phase == "COMMITTED", observerFailed=False))
        return {"readinessObservation": facts}

    def test_exact_actual_writer_provenance_and_all_native_phases_are_required(self):
        with patch("run_protected_otp_writer.classify", return_value="GREEN"):
            self.assertEqual("GREEN", classify_writer(self.valid()))
            for key in WRITER_FACTS:
                bad = self.valid(); bad["readinessObservation"][key] = False
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))
            for phase in ("ENTERED", "BLOCKED", "SMTP_RETURNED", "COMMITTED"):
                bad = self.valid(); bad["readinessObservation"]["inflightWriterEvents"] = [r for r in bad["readinessObservation"]["inflightWriterEvents"] if r["phase"] != phase]
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))

    def test_observer_error_and_guessed_blocker_cannot_be_acceptance(self):
        with patch("run_protected_otp_writer.classify", return_value="GREEN"):
            for key in ("actualNativeWriterTransaction", "exactPrivateSendingOrigin", "runtimeH2Pinned", "exactNativeDefaultDelegate", "cancelBlockedByCapturedWriter"):
                bad = self.valid()
                for row in bad["readinessObservation"]["inflightWriterEvents"]: row[key] = False
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))
            bad = self.valid(); bad["readinessObservation"]["inflightWriterEvents"][0]["observerFailed"] = True
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))

    def test_out_of_order_or_uncommitted_smtp_phases_are_fixture_failure(self):
        with patch("run_protected_otp_writer.classify", return_value="GREEN"):
            bad = self.valid()
            rows = bad["readinessObservation"]["inflightWriterEvents"]
            rows[1], rows[2] = rows[2], rows[1]
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))
            for index, key in ((0, "defaultSmtpReturned"), (1, "writerCommitted"),
                               (2, "defaultSmtpReturned"), (3, "writerCommitted")):
                bad = self.valid()
                rows = bad["readinessObservation"]["inflightWriterEvents"]
                rows[index][key] = not rows[index][key]
                self.assertEqual("INPUT_OR_FIXTURE_ERROR", classify_writer(bad))

    def test_fresh_wrapper_cannot_hide_actual_native_failure(self):
        with patch("run_protected_otp_writer.classify", return_value="BEHAVIOR_FAILURE"):
            self.assertEqual("BEHAVIOR_FAILURE", classify_writer(self.valid()))

    def test_installer_failure_retains_only_fixed_phase_status_and_expiry_boolean(self):
        from protected_otp_bootstrap import BootstrapFixture, BootstrapRead
        import base64
        fixture = BootstrapFixture("runTest")
        fixture.installer = "header." + base64.urlsafe_b64encode(b'{"exp":1}').decode().rstrip("=") + ".signature"
        fixture.base = "http://synthetic.invalid"
        BootstrapRead.observation = {}
        with patch("protected_otp_bootstrap.call", return_value=(401, {"private": "never-copy"})):
            with self.assertRaises(AssertionError):
                fixture.admin("PUT", "", {"smtpServer": {"password": "never-copy"}})
        self.assertEqual({"method": "PUT", "route": "REALM_CONFIGURATION", "status": 401,
                          "cachedNativeTokenExpired": True}, BootstrapRead.observation["installerAdminFailure"])
        from otp_writer_fixture import delegate_rows
        import json
        row = {"schema": 1, "phase": "CONSTRUCTED", "nativeDefaultPresent": False,
               "nativeDefaultClassExact": False}
        self.assertEqual([row], delegate_rows("ORISO_PROOF_OTP_DELEGATE_V1 " + json.dumps(row)))
        with self.assertRaises(AssertionError):
            delegate_rows("ORISO_PROOF_OTP_DELEGATE_V1 " + json.dumps(dict(row, rawError="never-copy")))

    def test_future_observation_retains_only_fixed_completion_and_http_status(self):
        from concurrent.futures import Future
        from otp_writer_fixture import future_observation
        pending = Future()
        self.assertEqual({"completed": False, "httpStatus": None}, future_observation(pending))
        pending.set_result((202, {"recipient": "never-copy", "receipt": "never-copy"}))
        self.assertEqual({"completed": True, "httpStatus": 202}, future_observation(pending))
        failed = Future()
        failed.set_exception(RuntimeError("never-copy"))
        self.assertEqual({"completed": True, "httpStatus": None}, future_observation(failed))

    def test_wait_observation_cannot_copy_sql_or_subject_and_has_closed_bounds(self):
        from otp_writer_fixture import wait_rows
        import json
        row = dict(schema=1, rowCount=1, nativeBlockedState=True, capturedBlockerMatches=True,
                   otherSession=True, realmTable=True, forUpdate=True, realmParameterSuffix=True,
                   exactOriginalGrammar=False)
        self.assertEqual([row], wait_rows("ORISO_PROOF_OTP_WAIT_V1 " + json.dumps(row)))
        with self.assertRaises(AssertionError):
            wait_rows("ORISO_PROOF_OTP_WAIT_V1 " + json.dumps(dict(row, statement="never-copy")))
        with self.assertRaises(AssertionError):
            wait_rows("ORISO_PROOF_OTP_WAIT_V1 " + json.dumps(dict(row, rowCount=1001)))

    def test_companion_remains_outside_product_and_delegates_native_smtp(self):
        tests = Path(__file__).parent
        source = (tests / "native-otp-writer-fixture/src/org/oriso/keycloak/lifecycle/proof/OtpWriterFixtureFactory.java").read_text()
        self.assertIn('new DefaultEmailSenderProviderFactory()', source)
        self.assertIn('nativeFactory.init(scope)', source)
        self.assertIn('nativeFactory.create(session)', source)
        self.assertIn('public void close() { delegate.close(); }', source)
        self.assertIn('org.keycloak.email.DefaultEmailSenderProvider', source)
        self.assertIn('select SESSION_ID()', source)
        self.assertIn('where BLOCKER_ID=:writer', source)
        self.assertIn('delegate.send(config, user, subject, text, html)', source)
        self.assertNotIn('setParameter("writer", witness.realm)', source)
        product = tests.parent / "src/main/resources/META-INF/services"
        self.assertFalse((product / "org.keycloak.email.EmailSenderProviderFactory").exists())
        workflow = (tests.parents[2] / ".github/workflows/scenario-c-protected-otp-writer-proof.yml").read_text()
        self.assertIn('contents: read', workflow)
        self.assertIn('"$RUNNER_TEMP/oriso-proof-otp-writer-companion.jar"', workflow)
        self.assertNotIn('continue-on-error', workflow)
        builder = (tests / "build_otp_writer_companion.py").read_text()
        self.assertIn('META-INF/services/org.keycloak.email.EmailSenderProviderFactory', builder)
        self.assertNotIn('META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory', builder)


if __name__ == "__main__":
    unittest.main()
