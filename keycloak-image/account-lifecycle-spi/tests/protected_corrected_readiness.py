"""A corrected native binding is published only after a new successful restart."""

import copy
import subprocess
import time
import uuid
from urllib.error import URLError

from lifecycle_fixture import IMAGE
from protected_binding_readiness import (
    BindingReadiness,
    NativeFixture,
    config_values,
    inspect_owned,
    request,
)
from protected_resources import require_active


class CorrectedReadiness(BindingReadiness):
    def test_corrected_binding_restart_restores_native_human_approval(self):
        # Execute every existing drift, native login and unavailable assertion.
        self.test_binding_drift_keeps_native_login_and_protected_unavailable()
        o = self.observation
        helper = NativeFixture("runTest")
        baseline = inspect_owned()
        configuration = config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"]
        before_count = helper.admin("GET", "/users/count")
        realm_before = helper.admin("GET")
        human_path = "/users/" + NativeFixture.human_subject
        human_before = helper.admin("GET", human_path)
        path = "/groups/" + NativeFixture.protected_group_id
        drifted = helper.admin("GET", path)
        self.assertEqual("platform-admins-binding-drift", drifted["name"])
        roles_before = helper.admin("GET", path + "/role-mappings")
        correction = copy.deepcopy(drifted)
        correction["name"] = "platform-admins"
        helper.admin("PUT", path, correction)
        corrected = helper.admin("GET", path)
        self.assertEqual("/protected-admins/platform-admins", corrected["path"])
        self.assertEqual(
            {k: v for k, v in drifted.items() if k not in {"name", "path"}},
            {k: v for k, v in corrected.items() if k not in {"name", "path"}},
        )
        self.assertEqual(roles_before, helper.admin("GET", path + "/role-mappings"))
        o["exactNativeBindingCorrectionVerified"] = True
        # A successful runtime edit cannot itself publish an unready capability.
        status, _, _ = self.login()
        self.assertEqual(200, status)
        bearer = helper.human(record=False)
        status, _, _ = request(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["correctedBeforeRestartApprovalStatus"] = status
        self.assertEqual(503, status)
        bearer = None
        NativeFixture.phase = "binding-corrected-restart"
        subprocess.run(
            ["docker", "stop", "-t", "5", NativeFixture.name],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "rm", NativeFixture.name],
            check=True,
            capture_output=True,
            timeout=15,
        )
        command = NativeFixture.command.copy()
        index = command.index(IMAGE)
        command[index:index] = [
            "-e",
            "ORISO_PROTECTED_INVITATIONS_ENABLED=true",
            "-e",
            "ORISO_PROTECTED_INVITATIONS_CONFIG=" + configuration,
        ]
        command.append("--verbose")
        NativeFixture.memoryStart()
        started = time.monotonic()
        deadline = started + 180
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        NativeFixture.refresh_endpoint("binding-corrected-restart")
        fourth = self.runtime(baseline, configuration)
        NativeFixture.native_image_ids.append(fourth["Image"])
        self.assertEqual(4, len(NativeFixture.native_image_ids))
        self.assertEqual(1, len(set(NativeFixture.native_image_ids)))
        o["fourthBootSameImageJarConfigVolumeAndCapsVerified"] = True
        bearer = None
        while time.monotonic() < deadline:
            require_active("binding-corrected-native-login")
            try:
                status, value, _ = self.login()
                o["correctedBootHumanLoginStatus"] = status
                if status == 200:
                    bearer = value["access_token"]
                    break
            except (URLError, TimeoutError, OSError):
                pass
            state = inspect_owned()["State"]
            self.assertTrue(state["Running"])
            self.assertFalse(state["OOMKilled"])
            time.sleep(0.2)
        self.assertIsNotNone(bearer)
        self.validate_observed_human(helper, bearer)
        o["correctedNativeHumanTokenUserinfoSessionClientGrantsVerified"] = True
        NativeFixture.phase = "binding-corrected-public-approval"
        approval = str(uuid.uuid4())
        status, value, cache = request(
            helper.base,
            "PUT",
            helper.endpoint(approval),
            {"scope": helper.scope()},
            bearer,
        )
        o["correctedRestartApprovalStatus"] = status
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", value["state"])
        receipt = value["approvalReceipt"]
        verified = helper.verified_receipt(
            receipt["receipt"],
            "protected-approval-receipt/v1",
            16384,
            {
                "approvalId",
                "scopeDigest",
                "issuerSubject",
                "bindingVersion",
                "profileVersion",
                "validUntil",
                "approvalRequestDigest",
            },
        )
        self.assertEqual({**verified, "receipt": receipt["receipt"]}, receipt)
        self.assertEqual(approval, receipt["approvalId"])
        self.assertEqual(value["scopeDigest"], receipt["scopeDigest"])
        self.assertEqual(NativeFixture.human_subject, receipt["issuerSubject"])
        self.assertEqual(
            value["approvalRequestDigest"], receipt["approvalRequestDigest"]
        )
        self.assertIn("no-store", {v.strip().lower() for v in cache.split(",")})
        self.assertEqual(realm_before, helper.admin("GET"))
        self.assertEqual(human_before, helper.admin("GET", human_path))
        self.assertEqual(corrected, helper.admin("GET", path))
        self.assertEqual(roles_before, helper.admin("GET", path + "/role-mappings"))
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        o["correctedApprovalReceiptMacAndNativeHumanVerified"] = True
        o["postCorrectionRealmHumanGroupAndAccountCountUnchanged"] = True
        o["fourthBootElapsedSeconds"] = round(time.monotonic() - started, 3)
        self.assertLess(time.monotonic(), deadline)
        bearer = None


def classify(summary):
    from run_protected_readiness import classify as drift_classify

    images = summary.get("nativeImageIds", [])
    o = summary.get("readinessObservation", {})
    if len(images) != 4 or len(set(images)) != 1:
        return "INPUT_OR_FIXTURE_ERROR"
    prior = {**summary, "nativeImageIds": images[:3]}
    if drift_classify(prior) != "GREEN":
        return "BEHAVIOR_FAILURE"
    if (
        summary.get("failures") == 0
        and o.get("correctedBeforeRestartApprovalStatus") == 503
        and o.get("correctedBootHumanLoginStatus") == 200
        and o.get("correctedRestartApprovalStatus") == 201
        and all(
            o.get(k) is True
            for k in (
                "exactNativeBindingCorrectionVerified",
                "fourthBootSameImageJarConfigVolumeAndCapsVerified",
                "correctedNativeHumanTokenUserinfoSessionClientGrantsVerified",
                "correctedApprovalReceiptMacAndNativeHumanVerified",
                "postCorrectionRealmHumanGroupAndAccountCountUnchanged",
            )
        )
        and 0 < o.get("fourthBootElapsedSeconds", 0) < 180
    ):
        return "GREEN"
    return "BEHAVIOR_FAILURE"
