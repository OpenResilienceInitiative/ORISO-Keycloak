"""A real rollback-only native validation cannot publish protected readiness."""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import time
import unittest
import uuid
import zipfile

from lifecycle_fixture import ACTORS, SUBJECTS, IMAGE, INSTALLER, REALM, call
from urllib.error import URLError
from protected_binding_readiness import (
    BindingReadiness,
    NativeFixture,
    config_values,
    inspect_owned,
    request,
)
from protected_resources import require_active
from run_protected import digest

COMPANION_TARGET = "/opt/keycloak/providers/oriso-proof-readiness.jar"
STATUS_FIELDS = {
    "enabled",
    "workerStarted",
    "nativeUnauthorizedProbeObserved",
    "capturedOneListener",
    "ownedSessionCreated",
    "rollbackOnlyBeforeBegin",
    "observerBegan",
    "observerRolledBack",
    "observerCommitted",
    "callbackReturnedNormally",
    "validationWarningsAbsent",
    "workerComplete",
    "workerFailed",
    "stage",
}
TRUE_STATUS_FIELDS = STATUS_FIELDS - {"observerCommitted", "workerFailed", "stage"}


class RollbackFixture(NativeFixture):
    @classmethod
    def setUpClass(cls):
        cls.startup_failure = {}
        cls.companion_path = Path(os.environ["LIFECYCLE_PROOF_COMPANION_JAR"]).resolve()
        if not cls.companion_path.is_file():
            raise AssertionError("Actual separately compiled companion JAR required")
        cls.companion_sha256 = digest(cls.companion_path)
        super().setUpClass()

    @classmethod
    def ready(cls):
        try:
            super().ready()
        except AssertionError:
            # Collect before owned cleanup, retaining no raw native message or value.
            try:
                cls.startup_failure = startup_failure_observation(cls)
            except Exception as error:
                cls.startup_failure = {"observerExceptionType": type(error).__name__}
            raise

    @classmethod
    def memoryStart(cls):
        source = str(cls.companion_path) + ":" + COMPANION_TARGET + ":ro"
        if source not in cls.command:
            index = cls.command.index(IMAGE)
            cls.command[index:index] = ["-v", source]
        if "--verbose" not in cls.command:
            cls.command.append("--verbose")
        super().memoryStart()

    @classmethod
    def stop(cls):
        super().stop()
        if digest(cls.companion_path) != cls.companion_sha256:
            raise AssertionError("Companion JAR changed during native execution")


class RollbackReadiness(unittest.TestCase):
    observation = {}

    def clean_native(self):
        RollbackFixture.doClassCleanups()
        self.assertEqual([], RollbackFixture.tearDown_exceptions)

    def inspect_companion(self, baseline, configuration):
        native = BindingReadiness.runtime(
            self, baseline, configuration, RollbackFixture
        )
        mounts = [m for m in native["Mounts"] if m["Destination"] == COMPANION_TARGET]
        self.assertEqual(1, len(mounts))
        self.assertEqual(str(RollbackFixture.companion_path), mounts[0]["Source"])
        self.assertFalse(mounts[0]["RW"])
        self.assertEqual(
            RollbackFixture.companion_sha256, digest(RollbackFixture.companion_path)
        )
        return native

    def third_boot_ready(self, deadline):
        while time.monotonic() < deadline:
            require_active("native-rollback-third-boot")
            try:
                status, value, _ = request(
                    RollbackFixture.base,
                    "POST",
                    "/realms/master/protocol/openid-connect/token",
                    {
                        "client_id": "admin-cli",
                        "grant_type": "password",
                        "username": "synthetic-installer",
                        "password": INSTALLER,
                    },
                    form=True,
                )
                if status == 200:
                    RollbackFixture.installer = value["access_token"]
                    return
            except (URLError, OSError, TimeoutError):
                pass
            self.assertTrue(inspect_owned(RollbackFixture)["State"]["Running"])
            time.sleep(0.2)
        self.fail("Actual third boot did not become ready in its finite window")

    def test_normal_native_validation_rollback_cannot_enable_approval(self):
        type(self).observation = {}
        o = self.observation
        self.addCleanup(self.clean_native)
        RollbackFixture.setUpClass()
        helper = RollbackFixture("runTest")
        self.assertTrue(RollbackFixture.configuration_checked)
        self.assertEqual(2, len(RollbackFixture.native_image_ids))
        bearer = helper.human()
        self.assertEqual(
            ["seed", "configured"], [p["stage"] for p in RollbackFixture.preconditions]
        )
        self.assertTrue(
            all(
                p["currentNativeSession"] and p["nativeUserinfoValidatedToken"]
                for p in RollbackFixture.preconditions
            )
        )
        self.assertEqual(RollbackFixture.realm_id, helper.admin("GET")["id"])
        for actor, (client_id, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client_id)
            self.assertEqual(1, len(clients))
            self.assertEqual(RollbackFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(
                SUBJECTS[actor],
                helper.admin(
                    "GET", "/clients/" + clients[0]["id"] + "/service-account-user"
                )["id"],
            )
        o["allFiveCurrentNativeClientLinksVerified"] = True
        before_count = helper.admin("GET", "/users/count")
        status, value = call(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["validBindingApproveStatus"] = status
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", value["state"])
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        o["sameJarValidBindingHumanApproveAndNoAccountVerified"] = True
        bearer = None
        baseline = inspect_owned(RollbackFixture)
        configuration = config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"]
        self.inspect_companion(baseline, configuration)
        self.assertNotIn("ORISO_PROOF_READINESS_ROLLBACK_ONLY", config_values(baseline))
        status, inert = call(
            helper.base, "GET", "/realms/" + REALM + "/oriso-proof-readiness"
        )
        o["inertCompanionHttpStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual(STATUS_FIELDS, set(inert))
        self.assertFalse(inert["enabled"])
        self.assertFalse(inert["workerStarted"])
        o["companionInertDuringActualHumanPositive"] = True
        o["installedConfigurationSHA256"] = hashlib.sha256(
            configuration.encode()
        ).hexdigest()
        realm_before = helper.admin("GET")
        human_before = helper.admin("GET", "/users/" + RollbackFixture.human_subject)
        group_path = "/groups/" + RollbackFixture.protected_group_id
        group_before = helper.admin("GET", group_path)
        RollbackFixture.phase = "native-rollback-controlled-restart"
        subprocess.run(
            ["docker", "stop", "-t", "5", RollbackFixture.name],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "rm", RollbackFixture.name],
            check=True,
            capture_output=True,
            timeout=15,
        )
        command = RollbackFixture.command.copy()
        index = command.index(IMAGE)
        command[index:index] = [
            "-e",
            "ORISO_PROTECTED_INVITATIONS_ENABLED=true",
            "-e",
            "ORISO_PROTECTED_INVITATIONS_CONFIG=" + configuration,
            "-e",
            "ORISO_PROOF_READINESS_ROLLBACK_ONLY=true",
        ]
        RollbackFixture.memoryStart()
        third_started = time.monotonic()
        third_deadline = third_started + 180
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        RollbackFixture.refresh_endpoint("native-rollback-controlled-restart")
        o["actualPublishedMappingObserved"] = True
        self.third_boot_ready(third_deadline)
        third = self.inspect_companion(baseline, configuration)
        RollbackFixture.native_image_ids.append(third["Image"])
        self.assertEqual(
            "true", config_values(third)["ORISO_PROOF_READINESS_ROLLBACK_ONLY"]
        )
        self.assertEqual(3, len(RollbackFixture.native_image_ids))
        self.assertEqual(1, len(set(RollbackFixture.native_image_ids)))
        o["sameImageMainCompanionJarConfigVolumeAndCapsVerified"] = True
        deadline = min(third_deadline, time.monotonic() + 60)
        while time.monotonic() < deadline:
            require_active("native-rollback-callback-observation")
            status, observed = call(
                helper.base, "GET", "/realms/" + REALM + "/oriso-proof-readiness"
            )
            o["activeCompanionHttpStatus"] = status
            self.assertEqual(200, status)
            self.assertEqual(STATUS_FIELDS, set(observed))
            self.assertTrue(
                all(isinstance(observed[k], bool) for k in STATUS_FIELDS - {"stage"})
            )
            if observed["workerComplete"]:
                break
            time.sleep(0.2)
        self.assertEqual("COMPLETE", observed["stage"])
        self.assertTrue(all(observed[k] is True for k in TRUE_STATUS_FIELDS))
        self.assertFalse(observed["workerFailed"])
        self.assertFalse(observed["observerCommitted"])
        o["actualNativeRollbackObservation"] = observed
        o["normalActualNativeValidationReturnedAfterRollbackOnlyClose"] = True
        self.assertEqual(realm_before, helper.admin("GET"))
        self.assertEqual(
            human_before, helper.admin("GET", "/users/" + RollbackFixture.human_subject)
        )
        self.assertEqual(group_before, helper.admin("GET", group_path))
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        o["actualNativeBindingsAndAccountsUnchangedByInstrumentation"] = True
        bearer = helper.human(record=False)
        o["currentHumanTokenUserinfoSessionClientGrantsVerifiedAfterRollback"] = True
        RollbackFixture.phase = "native-rollback-public-approval"
        status, value, cache = request(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["afterRollbackApprovalStatus"] = status
        o["afterRollbackResponseNoStore"] = "no-store" in {
            v.strip().lower() for v in cache.split(",")
        }
        o["actualAuthorizedReceiptReturned"] = (
            isinstance(value, dict)
            and value.get("state") == "AUTHORIZED"
            and isinstance(value.get("approvalReceipt"), dict)
        )
        if o["actualAuthorizedReceiptReturned"]:
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
            self.assertEqual(RollbackFixture.human_subject, receipt["issuerSubject"])
            self.assertEqual(value["approvalId"], receipt["approvalId"])
            self.assertEqual(value["scopeDigest"], receipt["scopeDigest"])
            o["actualAuthorizedReceiptMacAndNativeHumanVerified"] = True
        self.assertEqual(realm_before, helper.admin("GET"))
        self.assertEqual(
            human_before, helper.admin("GET", "/users/" + RollbackFixture.human_subject)
        )
        self.assertEqual(group_before, helper.admin("GET", group_path))
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        o["nativeRealmHumanGroupAndAccountCountUnchangedAfterApproval"] = True
        o["thirdBootElapsedSeconds"] = round(time.monotonic() - third_started, 3)
        self.assertLess(time.monotonic(), third_deadline)
        self.assertEqual(503, status)
        self.assertTrue(o["afterRollbackResponseNoStore"])
        self.assertFalse(o["actualAuthorizedReceiptReturned"])
        bearer = None


def companion_evidence():
    jar = RollbackFixture.companion_path
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        if any(
            not n.startswith("org/oriso/keycloak/lifecycle/proof/")
            and n
            not in {
                "META-INF/beans.xml",
                "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory",
            }
            for n in names
        ):
            raise AssertionError("Unexpected proof companion archive entry")
        entries = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in names}
    with zipfile.ZipFile(RollbackFixture.jar_path) as archive:
        if any(
            n.startswith("org/oriso/keycloak/lifecycle/proof/")
            for n in archive.namelist()
        ):
            raise AssertionError("Companion must not be part of production main JAR")
    return {
        "companionJarSHA256": RollbackFixture.companion_sha256,
        "companionJarStable": digest(jar) == RollbackFixture.companion_sha256,
        "companionJarEntriesSHA256": entries,
        "companionAbsentFromMainJar": True,
        "startupFailureObservation": getattr(RollbackFixture, "startup_failure", {}),
    }


def startup_failure_observation(fixture):
    inspected = inspect_owned(fixture)
    if inspected["Config"]["Labels"].get("oriso-protected-receiver-test") != "true":
        raise AssertionError("Owned native diagnostic label required")
    output = subprocess.run(
        ["docker", "logs", "--tail", "500", fixture.name],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return sanitized_startup_failure(inspected["State"], output.stdout + output.stderr)


def sanitized_startup_failure(state, raw):
    allowed = (
        "java.",
        "jakarta.",
        "io.quarkus.",
        "org.jboss.",
        "org.keycloak.",
        "org.oriso.keycloak.lifecycle.proof.",
    )
    # Only Java identifiers and numeric source coordinates cross this boundary.
    types = sorted(
        {
            v
            for v in re.findall(
                r"\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+(?:Exception|Error))\b",
                raw,
            )
            if v.startswith(allowed)
        }
    )[:16]
    frames = []
    for owner, file, line in re.findall(
        r"\bat\s+([A-Za-z_$][A-Za-z0-9_.$]*)\(([A-Za-z_$][A-Za-z0-9_$]*\.java):(\d+)\)",
        raw,
    ):
        value = {"method": owner, "file": file, "line": int(line)}
        if owner.startswith(allowed) and value not in frames:
            frames.append(value)
    phrases = (
        "non-static inner class",
        "non-static nested class",
        "must be static",
        "no suitable constructor",
        "no default constructor",
        "no no-arg constructor",
        "must have a public no-args constructor",
        "unsatisfied dependency",
        "ambiguous dependencies",
        "cannot be instantiated",
    )
    lower = raw.lower()
    return {
        "running": state["Running"],
        "oomKilled": state["OOMKilled"],
        "exitCode": state["ExitCode"],
        "exceptionTypes": types,
        "sourceFrames": frames[:16],
        "fixedDiagnosticFlags": {v: v in lower for v in phrases},
    }


def classify_rollback(summary):
    o = summary.get("readinessObservation", {})
    images = summary.get("nativeImageIds", [])
    required = (
        "allFiveCurrentNativeClientLinksVerified",
        "sameJarValidBindingHumanApproveAndNoAccountVerified",
        "companionInertDuringActualHumanPositive",
        "actualPublishedMappingObserved",
        "sameImageMainCompanionJarConfigVolumeAndCapsVerified",
        "normalActualNativeValidationReturnedAfterRollbackOnlyClose",
        "actualNativeBindingsAndAccountsUnchangedByInstrumentation",
        "currentHumanTokenUserinfoSessionClientGrantsVerifiedAfterRollback",
        "nativeRealmHumanGroupAndAccountCountUnchangedAfterApproval",
    )
    callback = o.get("actualNativeRollbackObservation", {})
    valid = (
        summary.get("executed") == 1
        and summary.get("errors") == summary.get("skipped") == 0
        and len(images) == 3
        and len(set(images)) == 1
        and all(o.get(k) is True for k in required)
        and o.get("validBindingApproveStatus") == 201
        and o.get("inertCompanionHttpStatus") == 200
        and o.get("activeCompanionHttpStatus") == 200
        and summary.get("companionJarStable") is True
        and summary.get("companionAbsentFromMainJar") is True
        and 0 < o.get("thirdBootElapsedSeconds", 181) < 180
        and set(callback) == STATUS_FIELDS
        and callback.get("stage") == "COMPLETE"
        and all(callback.get(k) is True for k in TRUE_STATUS_FIELDS)
        and callback.get("observerCommitted") is False
        and callback.get("workerFailed") is False
    )
    if not valid:
        return "INPUT_OR_FIXTURE_ERROR"
    if (
        summary.get("failures") == 0
        and o.get("afterRollbackApprovalStatus") == 503
        and o.get("afterRollbackResponseNoStore") is True
        and o.get("actualAuthorizedReceiptReturned") is False
    ):
        return "GREEN"
    if (
        summary.get("failures") == 1
        and o.get("afterRollbackApprovalStatus") == 201
        and o.get("actualAuthorizedReceiptReturned") is True
        and o.get("actualAuthorizedReceiptMacAndNativeHumanVerified") is True
    ):
        return "GENUINE_NORMAL_NATIVE_ROLLBACK_PUBLISHED_APPROVAL_RED"
    return "BEHAVIOR_FAILURE"
