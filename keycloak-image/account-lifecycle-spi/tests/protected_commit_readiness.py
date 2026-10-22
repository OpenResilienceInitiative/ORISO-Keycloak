"""Actual native prepare completion must precede published protected readiness."""

import hashlib
import json
import subprocess
import time
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, IMAGE, call
from protected_binding_readiness import config_values, inspect_owned, request
from protected_resources import require_active
from protected_rollback_readiness import (
    RollbackFixture,
    RollbackReadiness,
    STATUS_FIELDS,
    armed_record,
    inert_record,
)

PREFIX = "ORISO_PROOF_READINESS_COMMIT_V1 "
FIELDS = STATUS_FIELDS | {
    "commitMode",
    "beforeCommitProbeStatus",
    "intentionalCommitFailure",
    "validationFailureWarningCount",
}


def expected_record(mode, complete):
    record = {
        **armed_record(),
        "commitMode": mode,
        "beforeCommitProbeStatus": 0,
        "intentionalCommitFailure": False,
        "validationFailureWarningCount": 0,
    }
    if complete:
        record.update(
            workerStarted=True,
            nativeUnauthorizedProbeObserved=True,
            capturedOneListener=True,
            ownedSessionCreated=True,
            observerBegan=True,
            observerRolledBack=mode == "FAIL",
            observerCommitted=mode == "PASS",
            callbackReturnedNormally=True,
            validationWarningsAbsent=mode == "PASS",
            workerComplete=True,
            stage="COMPLETE",
            beforeCommitProbeStatus=503,
            intentionalCommitFailure=mode == "FAIL",
            validationFailureWarningCount=1 if mode == "FAIL" else 0,
        )
    return record


def parse_records(raw):
    def unique(pairs):
        value = {}
        for key, entry in pairs:
            if key in value:
                raise ValueError("Duplicate commit observation field")
            value[key] = entry
        return value

    records = []
    for line in raw.splitlines():
        if not line.startswith(PREFIX):
            continue
        value = json.loads(line[len(PREFIX) :], object_pairs_hook=unique)
        if (
            not isinstance(value, dict)
            or set(value) != FIELDS
            or any(type(value[k]) is not bool for k in STATUS_FIELDS - {"stage"})
            or type(value["intentionalCommitFailure"]) is not bool
            or value["commitMode"] not in {"PASS", "FAIL"}
            or value["stage"]
            not in {
                "ARMED",
                "COMPLETE",
                "NATIVE_AUTH_PROBE_UNAVAILABLE",
                "WORKER_INTERRUPTED",
                "WORKER_FAILED",
            }
            or type(value["beforeCommitProbeStatus"]) is not int
            or not -1 <= value["beforeCommitProbeStatus"] <= 599
            or type(value["validationFailureWarningCount"]) is not int
            or not 0 <= value["validationFailureWarningCount"] <= 10
        ):
            raise ValueError("Invalid closed native commit observation")
        records.append(value)
    if len(records) > 2:
        raise ValueError("Duplicate commit boot or completion observation")
    return records


def process_records():
    native = inspect_owned(RollbackFixture)
    if native["Config"]["Labels"].get("oriso-protected-receiver-test") != "true":
        raise AssertionError("Owned commit observer container required")
    output = subprocess.run(
        ["docker", "logs", "--tail", "500", RollbackFixture.name],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return parse_records(output.stdout + output.stderr)


class CommitReadiness(RollbackReadiness):
    def test_native_prepare_failure_keeps_approval_unavailable(self):
        self.exercise_commit("FAIL")

    def test_native_prepare_probe_precedes_successful_public_approval(self):
        self.exercise_commit("PASS")

    def verified_approval(self, helper, value):
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
        self.assertEqual(value["approvalId"], receipt["approvalId"])
        self.assertEqual(value["scopeDigest"], receipt["scopeDigest"])
        self.assertEqual(RollbackFixture.human_subject, receipt["issuerSubject"])

    def exercise_commit(self, mode):
        type(self).observation = {}
        o = self.observation
        o["commitMode"] = mode
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
        for actor, (client, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client)
            self.assertEqual(1, len(clients))
            self.assertEqual(RollbackFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(
                SUBJECTS[actor],
                helper.admin(
                    "GET", "/clients/" + clients[0]["id"] + "/service-account-user"
                )["id"],
            )
        o["allFiveCurrentNativeClientLinksVerified"] = True
        count = helper.admin("GET", "/users/count")
        status, value = call(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["validBindingApproveStatus"] = status
        self.assertEqual(201, status)
        self.verified_approval(helper, value)
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        self.assertEqual(
            [inert_record(), inert_record()], RollbackFixture.inert_boot_records
        )
        o["sameJarNativeHumanApprovalAndInertCompanionVerified"] = True
        bearer = None
        baseline = inspect_owned(RollbackFixture)
        configuration = config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"]
        self.inspect_companion(baseline, configuration)
        self.assertNotIn(
            "ORISO_PROOF_READINESS_COMMIT_CONTROL", config_values(baseline)
        )
        self.assertNotIn("ORISO_PROOF_READINESS_ROLLBACK_ONLY", config_values(baseline))
        o["installedConfigurationSHA256"] = hashlib.sha256(
            configuration.encode()
        ).hexdigest()
        realm = helper.admin("GET")
        human_path = "/users/" + RollbackFixture.human_subject
        human = helper.admin("GET", human_path)
        group_path = "/groups/" + RollbackFixture.protected_group_id
        group = helper.admin("GET", group_path)
        RollbackFixture.phase = "native-commit-controlled-restart"
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
            "ORISO_PROOF_READINESS_COMMIT_CONTROL=" + mode,
        ]
        RollbackFixture.memoryStart()
        started = time.monotonic()
        deadline = started + 180
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        RollbackFixture.refresh_endpoint("native-commit-controlled-restart")
        self.third_boot_ready(deadline)
        third = self.inspect_companion(baseline, configuration)
        self.assertEqual(
            mode, config_values(third)["ORISO_PROOF_READINESS_COMMIT_CONTROL"]
        )
        RollbackFixture.native_image_ids.append(third["Image"])
        self.assertEqual(3, len(RollbackFixture.native_image_ids))
        self.assertEqual(1, len(set(RollbackFixture.native_image_ids)))
        o["sameImageMainCompanionJarConfigVolumeAndCapsVerified"] = True
        observed = None
        while time.monotonic() < min(deadline, started + 90):
            require_active("native-commit-callback-observation")
            records = process_records()
            self.assertIn(len(records), (1, 2))
            self.assertEqual(expected_record(mode, False), records[0])
            o["actualActiveBootRecord"] = records[0]
            if len(records) == 2:
                observed = records[1]
                break
            time.sleep(0.2)
        self.assertEqual(expected_record(mode, True), observed)
        o["actualNativeCommitObservation"] = observed
        self.assertEqual(realm, helper.admin("GET"))
        self.assertEqual(human, helper.admin("GET", human_path))
        self.assertEqual(group, helper.admin("GET", group_path))
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        o["nativeBindingsAndAccountCountUnchangedByInstrumentation"] = True
        bearer = helper.human(record=False)
        o["currentHumanTokenUserinfoSessionClientGrantsVerified"] = True
        RollbackFixture.phase = "native-commit-public-approval"
        status, value, cache = request(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["afterCommitApprovalStatus"] = status
        o["afterCommitResponseNoStore"] = "no-store" in {
            v.strip().lower() for v in cache.split(",")
        }
        self.assertEqual(503 if mode == "FAIL" else 201, status)
        self.assertTrue(o["afterCommitResponseNoStore"])
        if mode == "PASS":
            self.verified_approval(helper, value)
            o["postCommitApprovalReceiptMacAndNativeHumanVerified"] = True
        else:
            self.assertNotIn("approvalReceipt", value)
        self.assertEqual(realm, helper.admin("GET"))
        self.assertEqual(human, helper.admin("GET", human_path))
        self.assertEqual(group, helper.admin("GET", group_path))
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        o["postCommitRealmHumanGroupAndAccountCountUnchanged"] = True
        o["thirdBootElapsedSeconds"] = round(time.monotonic() - started, 3)
        self.assertLess(time.monotonic(), deadline)
        bearer = None


def classify(summary):
    o = summary.get("readinessObservation", {})
    mode = o.get("commitMode")
    try:
        checked_records = parse_records(
            PREFIX
            + json.dumps(o.get("actualActiveBootRecord"))
            + "\n"
            + PREFIX
            + json.dumps(o.get("actualNativeCommitObservation"))
        )
    except (ValueError, TypeError):
        return "INPUT_OR_FIXTURE_ERROR"
    images = summary.get("nativeImageIds", [])
    required = (
        "allFiveCurrentNativeClientLinksVerified",
        "sameJarNativeHumanApprovalAndInertCompanionVerified",
        "sameImageMainCompanionJarConfigVolumeAndCapsVerified",
        "nativeBindingsAndAccountCountUnchangedByInstrumentation",
        "currentHumanTokenUserinfoSessionClientGrantsVerified",
        "postCommitRealmHumanGroupAndAccountCountUnchanged",
        "afterCommitResponseNoStore",
    )
    if (
        mode not in {"PASS", "FAIL"}
        or summary.get("case")
        != {
            "PASS": "binding-commit-ordering-available",
            "FAIL": "binding-commit-failure-unavailable",
        }.get(mode)
        or summary.get("executed") != 1
        or summary.get("errors") != 0
        or summary.get("skipped") != 0
        or len(images) != 3
        or len(set(images)) != 1
        or not all(o.get(k) is True for k in required)
        or o.get("validBindingApproveStatus") != 201
        or summary.get("companionInertBootRecords") != [inert_record(), inert_record()]
        or summary.get("companionJarStable") is not True
        or summary.get("companionAbsentFromMainJar") is not True
        or checked_records
        != [expected_record(mode, False), expected_record(mode, True)]
        or not 0 < o.get("thirdBootElapsedSeconds", 181) < 180
    ):
        return "INPUT_OR_FIXTURE_ERROR"
    if (
        summary.get("failures") == 0
        and o.get("afterCommitApprovalStatus") == (503 if mode == "FAIL" else 201)
        and (
            mode == "FAIL"
            or o.get("postCommitApprovalReceiptMacAndNativeHumanVerified") is True
        )
    ):
        return "GREEN"
    return "BEHAVIOR_FAILURE"
