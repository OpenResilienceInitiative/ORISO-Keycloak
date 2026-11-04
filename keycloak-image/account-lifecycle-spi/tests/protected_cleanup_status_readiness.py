"""One fixed native cleanup-status read after actual cancel/recover/compensate."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import time
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, REALM, call, canonical, mac
from protected_binding_readiness import BindingReadiness, inspect_owned, config_values
from protected_auth_lock_readiness import (
    AuthLockFixture, records, wait_record, companion_evidence,
)
from run_protected import digest
from pathlib import Path
import subprocess
import zipfile


class NativeFixture(AuthLockFixture):
    @classmethod
    def memoryStart(cls):
        mode = "ORISO_PROOF_AUTH_LOCK_CASE=CLEANUP_STATUS"
        if mode not in cls.command:
            image = "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
            cls.command[cls.command.index(image):cls.command.index(image)] = ["-e", mode]
        super().memoryStart()


REQUIRED = (
    "allFiveCurrentNativeClientLinksVerified",
    "sameJarConfiguredNativeRuntimeVerified",
    "actualCurrentHumanAndSessionVerified",
    "actualHumanApprovalDisabledCreateVerified",
    "actualBoundRestrictionAndFenceVerified",
    "actualRecoveryAtSavedFenceVerified",
    "actualNativeCompensateReceiptAndAccountAbsenceVerified",
    "originalRestrictionStatusUnchangedAfterCleanup",
)


def classify(summary):
    o = summary.get("readinessObservation", {})
    images = summary.get("nativeImageIds", [])
    if not (summary.get("executed") == 1 and summary.get("errors") == 0
            and summary.get("skipped") == 0 and all(o.get(k) is True for k in REQUIRED)
            and len(images) == 2 and len(set(images)) == 1):
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 1 and o.get("cleanupStatus") in {404, 405}:
        return "GENUINE_FIXED_CLEANUP_STATUS_ROUTE_MISSING_RED"
    if (summary.get("failures") == 0 and o.get("cleanupStatus") == 200
            and o.get("exactIndependentTerminalAndOriginalRestrictionVerified") is True
            and o.get("savedReplayAndAuthenticationDenialsVerified") is True
            and o.get("badProofDeniedBeforeActualHeldRealmRelease") is True
            and o.get("actualAbsentRecoveryRequiresCompensateBeforeAttestation") is True):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


def cleanup_request(helper, approval, *, bad_proof=False, no_bearer=False, bearer=None):
    now = int(time.time())
    claims = {"iss": "userservice", "aud": "oriso-protected-invitations",
              "purpose": "INVITE_RESERVATIONS", "operation": "protected-invitation.cleanup-status",
              "method": "GET", "actor": "SETUP", "realm": REALM,
              "target": "realm/" + helper.realm_id + "/protected-invitation/" + approval,
              "taskClient": ACTORS["SETUP"][0], "taskSubject": SUBJECTS["SETUP"],
              "payloadDigest": mac("protected-invitation-payload/v1", {}),
              "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60}
    encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(
        CONTEXT_KEY, ("protected-invitation-proof/v1\n" + encoded).encode(), hashlib.sha256
    ).digest()).decode().rstrip("=")
    proof = encoded + "." + ("A" * 43 if bad_proof else signature)
    return call(helper.base, "GET", helper.endpoint(approval, "/cleanup-status"),
                None, None if no_bearer else (bearer or helper.token("SETUP")), proof=proof)


class CleanupStatusReadiness(BindingReadiness):
    def clean_native(self):
        NativeFixture.doClassCleanups()
        self.assertEqual([], NativeFixture.tearDown_exceptions)

    def test_independent_cleanup_status_binds_the_original_restriction_and_native_terminal(self):
        type(self).observation = {}
        o = self.observation
        self.addCleanup(self.clean_native)
        NativeFixture.setUpClass()
        helper = NativeFixture("runTest")
        self.assertTrue(NativeFixture.configuration_checked)
        self.assertEqual(2, len(NativeFixture.native_image_ids))
        for actor, (client, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client)
            self.assertEqual(1, len(clients))
            self.assertEqual(NativeFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(SUBJECTS[actor], helper.admin(
                "GET", "/clients/" + clients[0]["id"] + "/service-account-user")["id"])
        o["allFiveCurrentNativeClientLinksVerified"] = True
        container = inspect_owned(NativeFixture)
        self.runtime(container, config_values(container)["ORISO_PROTECTED_INVITATIONS_CONFIG"], NativeFixture)
        o["sameJarConfiguredNativeRuntimeVerified"] = True
        # The original fixture verifies signed-token UserInfo, exact current native
        # session/client/tenant/grants before returning this transient bearer.
        self.assertTrue(helper.human(record=False))
        o["actualCurrentHumanAndSessionVerified"] = True
        approval, attempt, scope, approved, create = helper.approved_creation()
        status, opened = helper.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt)
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        self.assertFalse(helper.admin("GET", "/users/" + opened["accountId"])["enabled"])
        o["actualHumanApprovalDisabledCreateVerified"] = True
        query = {"scopeDigest": approved["scopeDigest"], "workflowId": scope["workflowId"],
                 "inviteId": scope["inviteId"], "authorizationRevision": 1, "attemptId": attempt,
                 "approvalRequestDigest": approved["approvalRequestDigest"]}
        cancel = {k: v for k, v in query.items() if k != "attemptId"}
        cancel.update(cancellationId=str(uuid.uuid4()), reason="REVOKED", absentScope=None)
        status, restricted = helper.protected_machine_request("cancel", approval, cancel)
        self.assertEqual(200, status)
        self.assertEqual("CANCELLED", restricted["state"])
        self.assertEqual(attempt, restricted["boundAttemptId"])
        self.assertEqual(restricted["fencedExecution"], restricted["transitionReceipt"]["fencedExecution"])
        fence = restricted["fencedExecution"]
        self.assertGreater(fence["generation"], 0)
        self.assertEqual(str(uuid.UUID(fence["executionId"])), fence["executionId"])
        o["actualBoundRestrictionAndFenceVerified"] = True
        recover = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision",
                                         "creationFingerprint", "acceptanceClaim")}
        recover.update(expectedGeneration=fence["generation"], recoveryId=str(uuid.uuid4()))
        status, claimed = helper.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt)
        self.assertEqual(200, status)
        self.assertEqual("RECOVERY_CLAIMED", claimed["state"])
        self.assertEqual({"generation": fence["generation"] + 1,
                          "executionId": recover["recoveryId"]}, claimed["execution"])
        o["actualRecoveryAtSavedFenceVerified"] = True
        cleanup = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision",
                                         "creationFingerprint")}
        cleanup.update(execution=claimed["execution"], accountId=opened["accountId"],
                       creationProof=opened["creationProof"], localCleanup={"journalVersion": 1,
                       "outboxId": str(uuid.uuid4()), "effectsDigest": "c" * 64})
        status, terminal = helper.protected_machine_request(
            "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt)
        self.assertEqual(200, status)
        self.assertEqual("COMPENSATED", terminal["state"])
        self.assertEqual(claimed["execution"], terminal["execution"])
        receipt = helper.verified_receipt(terminal["terminalReceipt"], "terminal-receipt", 16000,
            {"realmId", "attemptId", "accountId", "ownerClient", "ownerSubject", "scope",
             "creationFingerprint", "groupId", "roleFingerprint", "state", "generation",
             "executionId", "operation", "commandDigest"})
        self.assertEqual("compensate", receipt["operation"])
        self.assertEqual(mac("protected-invitation-payload/v1", cleanup), receipt["commandDigest"])
        self.assertEqual([], helper.admin("GET", "/users?username=" + create["account"]["username"] + "&exact=true"))
        o["actualNativeCompensateReceiptAndAccountAbsenceVerified"] = True
        status, historical = helper.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual(restricted, historical)
        o["originalRestrictionStatusUnchangedAfterCleanup"] = True
        NativeFixture.phase = "fixed-cleanup-status-public-counterfactual"
        status, result = cleanup_request(helper, approval)
        o["cleanupStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual({"version", "restriction", "terminal", "compensationDigest", "receipt"}, set(result))
        self.assertEqual(1, result["version"])
        self.assertEqual(restricted, result["restriction"])
        self.assertEqual(terminal, result["terminal"])
        self.assertEqual(mac("protected-invitation-payload/v1", cleanup), result["compensationDigest"])
        signed = helper.verified_receipt(result["receipt"], "protected-approval-cleanup-status/v1",
            65536, {"version", "restriction", "terminal", "compensationDigest"})
        self.assertEqual({k: v for k, v in result.items() if k != "receipt"}, signed)
        o["exactIndependentTerminalAndOriginalRestrictionVerified"] = True
        self.assertEqual((200, result), cleanup_request(helper, approval))
        self.assertEqual(403, cleanup_request(helper, approval, bad_proof=True)[0])
        self.assertEqual(401, cleanup_request(helper, approval, no_bearer=True)[0])
        self.assertEqual((200, restricted), helper.protected_machine_request("status", approval, query))
        o["savedReplayAndAuthenticationDenialsVerified"] = True
        self.held_authentication_negative(helper, approval, o)
        self.actual_absent_cleanup(helper, o)

    def held_authentication_negative(self, helper, approval, observed):
        self.assertEqual(["INERT", "ARMED"], NativeFixture.proof_boot_phases)
        paths = subprocess.run(["docker", "exec", NativeFixture.name, "find",
            "/opt/keycloak/lib/lib/main", "-maxdepth", "1", "-name", "com.h2database.h2-*.jar"],
            check=True, capture_output=True, text=True, timeout=15).stdout.splitlines()
        self.assertEqual(["/opt/keycloak/lib/lib/main/com.h2database.h2-2.4.240.jar"], paths)
        copied = NativeFixture.control.parent / ("oriso-cleanup-h2-" + uuid.uuid4().hex + ".jar")
        self.addCleanup(lambda: copied.unlink(missing_ok=True))
        subprocess.run(["docker", "cp", NativeFixture.name + ":" + paths[0], str(copied)],
            check=True, capture_output=True, timeout=15)
        with zipfile.ZipFile(copied) as jar:
            self.assertIn("Implementation-Version: 2.4.240\r\n", jar.read("META-INF/MANIFEST.MF").decode())
        observed["runtimeH2ArtifactSHA256"] = digest(copied)
        copied.unlink()
        bearer = helper.token("SETUP")
        self.assertEqual(200, cleanup_request(helper, approval, bearer=bearer)[0])
        self.assertEqual(403, cleanup_request(helper, approval, bad_proof=True, bearer=bearer)[0])
        self.assertEqual("ARMED", records(NativeFixture)[0]["phase"])
        with ThreadPoolExecutor(max_workers=1) as executor:
            (NativeFixture.control / "0.arm").touch(mode=0o644)
            held = wait_record(NativeFixture, 0, "LOCKED", time.monotonic() + 5)
            self.assertTrue(all(held[k] for k in ["runtimeH2Pinned", "nativeTransactionOwned", "actualRealmRowHeld"]))
            future = executor.submit(cleanup_request, helper, approval, bad_proof=True, bearer=bearer)
            try:
                deadline = time.monotonic() + 1.5
                while not future.done() and time.monotonic() < deadline:
                    time.sleep(0.025)
                completed = future.done()
            finally:
                (NativeFixture.control / "0.release").touch(mode=0o644)
            released = wait_record(NativeFixture, 0, "RELEASED", time.monotonic() + 2)
            self.assertEqual(403, future.result(timeout=5)[0])
        self.assertTrue(completed)
        self.assertTrue(released["nativeTransactionOwned"] and released["actualRealmRowHeld"])
        self.assertFalse(released["workerFailed"])
        wait_record(NativeFixture, 1, "COMPLETE", time.monotonic() + 2)
        self.assertEqual(200, cleanup_request(helper, approval)[0])
        observed["badProofDeniedBeforeActualHeldRealmRelease"] = True

    def actual_absent_cleanup(self, helper, observed):
        approval, attempt, scope, approved, create = helper.approved_creation()
        count = helper.admin("GET", "/users/count")
        cancel = {"scopeDigest": approved["scopeDigest"], "workflowId": scope["workflowId"],
                  "inviteId": scope["inviteId"], "authorizationRevision": 1,
                  "approvalRequestDigest": approved["approvalRequestDigest"],
                  "cancellationId": str(uuid.uuid4()), "reason": "REVOKED", "absentScope": None}
        status, restricted = helper.protected_machine_request("cancel", approval, cancel)
        self.assertEqual(200, status)
        self.assertIsNone(restricted["boundAttemptId"])
        self.assertIsNone(restricted["fencedExecution"])
        recover = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision",
                                         "creationFingerprint", "acceptanceClaim")}
        recover.update(expectedGeneration=0, recoveryId=str(uuid.uuid4()))
        status, absent = helper.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt)
        self.assertEqual(200, status)
        self.assertEqual("ABANDONED", absent["state"])
        self.assertIsNone(absent["accountId"])
        self.assertIsNone(absent["creationProof"])
        self.assertEqual(409, cleanup_request(helper, approval)[0])
        cleanup = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision",
                                         "creationFingerprint")}
        cleanup.update(execution=absent["execution"], accountId=None, creationProof=None,
                       localCleanup={"journalVersion": 1, "outboxId": str(uuid.uuid4()), "effectsDigest": "e" * 64})
        status, terminal = helper.protected_machine_request(
            "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt)
        self.assertEqual(200, status)
        self.assertEqual(absent, terminal)
        status, envelope = cleanup_request(helper, approval)
        self.assertEqual(200, status)
        self.assertEqual(1, envelope["version"])
        self.assertEqual(terminal, envelope["terminal"])
        original = envelope["restriction"]
        self.assertGreaterEqual(original["version"], restricted["version"])
        self.assertEqual({**restricted, "version": original["version"]}, original)
        self.assertIsNone(original["boundAttemptId"])
        self.assertIsNone(original["fencedExecution"])
        self.assertEqual(mac("protected-invitation-payload/v1", cleanup), envelope["compensationDigest"])
        signed = helper.verified_receipt(envelope["receipt"], "protected-approval-cleanup-status/v1",
            65536, {"version", "restriction", "terminal", "compensationDigest"})
        self.assertEqual({k: v for k, v in envelope.items() if k != "receipt"}, signed)
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        observed["actualAbsentRecoveryRequiresCompensateBeforeAttestation"] = True
