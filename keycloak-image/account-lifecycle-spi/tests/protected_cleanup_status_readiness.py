"""One fixed native cleanup-status read after actual cancel/recover/compensate."""
import base64
import hashlib
import hmac
import json
import time
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, REALM, call, canonical, mac
from protected_binding_readiness import BindingReadiness, NativeFixture, inspect_owned, config_values

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
            and o.get("savedReplayAndAuthenticationDenialsVerified") is True):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


def cleanup_request(helper, approval, *, bad_proof=False, no_bearer=False):
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
                None, None if no_bearer else helper.token("SETUP"), proof=proof)


class CleanupStatusReadiness(BindingReadiness):
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
        container = inspect_owned()
        self.runtime(container, config_values(container)["ORISO_PROTECTED_INVITATIONS_CONFIG"])
        o["sameJarConfiguredNativeRuntimeVerified"] = True
        self.validate_observed_human(helper, helper.human(record=False))
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
