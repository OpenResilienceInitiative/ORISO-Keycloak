"""Finite peer cancellation reach at the actual protected HTTP boundary."""

import copy
import uuid

from lifecycle_fixture import call
from protected_peer_readiness import PeerFixture, PeerReadiness, REQUIRED, TENANT, OTHER_PROFILE


CANCEL_REQUIRED = (*REQUIRED, "exactPeerIssuedReceiptVerified",
                   "outOfReachPrimaryApprovalsVerified",
                   "outOfReachCancelDenialsPreserveAuthorizedScopes",
                   "peerCancelAccountCountUnchanged",
                   "peerCancelNativeAccountAndMembershipUnchanged")


def classify(summary):
    observed = summary.get("readinessObservation", {})
    images = summary.get("nativeImageIds", [])
    if not (
        summary.get("executed") == 1
        and summary.get("errors") == 0
        and summary.get("skipped") == 0
        and all(observed.get(name) is True for name in CANCEL_REQUIRED)
        and len(images) == 2 and len(set(images)) == 1
        and observed.get("sourceApproveStatus") == 201
        and observed.get("sourceCreateStatus") == 201
        and observed.get("sourceCommitStatus") == 200
        and observed.get("sourceConsumedStatus") == 200
        and observed.get("peerApproveStatus") == 201
        and observed.get("outOfReachCancelStatuses") == [403, 403, 403, 403]
    ):
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 1 and observed.get("peerCancelStatus") == 403:
        return "GENUINE_COMMITTED_PEER_HUMAN_CANCEL_RED"
    if (summary.get("failures") == 0 and observed.get("peerCancelStatus") == 200
            and observed.get("immutableHumanCancelReceiptAndRetriesVerified") is True):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class PeerCancellation(PeerReadiness):
    def test_committed_peer_cancels_only_current_own_tenant_profile_and_mode(self):
        self.test_committed_tenant_admin_approves_own_tenant_peer_without_person_config()
        helper, subject, bearer, approval, scope, issued = self.peer_case
        observed = self.observation
        count = helper.admin("GET", "/users/count")
        native_before = helper.admin("GET", "/users/" + subject)
        groups_before = helper.admin("GET", "/users/" + subject + "/groups")
        primary = helper.human(record=False)
        denied = []
        for variant in ("foreign-tenant", "disallowed-tenant-profile", "platform-profile", "reserved-new-mode"):
            with self.subTest(reach=variant):
                other, other_scope = str(uuid.uuid4()), helper.scope()
                if variant == "foreign-tenant":
                    other_scope["targetTenantIds"] = [TENANT + 1]
                elif variant == "disallowed-tenant-profile":
                    other_scope["protectedProfileId"] = OTHER_PROFILE
                elif variant == "platform-profile":
                    other_scope.update(protectedKind="PLATFORM_ADMIN", targetTenantIds=[0],
                                       protectedProfileId="platform-v1")
                else:
                    other_scope.update(tenantMode="RESERVED_NEW", reservationBinding={
                        "tenantId": TENANT,
                        "invitationWorkflowId": other_scope["workflowId"],
                        "capabilityDigest": "a" * 64,
                    })
                status, authorized = call(helper.base, "PUT", helper.endpoint(other),
                                          {"scope": other_scope}, primary)
                self.assertEqual(201, status)
                status, _ = call(helper.base, "POST", helper.endpoint(other, "/cancel"),
                                 self.cancel_body(other_scope, authorized), bearer)
                denied.append(status)
                self.assertEqual(403, status)
                query = {"scopeDigest": authorized["scopeDigest"],
                         "workflowId": other_scope["workflowId"], "inviteId": other_scope["inviteId"],
                         "authorizationRevision": 1, "attemptId": None,
                         "approvalRequestDigest": authorized["approvalRequestDigest"]}
                status, current = helper.protected_machine_request("status", other, query)
                self.assertEqual(200, status)
                self.assertEqual(authorized, current)
        observed["outOfReachPrimaryApprovalsVerified"] = True
        observed["outOfReachCancelStatuses"] = denied
        observed["outOfReachCancelDenialsPreserveAuthorizedScopes"] = True
        body = self.cancel_body(scope, issued)
        PeerFixture.phase = "committed-peer-human-cancel"
        status, cancelled = call(helper.base, "POST", helper.endpoint(approval, "/cancel"), body, bearer)
        observed["peerCancelStatus"] = status
        observed["peerCancelAccountCountUnchanged"] = count == helper.admin("GET", "/users/count")
        self.assertTrue(observed["peerCancelAccountCountUnchanged"])
        observed["peerCancelNativeAccountAndMembershipUnchanged"] = (
            native_before == helper.admin("GET", "/users/" + subject)
            and groups_before == helper.admin("GET", "/users/" + subject + "/groups"))
        self.assertTrue(observed["peerCancelNativeAccountAndMembershipUnchanged"])
        self.assertEqual(200, status)
        self.assertEqual("CANCELLED", cancelled["state"])
        self.assertEqual(issued["approvalReceipt"], cancelled["approvalReceipt"])
        transition = cancelled["transitionReceipt"]
        verified = helper.verified_receipt(transition["receipt"], "protected-approval-cancel/v1", 24000,
            {"realmId", "approvalId", "workflowId", "inviteId", "authorizationRevision",
             "scopeDigest", "approvalRequestDigest", "operation", "cancellationId", "reason",
             "state", "actor", "actorSubject", "actorIssuer", "actorClient", "actorBindingVersion"})
        self.assertEqual({**verified, "receipt": transition["receipt"]}, transition)
        self.assertEqual(PeerFixture.realm_id, transition["realmId"])
        self.assertEqual(approval, transition["approvalId"])
        self.assertEqual(scope["workflowId"], transition["workflowId"])
        self.assertEqual(scope["inviteId"], transition["inviteId"])
        self.assertEqual(1, transition["authorizationRevision"])
        self.assertEqual(issued["scopeDigest"], transition["scopeDigest"])
        self.assertEqual(issued["approvalRequestDigest"], transition["approvalRequestDigest"])
        self.assertEqual("protected-invitation.cancel", transition["operation"])
        self.assertEqual(body["cancellationId"], transition["cancellationId"])
        self.assertEqual("REVOKED", transition["reason"])
        self.assertEqual("CANCELLED", transition["state"])
        self.assertEqual("HUMAN", transition["actor"])
        self.assertEqual(subject, transition["actorSubject"])
        self.assertEqual(PeerFixture.native_issuer, transition["actorIssuer"])
        self.assertEqual("protected-human-web", transition["actorClient"])
        self.assertEqual(1, transition["actorBindingVersion"])
        for retry_body in (body, {**body, "cancellationId": str(uuid.uuid4())}):
            status, retry = call(helper.base, "POST", helper.endpoint(approval, "/cancel"), retry_body, bearer)
            self.assertEqual(200, status)
            self.assertEqual(cancelled, retry)
        changed = copy.deepcopy(body)
        changed["reason"] = "SUPERSEDED"
        self.assertEqual(409, call(helper.base, "POST", helper.endpoint(approval, "/cancel"), changed, bearer)[0])
        self.assertEqual(409, call(helper.base, "PUT", helper.endpoint(approval), {"scope": scope}, bearer)[0])
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        observed["immutableHumanCancelReceiptAndRetriesVerified"] = True

    @staticmethod
    def cancel_body(scope, issued):
        return {"cancellationId": str(uuid.uuid4()), "scopeDigest": issued["scopeDigest"],
                "workflowId": scope["workflowId"], "inviteId": scope["inviteId"],
                "authorizationRevision": 1, "reason": "REVOKED", "absentScope": None,
                "approvalRequestDigest": issued["approvalRequestDigest"]}
