"""Public restrictive transitions; original native ownership never changes."""

import base64
import hashlib
import hmac
import json
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, REALM, CONTEXT_KEY, canonical, mac


class ProtectedFenceCases:
    def test_bound_cancellation_fences_once_and_requires_a_new_cleanup_claim(self):
        approval, attempt, scope, approved, create = self.approved_creation()
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        self.assertEqual(create["execution"], opened["execution"])
        account = opened["accountId"]
        self.assertEqual(account, str(uuid.UUID(account)))
        self.assertLessEqual(len(opened["creationProof"].encode()), 16384)
        self.assertEqual(1, opened["creationProof"].count("."))
        encoded, signature = opened["creationProof"].split(".")
        expected_signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    CONTEXT_KEY, ("creation-proof\n" + encoded).encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        self.assertTrue(hmac.compare_digest(expected_signature, signature))
        creation = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(
            encoded, base64.urlsafe_b64encode(canonical(creation)).decode().rstrip("=")
        )
        self.assertEqual(
            {
                "v",
                "realmName",
                "realmId",
                "attemptId",
                "accountId",
                "ownerClient",
                "ownerSubject",
                "scope",
                "initialGroupId",
                "initialRoleFingerprint",
                "creationFingerprint",
            },
            set(creation),
        )
        for field, value in {
            "v": 1,
            "realmName": REALM,
            "realmId": self.realm_id,
            "attemptId": attempt,
            "accountId": account,
            "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
            "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
            "initialGroupId": self.protected_group_id,
            "initialRoleFingerprint": mac(
                "protected-initial-profile/v1", self.native_configured_profiles[0]
            ),
            "creationFingerprint": create["creationFingerprint"],
        }.items():
            self.assertEqual(value, creation[field], field)
        self.assertEqual(
            {
                "tenantId": "0",
                "registrationKind": scope["protectedKind"],
                "initialGroup": self.native_configured_profiles[0]["groupPath"],
                "origin": {
                    "kind": "INVITATION",
                    "workflowId": scope["workflowId"],
                    "provenance": "protected-approval-v1:" + approval,
                    "humanIssuer": self.native_issuer,
                    "humanSubject": self.human_subject,
                    "humanAuthority": "PLATFORM",
                    "agencyIds": [],
                },
                "approvalBinding": {
                    "approvalId": approval,
                    "scopeDigest": approved["scopeDigest"],
                    "authorizationRevision": 1,
                    "acceptanceClaim": create["acceptanceClaim"],
                },
            },
            creation["scope"],
        )
        before = self.admin("GET", "/users/" + account)
        self.assertFalse(before["enabled"])
        groups = self.admin("GET", "/users/" + account + "/groups")
        self.assertEqual(["/pending-provisioning"], [g["path"] for g in groups])
        self.assertEqual(
            [], self.admin("GET", "/users/" + account + "/role-mappings/realm")
        )
        count = self.admin("GET", "/users/count")
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "attemptId": attempt,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, bound = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("BOUND", bound["state"])
        self.assertEqual(attempt, bound["boundAttemptId"])
        self.assertEqual(approved["approvalReceipt"], bound["approvalReceipt"])
        self.assertIsNone(bound["fencedExecution"])
        cancel = {
            "cancellationId": str(uuid.uuid4()),
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "reason": "REVOKED",
            "absentScope": None,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        type(self).phase = "protected-bound-setup-cancel-http"
        status, cancelled = self.protected_machine_request("cancel", approval, cancel)
        type(self).bound_cancel_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "realHumanApprovalAndNativeCreationValidated": True,
            "originalNativeCreationMACAndAllFieldsValidated": True,
            "trueBoundApprovalOriginalCreatorAndScopeValidated": True,
            "nativeSetupSubjectRolesAndAudiencesMatched": True,
            "originalGenerationZeroAndExecutionValidated": True,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before == self.admin("GET", "/users/" + account),
            "nativeMembershipUnchanged": groups
            == self.admin("GET", "/users/" + account + "/groups"),
        }
        self.assertEqual(200, status)
        self.assertEqual("CANCELLED", cancelled["state"])
        self.assertEqual(approved["approvalReceipt"], cancelled["approvalReceipt"])
        self.assertEqual(approved["scopeDigest"], cancelled["scopeDigest"])
        self.assertEqual(attempt, cancelled["boundAttemptId"])
        fence = cancelled["fencedExecution"]
        self.assertEqual({"executionId", "generation"}, set(fence))
        self.assertEqual(1, fence["generation"])
        self.assertEqual(fence["executionId"], str(uuid.UUID(fence["executionId"])))
        self.assertNotEqual(create["execution"]["executionId"], fence["executionId"])
        expected = {
            "realmId": self.realm_id,
            "approvalId": approval,
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "scopeDigest": approved["scopeDigest"],
            "approvalRequestDigest": approved["approvalRequestDigest"],
            "operation": "protected-invitation.cancel",
            "cancellationId": cancel["cancellationId"],
            "reason": "REVOKED",
            "state": "CANCELLED",
            "actor": "SETUP",
            "actorSubject": SUBJECTS["SETUP"],
            "actorIssuer": self.native_issuer,
            "actorClient": ACTORS["SETUP"][0],
            "actorBindingVersion": None,
            "boundAttemptId": attempt,
            "fencedExecution": fence,
        }
        transition = cancelled["transitionReceipt"]
        self.assertEqual(set(expected) | {"receipt"}, set(transition))
        self.assertLessEqual(len(canonical(transition)), 24000)
        self.assertEqual(
            expected,
            self.verified_receipt(
                transition["receipt"],
                "protected-approval-cancel/v1",
                24000,
                set(expected),
            ),
        )
        self.assertEqual(
            expected, {k: v for k, v in transition.items() if k != "receipt"}
        )
        for replay in (cancel, {**cancel, "cancellationId": str(uuid.uuid4())}):
            self.assertEqual(
                (200, cancelled),
                self.protected_machine_request("cancel", approval, replay),
            )
        changed = {**cancel, "reason": "SUPERSEDED"}
        self.assertEqual(
            409, self.protected_machine_request("cancel", approval, changed)[0]
        )
        self.assertEqual(
            (200, cancelled), self.protected_machine_request("status", approval, query)
        )
        commit = {
            k: create[k]
            for k in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "execution",
            )
        }
        commit.update(
            accountId=account,
            creationProof=opened["creationProof"],
            localCommit={
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "e" * 64,
            },
        )
        for execution in (create["execution"], fence):
            self.assertEqual(
                409,
                self.protected_machine_request(
                    "commit",
                    approval,
                    {**commit, "execution": execution},
                    actor="ACCOUNT_CREATE",
                    attempt=attempt,
                )[0],
            )
        cleanup = {k: v for k, v in commit.items() if k != "localCommit"}
        cleanup.update(
            execution=fence,
            localCleanup={
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "f" * 64,
            },
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
            )[0],
        )
        self.assertEqual(before, self.admin("GET", "/users/" + account))
        self.assertEqual(groups, self.admin("GET", "/users/" + account + "/groups"))
        self.assertEqual(count, self.admin("GET", "/users/count"))
        recover = {
            k: create[k]
            for k in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "acceptanceClaim",
            )
        }
        recover.update(expectedGeneration=1, recoveryId=str(uuid.uuid4()))
        status, claimed = self.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual("RECOVERY_CLAIMED", claimed["state"])
        self.assertEqual(account, claimed["accountId"])
        self.assertEqual(opened["creationProof"], claimed["creationProof"])
        self.assertEqual(
            {"generation": 2, "executionId": recover["recoveryId"]},
            claimed["execution"],
        )
        receipt_fields = {
            "realmId",
            "attemptId",
            "accountId",
            "ownerClient",
            "ownerSubject",
            "scope",
            "creationFingerprint",
            "groupId",
            "roleFingerprint",
            "state",
            "generation",
            "executionId",
            "operation",
            "commandDigest",
        }
        recovery = self.verified_receipt(
            claimed["recoveryReceipt"], "recovery-receipt", 16000, receipt_fields
        )
        expected_native = {
            "realmId": self.realm_id,
            "attemptId": attempt,
            "accountId": account,
            "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
            "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
            "scope": canonical(creation["scope"]).decode(),
            "creationFingerprint": create["creationFingerprint"],
            "groupId": self.protected_group_id,
            "roleFingerprint": creation["initialRoleFingerprint"],
            "state": "RECOVERY_CLAIMED",
            "generation": 2,
            "executionId": recover["recoveryId"],
            "operation": "recover",
            "commandDigest": mac("protected-invitation-payload/v1", recover),
        }
        self.assertEqual(expected_native, recovery)
        self.assertEqual(
            (200, claimed),
            self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            ),
        )
        self.assertEqual(
            (200, cancelled), self.protected_machine_request("status", approval, query)
        )
        cleanup["execution"] = claimed["execution"]
        status, terminal = self.protected_machine_request(
            "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual("COMPENSATED", terminal["state"])
        native_terminal = self.verified_receipt(
            terminal["terminalReceipt"], "terminal-receipt", 16000, receipt_fields
        )
        expected_native.update(
            state="COMPENSATED",
            operation="compensate",
            commandDigest=mac("protected-invitation-payload/v1", cleanup),
        )
        self.assertEqual(expected_native, native_terminal)
        self.assertEqual(claimed["recoveryReceipt"], terminal["recoveryReceipt"])
        self.assertEqual(
            (200, cancelled), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(
            [],
            self.admin("GET", "/users?username=" + before["username"] + "&exact=true"),
        )
        self.assertEqual(count - 1, self.admin("GET", "/users/count"))
        self.assertEqual(
            (200, terminal),
            self.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_CREATE", attempt=attempt
            ),
        )
        self.assertEqual(
            (200, cancelled), self.protected_machine_request("cancel", approval, cancel)
        )
