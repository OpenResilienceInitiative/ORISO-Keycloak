"""Public receiver expiry must commit a restriction even when activation returns409."""

import base64
import hashlib
import hmac
import json
import time
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, REALM, CONTEXT_KEY, canonical, mac
from protected_resources import require_active


class ProtectedExpiryCases:
    def test_expired_first_commit_persists_fence_before_any_status_request(self):
        deadline = int(time.time()) + 12
        valid_until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline))
        approval, attempt, scope, approved, create = self.approved_creation(valid_until)
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
        expected_scope = {
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
        }
        self.assertEqual(
            {
                "v": 1,
                "realmName": REALM,
                "realmId": self.realm_id,
                "attemptId": attempt,
                "accountId": account,
                "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
                "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
                "scope": expected_scope,
                "initialGroupId": self.protected_group_id,
                "initialRoleFingerprint": mac(
                    "protected-initial-profile/v1", self.native_configured_profiles[0]
                ),
                "creationFingerprint": create["creationFingerprint"],
            },
            creation,
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
        self.assertEqual(approved["approvalReceipt"], bound["approvalReceipt"])
        self.assertIsNone(bound["fencedExecution"])
        self.assertLess(time.time(), deadline)
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
                "effectsDigest": "a" * 64,
            },
        )
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
        while time.time() <= deadline + 1:
            require_active("waiting-for-first-commit-receiver-expiry")
            time.sleep(0.2)
        type(self).phase = "protected-expired-first-commit-http"
        commit_status, _ = self.protected_machine_request(
            "commit", approval, commit, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(409, commit_status)
        # No status request may materialize the fence before this independent
        # transaction. Recover must compare expectedGeneration without expiring it.
        old_recover = {
            **recover,
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        old_status, _ = self.protected_machine_request(
            "recover", approval, old_recover, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        type(self).expired_commit_observation = {
            "actualCommitStatus": commit_status,
            "expectedCommitStatus": 409,
            "oldGenerationRecoverStatus": old_status,
            "expectedOldGenerationRecoverStatus": 409,
            "nativeHumanApprovalAndCreationMACAllFieldsValidated": True,
            "trueBoundApprovalOriginalCreatorAndScopeValidated": True,
            "nativeCreatorAndAdminSubjectRolesAudiencesMatched": True,
            "originalGenerationZeroValidated": True,
            "receiverDeadlineElapsed": time.time() > deadline,
            "noStatusRequestBetweenCommitAndRecovery": True,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before == self.admin("GET", "/users/" + account),
            "nativeMembershipUnchanged": groups
            == self.admin("GET", "/users/" + account + "/groups"),
        }
        self.assertEqual(409, old_status)
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
        expected_native = {
            "realmId": self.realm_id,
            "attemptId": attempt,
            "accountId": account,
            "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
            "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
            "scope": canonical(expected_scope).decode(),
            "creationFingerprint": create["creationFingerprint"],
            "groupId": self.protected_group_id,
            "roleFingerprint": creation["initialRoleFingerprint"],
            "state": "RECOVERY_CLAIMED",
            "generation": 2,
            "executionId": recover["recoveryId"],
            "operation": "recover",
            "commandDigest": mac("protected-invitation-payload/v1", recover),
        }
        self.assertEqual(
            expected_native,
            self.verified_receipt(
                claimed["recoveryReceipt"],
                "recovery-receipt",
                16000,
                set(expected_native),
            ),
        )
        # Only now may status inspect the already committed expiry restriction.
        status, expired = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("EXPIRED", expired["state"])
        self.assertEqual(approved["approvalReceipt"], expired["approvalReceipt"])
        fence = expired["fencedExecution"]
        self.assertEqual(1, fence["generation"])
        self.assertEqual(fence["executionId"], str(uuid.UUID(fence["executionId"])))
        self.assertNotIn(
            fence["executionId"],
            (create["execution"]["executionId"], recover["recoveryId"]),
        )
        transition = expired["transitionReceipt"]
        self.assertEqual(
            {
                "realmId",
                "approvalId",
                "workflowId",
                "inviteId",
                "authorizationRevision",
                "scopeDigest",
                "approvalRequestDigest",
                "operation",
                "reason",
                "state",
                "actor",
                "expiryId",
                "validUntil",
                "expiredAt",
                "boundAttemptId",
                "fencedExecution",
                "receipt",
            },
            set(transition),
        )
        payload = {k: v for k, v in transition.items() if k != "receipt"}
        self.assertEqual(
            payload,
            self.verified_receipt(
                transition["receipt"],
                "protected-approval-expire/v1",
                24000,
                set(payload),
            ),
        )
        expected_expiry = {
            "realmId": self.realm_id,
            "approvalId": approval,
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "scopeDigest": approved["scopeDigest"],
            "approvalRequestDigest": approved["approvalRequestDigest"],
            "operation": "protected-invitation.expire",
            "reason": "EXPIRED",
            "state": "EXPIRED",
            "actor": "RECEIVER",
            "validUntil": valid_until,
            "boundAttemptId": attempt,
            "fencedExecution": fence,
        }
        for key, value in expected_expiry.items():
            self.assertEqual(value, payload[key], key)
        self.assertEqual(payload["expiryId"], str(uuid.UUID(payload["expiryId"])))
        # Compare timezone-aware ISO times independently from the receipt issuer.
        from datetime import datetime

        self.assertGreaterEqual(
            datetime.fromisoformat(
                payload["expiredAt"].replace("Z", "+00:00")
            ).timestamp(),
            deadline,
        )
        self.assertEqual(
            (200, expired), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(before, self.admin("GET", "/users/" + account))
        self.assertEqual(groups, self.admin("GET", "/users/" + account + "/groups"))
        self.assertEqual(count, self.admin("GET", "/users/count"))
        for execution in (create["execution"], fence, claimed["execution"]):
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
            localCleanup={
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "b" * 64,
            }
        )
        cleanup["execution"] = fence
        self.assertEqual(
            409,
            self.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
            )[0],
        )
        cleanup["execution"] = claimed["execution"]
        status, terminal = self.protected_machine_request(
            "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual("COMPENSATED", terminal["state"])
        expected_native.update(
            state="COMPENSATED",
            operation="compensate",
            commandDigest=mac("protected-invitation-payload/v1", cleanup),
        )
        self.assertEqual(
            expected_native,
            self.verified_receipt(
                terminal["terminalReceipt"],
                "terminal-receipt",
                16000,
                set(expected_native),
            ),
        )
        self.assertEqual(claimed["recoveryReceipt"], terminal["recoveryReceipt"])
        self.assertEqual(
            (200, expired), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(
            [],
            self.admin("GET", "/users?username=" + before["username"] + "&exact=true"),
        )
        self.assertEqual(count - 1, self.admin("GET", "/users/count"))
        type(self).expired_commit_observation.update(
            currentClaimStatus=200,
            currentClaimGeneration=2,
            immutableExpiryFenceGeneration=1,
            actualTerminalState=terminal["state"],
            normal409TransactionCommitWitnessValidated=True,
        )
