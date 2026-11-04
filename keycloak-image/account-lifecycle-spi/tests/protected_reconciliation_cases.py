"""Original creation outcomes remain recoverable without renewing activation authority."""

import base64
import copy
import hashlib
import hmac
import json
import time
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, REALM, CONTEXT_KEY, canonical, mac
from protected_resources import require_active


class ProtectedReconciliationCases:
    def test_expired_creation_replay_reports_current_outcome_and_restricts_native_read(
        self,
    ):
        deadline = int(time.time()) + 12
        valid_until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline))
        approval, attempt, scope, approved, create = self.approved_creation(valid_until)
        status, reference = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", reference["state"])
        self.assertEqual(create["execution"], reference["execution"])
        # Reference is an independent fixture oracle. The replay caller below
        # receives only the original request, never account/proof from this reply.
        account = reference["accountId"]
        self.assertEqual(account, str(uuid.UUID(account)))
        encoded, signature = reference["creationProof"].split(".")
        self.assertLessEqual(len(reference["creationProof"].encode()), 16384)
        self.assertTrue(
            hmac.compare_digest(
                signature,
                base64.urlsafe_b64encode(
                    hmac.new(
                        CONTEXT_KEY,
                        ("creation-proof\n" + encoded).encode(),
                        hashlib.sha256,
                    ).digest()
                )
                .decode()
                .rstrip("="),
            )
        )
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
        read = {
            k: create[k]
            for k in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "execution",
            )
        }
        read.update(accountId=account, creationProof=reference["creationProof"])
        status, projection = self.protected_machine_request(
            "owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual(account, projection["id"])
        self.assertFalse(projection["enabled"])
        self.assertEqual([], projection["effectiveRoles"])
        self.assertLess(time.time(), deadline)
        original_request = copy.deepcopy(create)
        while time.time() <= deadline + 1:
            require_active("waiting-for-creation-reconciliation-expiry")
            time.sleep(0.2)
        type(self).phase = "protected-expired-creation-replay-and-read-http"
        replay_status, reconciled = self.protected_machine_request(
            "create",
            approval,
            original_request,
            actor="ACCOUNT_CREATE",
            attempt=attempt,
        )
        read_status, expired_projection = self.protected_machine_request(
            "owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt
        )
        type(self).creation_reconciliation_observation = {
            "actualReplayStatus": replay_status,
            "expectedReplayStatus": 200,
            "actualOwnedReadStatus": read_status,
            "expectedOwnedReadStatus": 200,
            "nativeHumanApprovalAndCreationMACAllFieldsValidated": True,
            "originalOwnerScopeAcceptanceFingerprintAndExecutionValidated": True,
            "sourceNativeLiveReadValidated": True,
            "receiverDeadlineElapsed": time.time() > deadline,
            "replayInputHasNoCreationOutcomeOrHumanBearer": True,
            "originalRequestBodyUnchanged": original_request == create,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before == self.admin("GET", "/users/" + account),
            "nativeMembershipUnchanged": groups
            == self.admin("GET", "/users/" + account + "/groups"),
        }
        self.assertEqual(200, replay_status)
        self.assertEqual(200, read_status)
        self.assertEqual(reference, reconciled)
        self.assertEqual(projection, expired_projection)
        self.assertEqual(
            {
                "attemptId",
                "accountId",
                "state",
                "execution",
                "creationProof",
                "recoveryReceipt",
                "terminalReceipt",
            },
            set(reconciled),
        )
        # A saved OPEN outcome is not activation authority: commit must fence it.
        commit = {
            **read,
            "localCommit": {
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "c" * 64,
            },
        }
        self.assertEqual(
            409,
            self.protected_machine_request(
                "commit", approval, commit, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        status, fenced_result = self.protected_machine_request(
            "create",
            approval,
            original_request,
            actor="ACCOUNT_CREATE",
            attempt=attempt,
        )
        self.assertEqual(200, status)
        self.assertEqual("RECOVERY_CLAIMED", fenced_result["state"])
        self.assertEqual(account, fenced_result["accountId"])
        self.assertEqual(reference["creationProof"], fenced_result["creationProof"])
        self.assertIsNone(fenced_result["recoveryReceipt"])
        self.assertIsNone(fenced_result["terminalReceipt"])
        fence = fenced_result["execution"]
        self.assertEqual(1, fence["generation"])
        self.assertEqual(fence["executionId"], str(uuid.UUID(fence["executionId"])))
        self.assertNotEqual(create["execution"]["executionId"], fence["executionId"])
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "attemptId": attempt,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, expired = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("EXPIRED", expired["state"])
        self.assertEqual(fence, expired["fencedExecution"])
        transition = expired["transitionReceipt"]
        expiry_payload = {k: v for k, v in transition.items() if k != "receipt"}
        self.assertEqual(17, len(transition))
        self.assertEqual(
            expiry_payload,
            self.verified_receipt(
                transition["receipt"],
                "protected-approval-expire/v1",
                24000,
                set(expiry_payload),
            ),
        )
        self.assertEqual(attempt, expiry_payload["boundAttemptId"])
        self.assertEqual(fence, expiry_payload["fencedExecution"])
        self.assertEqual(approved["scopeDigest"], expiry_payload["scopeDigest"])
        self.assertEqual(
            409,
            self.protected_machine_request(
                "owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        current_read = {**read, "execution": fence}
        self.assertEqual(
            (200, projection),
            self.protected_machine_request(
                "owned-read",
                approval,
                current_read,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            ),
        )
        cleanup = {
            **current_read,
            "localCleanup": {
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "d" * 64,
            },
        }
        self.assertEqual(
            409,
            self.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
            )[0],
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
        recover.update(expectedGeneration=1, recoveryId=str(uuid.uuid4()))
        status, claimed = self.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual(
            {"executionId": recover["recoveryId"], "generation": 2},
            claimed["execution"],
        )
        native = {
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
            native,
            self.verified_receipt(
                claimed["recoveryReceipt"], "recovery-receipt", 16000, set(native)
            ),
        )
        self.assertEqual(
            (200, claimed),
            self.protected_machine_request(
                "create",
                approval,
                original_request,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            ),
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "owned-read",
                approval,
                current_read,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            )[0],
        )
        current_read["execution"] = claimed["execution"]
        self.assertEqual(
            (200, projection),
            self.protected_machine_request(
                "owned-read",
                approval,
                current_read,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            ),
        )
        self.assertEqual(before, self.admin("GET", "/users/" + account))
        self.assertEqual(groups, self.admin("GET", "/users/" + account + "/groups"))
        self.assertEqual(count, self.admin("GET", "/users/count"))
        for changed in ("execution", "password", "actor"):
            body, actor = copy.deepcopy(original_request), "ACCOUNT_CREATE"
            if changed == "execution":
                body["execution"]["executionId"] = str(uuid.uuid4())
            elif changed == "password":
                body["account"]["password"] += "x"
                body["creationFingerprint"] = mac(
                    "protected-account-creation/v1",
                    {k: v for k, v in body.items() if k != "creationFingerprint"},
                )
            else:
                actor = "ACCOUNT_ADMIN"
            self.assertEqual(
                403,
                self.protected_machine_request(
                    "create", approval, body, actor=actor, attempt=attempt
                )[0],
            )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "create",
                approval,
                original_request,
                actor="ACCOUNT_CREATE",
                attempt=str(uuid.uuid4()),
            )[0],
        )
        cleanup["execution"] = claimed["execution"]
        status, terminal = self.protected_machine_request(
            "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual("COMPENSATED", terminal["state"])
        native.update(
            state="COMPENSATED",
            operation="compensate",
            commandDigest=mac("protected-invitation-payload/v1", cleanup),
        )
        self.assertEqual(
            native,
            self.verified_receipt(
                terminal["terminalReceipt"], "terminal-receipt", 16000, set(native)
            ),
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "owned-read",
                approval,
                current_read,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            )[0],
        )
        self.assertEqual(
            [],
            self.admin("GET", "/users?username=" + before["username"] + "&exact=true"),
        )
        group_before = self.admin("GET", "/groups/" + self.protected_group_id)
        self.admin(
            "PUT",
            "/groups/" + self.protected_group_id,
            {"name": "retired-" + uuid.uuid4().hex},
        )
        self.addCleanup(
            self.admin,
            "PUT",
            "/groups/" + self.protected_group_id,
            {"name": group_before["name"]},
        )
        self.admin(
            "POST",
            "/users",
            {
                "username": before["username"],
                "enabled": True,
                "email": "replacement-" + uuid.uuid4().hex + "@fixture.invalid",
            },
        )
        foreign = self.admin(
            "GET", "/users?username=" + before["username"] + "&exact=true"
        )
        self.assertEqual(1, len(foreign))
        foreign_id = foreign[0]["id"]
        self.assertNotEqual(account, foreign_id)
        foreign_before = self.admin("GET", "/users/" + foreign_id)
        self.addCleanup(self.admin, "DELETE", "/users/" + foreign_id)
        self.assertEqual(
            (200, terminal),
            self.protected_machine_request(
                "create",
                approval,
                original_request,
                actor="ACCOUNT_CREATE",
                attempt=attempt,
            ),
        )
        self.assertEqual(foreign_before, self.admin("GET", "/users/" + foreign_id))
        self.assertEqual(
            (200, expired), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(count, self.admin("GET", "/users/count"))
        type(self).creation_reconciliation_observation.update(
            accurateSavedStateAndExecution=True,
            currentRestrictedReadValidated=True,
            staleReadsRefused=True,
            nativeRecoveryAndTerminalMACsValidated=True,
            terminalCreationReplayHistoricalOnly=True,
            replacementAndProfileDriftUnaffected=True,
        )
