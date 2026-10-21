"""Protected cleanup through its public HTTP/native receiving seams."""

import base64
import copy
import hashlib
import hmac
import json
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, canonical, mac


class ProtectedCleanupCases:
    def test_protected_compensation_deletes_only_owned_pending_account_and_retries_without_effects(
        self,
    ):
        approval, attempt, scope, approved, create = self.approved_creation()
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        account = opened["accountId"]
        self.assertEqual(account, str(uuid.UUID(account)))
        before = self.admin("GET", "/users/" + account)
        self.assertFalse(before["enabled"])
        groups = self.admin("GET", "/users/" + account + "/groups")
        self.assertEqual(["/pending-provisioning"], [v["path"] for v in groups])
        count = self.admin("GET", "/users/count")
        encoded, signature = opened["creationProof"].split(".")
        self.assertEqual(
            base64.urlsafe_b64encode(
                hmac.new(
                    CONTEXT_KEY, ("creation-proof\n" + encoded).encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("="),
            signature,
        )
        origin = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(self.realm_id, origin["realmId"])
        self.assertEqual(account, origin["accountId"])
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], origin["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], origin["ownerSubject"])
        self.assertEqual(create["creationFingerprint"], origin["creationFingerprint"])
        self.assertEqual(
            create["acceptanceClaim"],
            origin["scope"]["approvalBinding"]["acceptanceClaim"],
        )
        recover = {
            key: create[key]
            for key in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "acceptanceClaim",
            )
        }
        recover.update(expectedGeneration=0, recoveryId=str(uuid.uuid4()))
        status, claimed = self.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual("RECOVERY_CLAIMED", claimed["state"])
        self.assertEqual(account, claimed["accountId"])
        self.assertEqual(opened["creationProof"], claimed["creationProof"])
        self.assertEqual(
            {"generation": 1, "executionId": recover["recoveryId"]},
            claimed["execution"],
        )
        fields = {
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
            claimed["recoveryReceipt"], "recovery-receipt", 16000, fields
        )
        self.assertEqual("recover", recovery["operation"])
        self.assertEqual(
            mac("protected-invitation-payload/v1", recover), recovery["commandDigest"]
        )
        self.assertEqual("RECOVERY_CLAIMED", recovery["state"])
        self.assertEqual(account, recovery["accountId"])
        self.assertEqual(origin["scope"], json.loads(recovery["scope"]))
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
        self.assertEqual(before, self.admin("GET", "/users/" + account))
        self.assertEqual(groups, self.admin("GET", "/users/" + account + "/groups"))
        self.assertEqual(count, self.admin("GET", "/users/count"))
        native_admin = self.admin(
            "GET",
            "/clients/" + self.client_ids["ACCOUNT_ADMIN"] + "/service-account-user",
        )
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], native_admin["id"])
        self.assertEqual(
            set(ACTORS["ACCOUNT_ADMIN"][1]),
            {
                role["name"]
                for role in self.admin(
                    "GET",
                    "/users/" + native_admin["id"] + "/role-mappings/realm/composite",
                )
            },
        )
        cleanup = {
            key: create[key]
            for key in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
            )
        }
        cleanup.update(
            execution=claimed["execution"],
            accountId=account,
            creationProof=opened["creationProof"],
            localCleanup={
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "c" * 64,
            },
        )
        original_digest = mac("protected-invitation-payload/v1", cleanup)
        self.admin(
            "PUT",
            "/groups/" + self.protected_group_id,
            {"name": "temporarily-renamed-profile"},
        )
        try:
            self.assertEqual(
                "temporarily-renamed-profile",
                self.admin("GET", "/groups/" + self.protected_group_id)["name"],
            )
            type(self).phase = "protected-owned-admin-compensate-http"
            status, terminal = self.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt
            )
            remaining = self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            )
            type(self).compensate_observation = {
                "actualStatus": status,
                "expectedStatus": 200,
                "sourceLiveHumanApprovalAndCreateSucceeded": True,
                "nativePendingAccountAndMembershipValidated": True,
                "nativeAdminSubjectRolesAndAudiencesMatched": True,
                "currentCleanupRecoveryClaimValidated": True,
                "originalCreatorAcceptanceProofAndDigestPredispatch": True,
                "boundApprovalAndOriginalHumanReceiptValidated": True,
                "mutableProfileRenamedBeforeCleanup": True,
                "accountCountUnchanged": count == self.admin("GET", "/users/count"),
                "originalPendingAccountPreserved": len(remaining) == 1
                and remaining[0]["id"] == account
                and before == self.admin("GET", "/users/" + account)
                and groups == self.admin("GET", "/users/" + account + "/groups"),
            }
            self.assertEqual(200, status)
            self.assertEqual("COMPENSATED", terminal["state"])
            self.assertEqual(account, terminal["accountId"])
            self.assertEqual(claimed["execution"], terminal["execution"])
            self.assertEqual(opened["creationProof"], terminal["creationProof"])
            self.assertEqual(claimed["recoveryReceipt"], terminal["recoveryReceipt"])
            self.assertEqual([], remaining)
            self.assertEqual(count - 1, self.admin("GET", "/users/count"))
            receipt = self.verified_receipt(
                terminal["terminalReceipt"], "terminal-receipt", 16000, fields
            )
            type(self).compensate_receipt_fields = []
            for key, value in {
                "realmId": self.realm_id,
                "attemptId": attempt,
                "accountId": account,
                "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
                "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
                "scope": canonical(origin["scope"]).decode(),
                "creationFingerprint": create["creationFingerprint"],
                "groupId": self.protected_group_id,
                "roleFingerprint": mac(
                    "protected-initial-profile/v1", self.native_configured_profiles[0]
                ),
                "state": "COMPENSATED",
                "generation": 1,
                "executionId": recover["recoveryId"],
                "operation": "compensate",
                "commandDigest": original_digest,
            }.items():
                type(self).compensate_receipt_fields.append(
                    {"field": key, "matched": value == receipt[key]}
                )
                self.assertEqual(value, receipt[key], key)
            status, restricted = self.protected_machine_request(
                "status", approval, query
            )
            self.assertEqual(200, status)
            self.assertEqual("CANCELLED", restricted["state"])
            self.assertEqual(approved["approvalReceipt"], restricted["approvalReceipt"])
            self.assertEqual(attempt, restricted["boundAttemptId"])
            wrapper = restricted["transitionReceipt"]
            self.assertLessEqual(len(canonical(wrapper)), 24000)
            self.assertEqual(
                {
                    "operation",
                    "state",
                    "approvalId",
                    "scopeDigest",
                    "boundAttemptId",
                    "accountId",
                    "terminalReceipt",
                    "receipt",
                },
                set(wrapper),
            )
            outer = self.verified_receipt(
                wrapper["receipt"],
                "protected-approval-cleanup/v1",
                24000,
                set(wrapper) - {"receipt"},
            )
            self.assertEqual(
                {k: v for k, v in wrapper.items() if k != "receipt"}, outer
            )
            self.assertEqual(
                {
                    "operation": "protected-invitation.cleanup",
                    "state": "CANCELLED",
                    "approvalId": approval,
                    "scopeDigest": approved["scopeDigest"],
                    "boundAttemptId": attempt,
                    "accountId": account,
                    "terminalReceipt": terminal["terminalReceipt"],
                },
                outer,
            )
            # A real, independent native user reuses BOTH the deleted UUID and username.
            self.admin(
                "POST",
                "/partialImport",
                {
                    "ifResourceExists": "FAIL",
                    "users": [
                        {
                            "id": account,
                            "username": create["account"]["username"],
                            "enabled": True,
                            "email": "replacement-"
                            + uuid.uuid4().hex
                            + "@fixture.invalid",
                        }
                    ],
                },
            )
            replacement = self.admin("GET", "/users/" + account)
            self.addCleanup(lambda: self.admin("DELETE", "/users/" + account))
            type(self).compensate_replacement_observation = {
                "actualNativeUUIDMatched": account == replacement["id"],
                "wireUsernameMatched": create["account"]["username"]
                == replacement["username"],
                "nativeLowercaseUsernameMatched": create["account"]["username"].lower()
                == replacement["username"],
                "originalNativeUsernameMatched": before["username"]
                == replacement["username"],
                "nativeEnabled": replacement["enabled"] is True,
            }
            self.assertEqual(account, replacement["id"])
            self.assertEqual(before["username"], replacement["username"])
            self.assertTrue(replacement["enabled"])
            self.assertEqual(
                (200, terminal),
                self.protected_machine_request(
                    "compensate",
                    approval,
                    cleanup,
                    actor="ACCOUNT_ADMIN",
                    attempt=attempt,
                ),
            )
            changed = copy.deepcopy(cleanup)
            changed["localCleanup"]["journalVersion"] = 2
            self.assertEqual(
                409,
                self.protected_machine_request(
                    "compensate",
                    approval,
                    changed,
                    actor="ACCOUNT_ADMIN",
                    attempt=attempt,
                )[0],
            )
            translated = {
                "identity": {
                    "scope": origin["scope"],
                    "creationFingerprint": create["creationFingerprint"],
                },
                **{
                    k: cleanup[k]
                    for k in ("execution", "accountId", "creationProof", "localCleanup")
                },
            }
            controls = [
                (
                    "wrong-purpose",
                    {"claim_overrides": {"purpose": "INVITE_RESERVATIONS"}},
                ),
                ("ordinary-proof-domain", {"proof_domain": "proof"}),
                ("ordinary-payload-domain", {"payload_domain": "payload"}),
                ("translated-body-proof", {"proof_body": translated}),
                ("setup-native-bearer", {"actor": "SETUP"}),
                ("mail-native-bearer", {"actor": "MAIL"}),
                ("runtime-native-bearer", {"actor": "RUNTIME"}),
            ]
            for label, options in controls:
                with self.subTest(control=label):
                    denied, _ = self.protected_machine_request(
                        "compensate",
                        approval,
                        cleanup,
                        attempt=attempt,
                        **{"actor": "ACCOUNT_ADMIN", **options}
                    )
                    type(self).compensate_proof_controls.append(
                        {"control": label, "status": denied}
                    )
                    self.assertEqual(403, denied)
            for field, value in (
                ("accountId", SUBJECTS["ACCOUNT_ADMIN"]),
                ("creationProof", "foreign.proof"),
            ):
                changed = copy.deepcopy(cleanup)
                changed[field] = value
                self.assertEqual(
                    403,
                    self.protected_machine_request(
                        "compensate",
                        approval,
                        changed,
                        actor="ACCOUNT_ADMIN",
                        attempt=attempt,
                    )[0],
                )
            self.assertEqual(
                (200, terminal),
                self.protected_machine_request(
                    "compensate",
                    approval,
                    cleanup,
                    actor="ACCOUNT_CREATE",
                    attempt=attempt,
                ),
            )
            self.assertEqual(
                (200, restricted),
                self.protected_machine_request("status", approval, query),
            )
            self.assertEqual(replacement, self.admin("GET", "/users/" + account))
            self.assertEqual(count, self.admin("GET", "/users/count"))
        finally:
            self.admin(
                "PUT", "/groups/" + self.protected_group_id, {"name": "platform-admins"}
            )
