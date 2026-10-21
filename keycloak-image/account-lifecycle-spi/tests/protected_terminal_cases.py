"""Public protected account scenarios; the native fixture owns all setup."""

import base64
import copy
import hashlib
import hmac
import json
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, canonical, mac


class ProtectedTerminalCases:
    def test_protected_absent_recovery_restricts_without_adopting_existing_username(
        self,
    ):
        original_count = self.admin("GET", "/users/count")
        approval, attempt, scope, approved, create = self.approved_creation()
        self.assertEqual(original_count, self.admin("GET", "/users/count"))
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "attemptId": None,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, live = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("AUTHORIZED", live["state"])
        self.assertIsNone(live["boundAttemptId"])
        self.admin(
            "POST",
            "/users",
            {
                "username": create["account"]["username"],
                "enabled": True,
                "email": "independent-" + uuid.uuid4().hex + "@fixture.invalid",
                "firstName": "Independent",
                "lastName": "User",
            },
        )
        foreign = self.admin(
            "GET", "/users?username=" + create["account"]["username"] + "&exact=true"
        )
        self.assertEqual(1, len(foreign))
        foreign_id = foreign[0]["id"]
        self.assertEqual(foreign_id, str(uuid.UUID(foreign_id)))
        foreign_before = self.admin("GET", "/users/" + foreign_id)
        foreign_present = [True]

        def remove_foreign():
            if foreign_present[0]:
                self.admin("DELETE", "/users/" + foreign_id)
                foreign_present[0] = False

        self.addCleanup(remove_foreign)
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
        fingerprint_input = {
            key: value for key, value in create.items() if key != "creationFingerprint"
        }
        self.assertEqual(
            create["creationFingerprint"],
            mac("protected-account-creation/v1", fingerprint_input),
        )
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], scope["creatorClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], scope["creatorSubject"])
        self.assertEqual(scope["workflowId"], recover["acceptanceClaim"]["workflowId"])
        self.assertEqual(scope["inviteId"], recover["acceptanceClaim"]["inviteId"])
        original_digest = mac("protected-invitation-payload/v1", recover)
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
            type(self).phase = "protected-absent-admin-recover-http"
            status, abandoned = self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            )
            type(self).absent_recover_observation = {
                "actualStatus": status,
                "expectedStatus": 200,
                "expectedState": "ABANDONED",
                "sourceRealHumanApprovalUnbound": True,
                "noCreateDispatched": True,
                "nativeAdminSubjectRolesAndAudiencesMatched": True,
                "originalCreatorAcceptanceAndFingerprintPredispatch": True,
                "mutableProfileRenamedBeforeRestriction": True,
                "foreignNativeUserExistedBeforeRequest": True,
                "foreignNativeUserPreserved": foreign_before
                == self.admin("GET", "/users/" + foreign_id),
                "accountCountUnchanged": original_count + 1
                == self.admin("GET", "/users/count"),
            }
        finally:
            self.admin(
                "PUT", "/groups/" + self.protected_group_id, {"name": "platform-admins"}
            )
        self.assertEqual(200, status)
        self.assertEqual("ABANDONED", abandoned["state"])
        self.assertIsNone(abandoned["accountId"])
        self.assertIsNone(abandoned["creationProof"])
        self.assertEqual(
            {"executionId": recover["recoveryId"], "generation": 1},
            abandoned["execution"],
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
        terminal = self.verified_receipt(
            abandoned["terminalReceipt"], "terminal-receipt", 16000, fields
        )
        recovery = self.verified_receipt(
            abandoned["recoveryReceipt"], "recovery-receipt", 16000, fields
        )
        for value, operation in ((terminal, "abandon"), (recovery, "recover")):
            self.assertEqual(self.realm_id, value["realmId"])
            self.assertEqual(attempt, value["attemptId"])
            self.assertIsNone(value["accountId"])
            self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], value["ownerClient"])
            self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], value["ownerSubject"])
            self.assertEqual(
                create["creationFingerprint"], value["creationFingerprint"]
            )
            self.assertEqual(self.protected_group_id, value["groupId"])
            self.assertEqual(
                mac("protected-initial-profile/v1", self.native_configured_profiles[0]),
                value["roleFingerprint"],
            )
            self.assertEqual("ABANDONED", value["state"])
            self.assertEqual(1, value["generation"])
            self.assertEqual(recover["recoveryId"], value["executionId"])
            self.assertEqual(operation, value["operation"])
            self.assertEqual(original_digest, value["commandDigest"])
            nested = json.loads(value["scope"])
            self.assertEqual(canonical(nested).decode(), value["scope"])
            self.assertEqual(
                {
                    "approvalId": approval,
                    "scopeDigest": approved["scopeDigest"],
                    "authorizationRevision": 1,
                    "acceptanceClaim": create["acceptanceClaim"],
                },
                nested["approvalBinding"],
            )
            self.assertEqual(self.human_subject, nested["origin"]["humanSubject"])
            self.assertEqual(self.native_issuer, nested["origin"]["humanIssuer"])
            self.assertEqual("0", nested["tenantId"])
            self.assertEqual("PLATFORM_ADMIN", nested["registrationKind"])
        self.assertEqual(terminal["scope"], recovery["scope"])
        query["attemptId"] = attempt
        status, restricted = self.protected_machine_request("status", approval, query)
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
        self.assertEqual({k: v for k, v in wrapper.items() if k != "receipt"}, outer)
        self.assertEqual("protected-invitation.cleanup", outer["operation"])
        self.assertEqual("CANCELLED", outer["state"])
        self.assertEqual(approval, outer["approvalId"])
        self.assertEqual(approved["scopeDigest"], outer["scopeDigest"])
        self.assertEqual(attempt, outer["boundAttemptId"])
        self.assertIsNone(outer["accountId"])
        self.assertEqual(abandoned["terminalReceipt"], outer["terminalReceipt"])
        self.assertEqual(foreign_before, self.admin("GET", "/users/" + foreign_id))
        self.assertEqual(
            (200, abandoned),
            self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            ),
        )
        # Remove the independent user to prove late create is blocked by the
        # durable restriction, independently of a username availability conflict.
        remove_foreign()
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "create",
                approval,
                create,
                actor="ACCOUNT_CREATE",
                attempt=str(uuid.uuid4()),
            )[0],
        )
        self.assertEqual(
            (200, abandoned),
            self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            ),
        )
        self.assertEqual(
            (200, restricted), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(original_count, self.admin("GET", "/users/count"))

    def verified_receipt(self, receipt, domain, bound, fields):
        self.assertIsInstance(receipt, str)
        self.assertLessEqual(len(receipt.encode("utf-8")), bound)
        self.assertEqual(1, receipt.count("."))
        encoded, signature = receipt.split(".")
        self.assertEqual(64, len(signature))
        self.assertTrue(all(c in "0123456789abcdef" for c in signature))
        expected = hmac.new(
            CONTEXT_KEY, (domain + "\n" + encoded).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        value = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertIsInstance(value, dict)
        self.assertEqual(set(fields), set(value))
        self.assertEqual(
            encoded, base64.urlsafe_b64encode(canonical(value)).decode().rstrip("=")
        )
        return value

    def test_protected_commit_consumes_once_and_returns_bound_immutable_receipts(self):
        approval, attempt, scope, approved, create = self.approved_creation()
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        account = opened["accountId"]
        before = self.admin("GET", "/users/" + account)
        self.assertFalse(before["enabled"])
        groups = self.admin("GET", "/users/" + account + "/groups")
        self.assertEqual(["/pending-provisioning"], [v["path"] for v in groups])
        self.assertEqual(
            [], self.admin("GET", "/users/" + account + "/role-mappings/realm")
        )
        count = self.admin("GET", "/users/count")
        commit = {
            key: create[key]
            for key in (
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
        self.assertLessEqual(len(canonical(commit)), 65536)
        self.assertLessEqual(len(commit["creationProof"].encode()), 16384)
        original_digest = mac("protected-invitation-payload/v1", commit)
        type(self).phase = "protected-first-commit-http"
        status, terminal = self.protected_machine_request(
            "commit", approval, commit, actor="ACCOUNT_CREATE", attempt=attempt
        )
        type(self).commit_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "sourceLiveApprovalAndCreateSucceeded": True,
            "nativePendingAccountValidated": True,
            "nativeCreatorSubjectRolesAndAudiencesMatched": True,
            "exactStoredApprovalAndCreationProof": True,
            "originalCommitDigestPredispatch": True,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before == self.admin("GET", "/users/" + account),
            "nativeMembershipUnchanged": groups
            == self.admin("GET", "/users/" + account + "/groups"),
        }
        self.assertEqual(200, status)
        self.assertEqual("COMMITTED", terminal["state"])
        self.assertEqual(account, terminal["accountId"])
        self.assertEqual(opened["execution"], terminal["execution"])
        self.assertEqual(opened["creationProof"], terminal["creationProof"])
        self.assertTrue(self.admin("GET", "/users/" + account)["enabled"])
        self.assertEqual(
            [self.protected_group_id],
            [v["id"] for v in self.admin("GET", "/users/" + account + "/groups")],
        )
        self.assertEqual(
            {"agency-admin", "tenant-admin"},
            {
                v["name"]
                for v in self.admin(
                    "GET", "/users/" + account + "/role-mappings/realm/composite"
                )
            },
        )
        self.assertEqual(
            [], self.admin("GET", "/users/" + account + "/role-mappings/realm")
        )
        native = self.verified_receipt(
            terminal["terminalReceipt"],
            "terminal-receipt",
            16000,
            {
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
            },
        )
        self.assertEqual(self.realm_id, native["realmId"])
        self.assertEqual(attempt, native["attemptId"])
        self.assertEqual(account, native["accountId"])
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], native["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], native["ownerSubject"])
        self.assertEqual("COMMITTED", native["state"])
        self.assertEqual("commit", native["operation"])
        self.assertEqual(original_digest, native["commandDigest"])
        self.assertEqual(create["creationFingerprint"], native["creationFingerprint"])
        self.assertEqual(self.protected_group_id, native["groupId"])
        self.assertEqual(
            mac("protected-initial-profile/v1", self.native_configured_profiles[0]),
            native["roleFingerprint"],
        )
        self.assertEqual(create["execution"]["generation"], native["generation"])
        self.assertEqual(create["execution"]["executionId"], native["executionId"])
        self.assertIsInstance(native["scope"], str)
        nested = json.loads(native["scope"])
        self.assertEqual(canonical(nested).decode(), native["scope"])
        self.assertEqual("PLATFORM_ADMIN", nested["registrationKind"])
        self.assertEqual("0", nested["tenantId"])
        self.assertEqual(
            {
                "approvalId": approval,
                "scopeDigest": approved["scopeDigest"],
                "authorizationRevision": 1,
                "acceptanceClaim": create["acceptanceClaim"],
            },
            nested["approvalBinding"],
        )
        self.assertEqual(self.human_subject, nested["origin"]["humanSubject"])
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "attemptId": attempt,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, consumed = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("CONSUMED", consumed["state"])
        self.assertEqual(approved["approvalReceipt"], consumed["approvalReceipt"])
        self.assertEqual(attempt, consumed["boundAttemptId"])
        wrapper = consumed["transitionReceipt"]
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
            "protected-approval-consume/v1",
            24000,
            set(wrapper) - {"receipt"},
        )
        self.assertEqual({k: v for k, v in wrapper.items() if k != "receipt"}, outer)
        self.assertEqual("protected-invitation.consume", outer["operation"])
        self.assertEqual("CONSUMED", outer["state"])
        self.assertEqual(approval, outer["approvalId"])
        self.assertEqual(approved["scopeDigest"], outer["scopeDigest"])
        self.assertEqual(attempt, outer["boundAttemptId"])
        self.assertEqual(account, outer["accountId"])
        self.assertEqual(terminal["terminalReceipt"], outer["terminalReceipt"])
        # Even a saved terminal retry must authenticate its current machine/proof,
        # then return before mutable native profile/expiry checks or account writes.
        self.admin("PUT", "/users/" + account, {"enabled": False})
        self.admin("DELETE", "/users/" + account + "/groups/" + self.protected_group_id)
        self.admin(
            "PUT",
            "/groups/" + self.protected_group_id,
            {"name": "temporarily-renamed-profile"},
        )
        try:
            status, retry = self.protected_machine_request(
                "commit", approval, commit, actor="ACCOUNT_CREATE", attempt=attempt
            )
            self.assertEqual(200, status)
            self.assertEqual(terminal, retry)
        finally:
            self.admin(
                "PUT", "/groups/" + self.protected_group_id, {"name": "platform-admins"}
            )
        self.assertFalse(self.admin("GET", "/users/" + account)["enabled"])
        self.assertEqual([], self.admin("GET", "/users/" + account + "/groups"))
        changed = copy.deepcopy(commit)
        changed["localCommit"]["outboxId"] = str(uuid.uuid4())
        self.assertEqual(
            409,
            self.protected_machine_request(
                "commit", approval, changed, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        oversized = copy.deepcopy(commit)
        oversized["creationProof"] = "a" * 16385
        self.assertEqual(
            400,
            self.protected_machine_request(
                "commit", approval, oversized, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        self.assertEqual(
            403,
            self.protected_machine_request(
                "commit", approval, commit, actor="ACCOUNT_ADMIN", attempt=attempt
            )[0],
        )
        self.assertEqual(
            (200, consumed), self.protected_machine_request("status", approval, query)
        )
        self.assertEqual(count, self.admin("GET", "/users/count"))
        self.assertFalse(self.admin("GET", "/users/" + account)["enabled"])

    def test_protected_recovery_fences_cleanup_without_adopting_original_ownership(
        self,
    ):
        approval, attempt, scope, approved, create = self.approved_creation()
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        account = opened["accountId"]
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
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], origin["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], origin["ownerSubject"])
        self.assertEqual(account, origin["accountId"])
        self.assertEqual(create["creationFingerprint"], origin["creationFingerprint"])
        self.assertEqual(
            create["acceptanceClaim"],
            origin["scope"]["approvalBinding"]["acceptanceClaim"],
        )
        before = self.admin("GET", "/users/" + account)
        self.assertFalse(before["enabled"])
        groups = self.admin("GET", "/users/" + account + "/groups")
        self.assertEqual(["/pending-provisioning"], [v["path"] for v in groups])
        count = self.admin("GET", "/users/count")
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
        original_digest = mac("protected-invitation-payload/v1", recover)
        type(self).phase = "protected-owned-admin-recover-http"
        status, claimed = self.protected_machine_request(
            "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
        )
        type(self).recover_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "sourceLiveApprovalAndCreateSucceeded": True,
            "nativePendingAccountValidated": True,
            "nativeAdminSubjectRolesAndAudiencesMatched": True,
            "originalCreatorAndAcceptanceBound": True,
            "originalRecoverDigestPredispatch": True,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before == self.admin("GET", "/users/" + account),
            "nativeMembershipUnchanged": groups
            == self.admin("GET", "/users/" + account + "/groups"),
        }
        self.assertEqual(200, status)
        self.assertEqual("RECOVERY_CLAIMED", claimed["state"])
        self.assertEqual(account, claimed["accountId"])
        self.assertEqual(opened["creationProof"], claimed["creationProof"])
        self.assertEqual(
            {"executionId": recover["recoveryId"], "generation": 1},
            claimed["execution"],
        )
        self.assertIsNone(claimed["terminalReceipt"])
        receipt = self.verified_receipt(
            claimed["recoveryReceipt"],
            "recovery-receipt",
            16000,
            {
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
            },
        )
        self.assertEqual(self.realm_id, receipt["realmId"])
        self.assertEqual(attempt, receipt["attemptId"])
        self.assertEqual(account, receipt["accountId"])
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], receipt["ownerSubject"])
        self.assertEqual(create["creationFingerprint"], receipt["creationFingerprint"])
        self.assertEqual(self.protected_group_id, receipt["groupId"])
        self.assertEqual(
            mac("protected-initial-profile/v1", self.native_configured_profiles[0]),
            receipt["roleFingerprint"],
        )
        self.assertEqual("RECOVERY_CLAIMED", receipt["state"])
        self.assertEqual("recover", receipt["operation"])
        self.assertEqual(1, receipt["generation"])
        self.assertEqual(recover["recoveryId"], receipt["executionId"])
        self.assertEqual(original_digest, receipt["commandDigest"])
        nested = json.loads(receipt["scope"])
        self.assertEqual(canonical(nested).decode(), receipt["scope"])
        self.assertEqual(origin["scope"], nested)
        self.assertEqual(
            {
                "approvalId": approval,
                "scopeDigest": approved["scopeDigest"],
                "authorizationRevision": 1,
                "acceptanceClaim": create["acceptanceClaim"],
            },
            nested["approvalBinding"],
        )
        self.assertEqual(
            (200, claimed),
            self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            ),
        )
        later = copy.deepcopy(recover)
        later.update(expectedGeneration=1, recoveryId=str(uuid.uuid4()))
        # A cleanup-only claim does not consult or grant mutable profile state.
        self.admin(
            "PUT",
            "/groups/" + self.protected_group_id,
            {"name": "temporarily-renamed-profile"},
        )
        try:
            status, second = self.protected_machine_request(
                "recover", approval, later, actor="ACCOUNT_CREATE", attempt=attempt
            )
            self.assertEqual(200, status)
            self.assertEqual(
                {"executionId": later["recoveryId"], "generation": 2},
                second["execution"],
            )
        finally:
            self.admin(
                "PUT", "/groups/" + self.protected_group_id, {"name": "platform-admins"}
            )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt
            )[0],
        )
        finish = {
            key: create[key]
            for key in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "execution",
            )
        }
        finish.update(
            accountId=account,
            creationProof=opened["creationProof"],
            localCommit={
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "b" * 64,
            },
        )
        self.assertEqual(
            409,
            self.protected_machine_request(
                "commit", approval, finish, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        finish["execution"] = second["execution"]
        self.assertEqual(
            409,
            self.protected_machine_request(
                "commit", approval, finish, actor="ACCOUNT_CREATE", attempt=attempt
            )[0],
        )
        translated = {
            "identity": {
                "scope": nested,
                "creationFingerprint": create["creationFingerprint"],
            },
            "expectedGeneration": 1,
            "recoveryId": later["recoveryId"],
        }
        controls = [
            ("wrong-purpose", {"claim_overrides": {"purpose": "INVITE_RESERVATIONS"}}),
            ("ordinary-proof-domain", {"proof_domain": "proof"}),
            ("ordinary-payload-domain", {"payload_domain": "payload"}),
            ("translated-body-proof", {"proof_body": translated}),
            ("setup-native-bearer", {"actor": "SETUP"}),
            ("mail-native-bearer", {"actor": "MAIL"}),
            ("runtime-native-bearer", {"actor": "RUNTIME"}),
        ]
        for label, options in controls:
            with self.subTest(control=label):
                status, _ = self.protected_machine_request(
                    "recover",
                    approval,
                    later,
                    attempt=attempt,
                    **{"actor": "ACCOUNT_ADMIN", **options},
                )
                type(self).recover_proof_controls.append(
                    {"control": label, "status": status}
                )
                self.assertEqual(403, status)
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
