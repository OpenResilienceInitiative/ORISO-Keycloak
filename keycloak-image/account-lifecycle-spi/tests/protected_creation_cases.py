"""Public protected account scenarios; the native fixture owns all setup."""

import base64
import copy
import time
import uuid
from lifecycle_fixture import ACTORS, SUBJECTS, call, mac


class ProtectedCreationCases:
    def approved_creation(self, valid_until=None):
        approval, attempt = str(uuid.uuid4()), str(uuid.uuid4())
        scope = self.scope()
        if valid_until is not None:
            scope["validUntil"] = valid_until
        status, approved = call(
            self.base,
            "PUT",
            self.endpoint(approval),
            {"scope": scope},
            self.human(record=False),
        )
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", approved["state"])
        receipt = approved["approvalReceipt"]
        self.assertEqual(approval, receipt["approvalId"])
        self.assertEqual(self.human_subject, receipt["issuerSubject"])
        self.assertEqual(approved["scopeDigest"], receipt["scopeDigest"])
        account = self.creation()["account"]
        account["email"] = scope["recipient"]
        account["username"] = "enc." + base64.b32encode(
            scope["recipient"].encode("utf-8")
        ).decode("ascii").replace("=", ".")
        create = {
            "approvalReceipt": receipt,
            "scopeDigest": approved["scopeDigest"],
            "authorizationRevision": scope["authorizationRevision"],
            "acceptanceClaim": {
                "workflowId": scope["workflowId"],
                "inviteId": scope["inviteId"],
                "authorizationRevision": scope["authorizationRevision"],
                "claimId": str(uuid.uuid4()),
                "journalVersion": 1,
            },
            "execution": {"executionId": str(uuid.uuid4()), "generation": 0},
            "account": account,
        }
        create["creationFingerprint"] = mac("protected-account-creation/v1", create)
        return approval, attempt, scope, approved, create

    def test_protected_create_binds_live_approval_to_one_disabled_pending_account(self):
        approval, attempt, scope, approved, create = self.approved_creation()
        account, receipt = create["account"], approved["approvalReceipt"]
        before = self.admin("GET", "/users/count")
        self.assertEqual(
            [],
            self.admin("GET", "/users?username=" + account["username"] + "&exact=true"),
        )
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        after = self.admin("GET", "/users/count")
        type(self).create_observation = {
            "actualStatus": status,
            "expectedStatus": 201,
            "sourceLiveApprovalCreated": True,
            "exactHumanReceiptBound": True,
            "originalAcceptanceAndAccountFingerprintPredispatch": True,
            "nativeCreatorSubjectRolesAndAudiencesMatched": True,
            "nativeConfigurationChecked": self.configuration_checked,
            "noAccountBeforeDispatch": True,
            "noAccountCreated": before == after,
            "oneAccountCreated": after == before + 1,
        }
        self.assertEqual(201, status)
        self.assertEqual(before + 1, after)
        self.assertEqual("OPEN", opened["state"])
        self.assertEqual(create["execution"], opened["execution"])
        account_id = opened["accountId"]
        self.assertEqual(account_id, str(uuid.UUID(account_id)))
        self.assertTrue(opened["creationProof"])
        self.assertIsNone(opened["terminalReceipt"])
        native = self.admin("GET", "/users/" + account_id)
        self.assertFalse(native["enabled"])
        self.assertTrue(native["emailVerified"])
        self.assertEqual(account["email"], native["email"])
        self.assertEqual(account["username"].lower(), native["username"])
        self.assertEqual(
            ["/pending-provisioning"],
            [v["path"] for v in self.admin("GET", "/users/" + account_id + "/groups")],
        )
        self.assertEqual(
            [], self.admin("GET", "/users/" + account_id + "/role-mappings/realm")
        )
        credentials = self.admin("GET", "/users/" + account_id + "/credentials")
        self.assertEqual(["password"], [v["type"] for v in credentials])
        status, retry = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(200, status)
        self.assertEqual(opened, retry)
        self.assertEqual(native, self.admin("GET", "/users/" + account_id))
        self.assertEqual(
            credentials, self.admin("GET", "/users/" + account_id + "/credentials")
        )
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": scope["authorizationRevision"],
            "attemptId": attempt,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, bound = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("BOUND", bound["state"])
        self.assertEqual(attempt, bound["boundAttemptId"])
        self.assertEqual(receipt, bound["approvalReceipt"])
        self.assertEqual(after, self.admin("GET", "/users/count"))

    def test_protected_owned_read_requires_exact_receipt_and_original_wire_proof(self):
        approval, attempt, scope, approved, create = self.approved_creation()
        status, opened = self.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        before = self.admin("GET", "/users/" + opened["accountId"])
        self.assertFalse(before["enabled"])
        self.assertEqual(
            ["/pending-provisioning"],
            [
                v["path"]
                for v in self.admin("GET", "/users/" + opened["accountId"] + "/groups")
            ],
        )
        count = self.admin("GET", "/users/count")
        read = {
            key: create[key]
            for key in (
                "approvalReceipt",
                "scopeDigest",
                "authorizationRevision",
                "creationFingerprint",
                "execution",
            )
        }
        read.update(
            {"accountId": opened["accountId"], "creationProof": opened["creationProof"]}
        )
        status, projection = self.protected_machine_request(
            "owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt
        )
        type(self).read_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "sourceLiveApprovalAndCreateSucceeded": True,
            "nativePendingAccountValidated": True,
            "nativeCreatorSubjectRolesAndAudiencesMatched": True,
            "exactStoredApprovalAndCreationProof": True,
            "accountCountUnchanged": count == self.admin("GET", "/users/count"),
            "nativeAccountUnchanged": before
            == self.admin("GET", "/users/" + opened["accountId"]),
        }
        self.assertEqual(200, status)
        self.assertEqual(
            {
                "id",
                "username",
                "email",
                "firstName",
                "lastName",
                "tenantId",
                "preferredLanguage",
                "enabled",
                "emailVerified",
                "effectiveRoles",
                "passwordChangeRequired",
            },
            set(projection),
        )
        self.assertEqual(opened["accountId"], projection["id"])
        self.assertEqual(create["account"]["email"], projection["email"])
        self.assertEqual("0", projection["tenantId"])
        self.assertFalse(projection["enabled"])
        self.assertTrue(projection["emailVerified"])
        self.assertEqual([], projection["effectiveRoles"])
        translated = {
            "identity": {
                "scope": {
                    "tenantId": "0",
                    "registrationKind": "PLATFORM_ADMIN",
                    "initialGroup": "/protected-admins/platform-admins",
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
                        "scopeDigest": create["scopeDigest"],
                        "authorizationRevision": 1,
                        "acceptanceClaim": create["acceptanceClaim"],
                    },
                },
                "creationFingerprint": create["creationFingerprint"],
            },
            "execution": read["execution"],
            "accountId": read["accountId"],
            "creationProof": read["creationProof"],
        }
        controls = [
            (
                "wrong-purpose",
                read,
                {"claim_overrides": {"purpose": "INVITE_RESERVATIONS"}},
            ),
            ("translated-body-proof", read, {"proof_body": translated}),
            (
                "wrong-target",
                read,
                {
                    "claim_overrides": {
                        "target": "realm/"
                        + self.realm_id
                        + "/protected-invitation/"
                        + str(uuid.uuid4())
                        + "/account-attempt/"
                        + attempt
                    }
                },
            ),
            (
                "wrong-native-subject",
                read,
                {"claim_overrides": {"taskSubject": SUBJECTS["SETUP"]}},
            ),
            ("ordinary-proof-domain", read, {"proof_domain": "proof"}),
            ("ordinary-payload-domain", read, {"payload_domain": "payload"}),
            (
                "expired-proof",
                read,
                {
                    "claim_overrides": {
                        "iat": int(time.time()) - 61,
                        "exp": int(time.time()) - 1,
                    }
                },
            ),
        ]
        for field, value in [
            ("accountId", str(uuid.uuid4())),
            (
                "creationProof",
                read["creationProof"][:-1]
                + ("a" if read["creationProof"][-1] != "a" else "b"),
            ),
            ("scopeDigest", "0" * 64),
        ]:
            changed = copy.deepcopy(read)
            changed[field] = value
            controls.append(("changed-" + field, changed, {}))
        changed = copy.deepcopy(read)
        changed["approvalReceipt"]["issuerSubject"] = str(uuid.uuid4())
        controls.append(("changed-human-receipt", changed, {}))
        changed = copy.deepcopy(read)
        changed["accountId"] = str(uuid.uuid4())
        controls.append(
            ("original-proof-different-wire-body", changed, {"proof_body": read})
        )
        for actor in ("ACCOUNT_ADMIN", "SETUP", "MAIL", "RUNTIME"):
            controls.append(("wrong-native-actor-" + actor, read, {"actor": actor}))
        self.assertEqual(16, len(controls))
        for label, body, options in controls:
            with self.subTest(control=label):
                options = {"actor": "ACCOUNT_CREATE", **options}
                status, _ = self.protected_machine_request(
                    "owned-read", approval, body, attempt=attempt, **options
                )
                type(self).read_proof_controls.append(
                    {"control": label, "status": status}
                )
                self.assertEqual(403, status)
        self.assertEqual(before, self.admin("GET", "/users/" + opened["accountId"]))
        self.assertEqual(count, self.admin("GET", "/users/count"))
