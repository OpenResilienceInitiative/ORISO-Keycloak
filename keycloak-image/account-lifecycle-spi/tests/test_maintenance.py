#!/usr/bin/env python3
"""Real bounded maintenance HTTP gates. Fixture absence is an error, never a skip.

These tests exercise receiver trust in a UserService-checked scheduled workflow.
They do not establish the separately required UserService domain checks.
"""
import base64
import hashlib
import hmac
import time
import unittest
import uuid

from maintenance_human_fixture import HumanMaintenance

from lifecycle_fixture import (
    ACTORS, SUBJECTS, REALM, CONTEXT_KEY, LifecycleFixture, call, canonical, mac,
)


class MaintenancePermissions(LifecycleFixture, unittest.TestCase):
    # Sanitized phase receipts distinguish setup errors from the intended native RED.
    phase_receipts = []

    @classmethod
    def setUpClass(cls):
        cls.phase_receipts = []
        super().setUpClass()

    def setUp(self):
        # Installer grants are short-lived; refresh through the real native login per method.
        self.ready()
        super().setUp()

    def phase(self, phase, **details):
        self.phase_receipts.append({"case": self.id(), "phase": phase, **details})

    def committed(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        status, saved = self.request("commit", attempt, self.finish(create, opened))
        self.assertEqual(200, status)
        self.phase("ordinary-committed", create_status=201, commit_status=200)
        return opened["accountId"], create

    def maintenance(self, command, account_id, body, actor="ACCOUNT_ADMIN", changes=None, expected_status=200, bearer=None):
        now = int(time.time())
        claims = {
            "iss": "userservice", "aud": "oriso-account-maintenance",
            "purpose": "ACCOUNT_MAINTENANCE", "operation": "account." + command,
            "method": "POST", "actor": actor, "realm": REALM,
            "target": "realm/" + self.realm_id + "/account/" + account_id,
            "taskClient": ACTORS[actor][0], "taskSubject": SUBJECTS[actor],
            "payloadDigest": mac("payload", body), "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60,
        }
        claims.update(changes or {})
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(
            hmac.new(CONTEXT_KEY, ("proof\n" + encoded).encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        response = call(self.base, "POST", "/realms/" + REALM
                    + "/oriso-account-maintenance/v1/accounts/" + account_id + "/" + command,
                    body, bearer or self.token(actor), proof=encoded + "." + signature)
        self.phase("maintenance-http", command=command, actor=actor,
                   method="POST", status=response[0], expected_status=expected_status)
        return response

    @staticmethod
    def target(account_id, create):
        return {
            "accountId": account_id, "tenantId": create["identity"]["scope"]["tenantId"],
            "origin": {"kind": "DELETION", "workflowId": "hard-delete:" + account_id,
                       "humanSubject": None, "humanIssuer": None,
                       "humanClient": None, "humanAuthority": None},
        }

    def test_admin_reads_exact_deletion_target_without_any_native_user_powers(self):
        account_id, create = self.committed()
        bearer = self.token("ACCOUNT_ADMIN")
        ordinary_role = self.admin("GET", "/roles/user")
        for operation, method, suffix, payload in [
            ("read", "GET", "", None),
            ("profile", "PUT", "", {"enabled": False}),
            ("password", "PUT", "/reset-password", {"type": "password", "value": "forbidden"}),
            ("roles", "POST", "/role-mappings/realm", [ordinary_role]),
            ("membership", "PUT", "/groups/" + self.group_id("/human-roles/user"), None),
            ("delete", "DELETE", "", None),
        ]:
            status, _ = call(self.base, method, "/admin/realms/" + REALM
                            + "/users/" + account_id + suffix, payload, bearer)
            self.assertEqual(403, status)
            self.phase("stock-native-denied", operation=operation, method=method, status=status)
        # Reuse that exact bearer for the bounded positive, even in the initial RED.
        status, result = self.maintenance("read", account_id,
            {"target": self.target(account_id, create)}, bearer=bearer)
        self.assertEqual(200, status)
        self.assertEqual(account_id, result["id"])
        self.assertRegex(result["state"], r"^[a-f0-9]{64}$")
        self.assertFalse({"attributes", "credentials", "serviceAccountClientLink"} & set(result))

    def test_delete_retry_returns_saved_receipt_and_never_removes_reused_identity(self):
        account_id, create = self.committed()
        target = self.target(account_id, create)
        status, before = self.maintenance("read", account_id, {"target": target})
        self.assertEqual(200, status)
        command = {"target": target, "operationId": str(uuid.uuid4()),
                   "expectedState": before["state"], "change": {}}
        status, receipt = self.maintenance("delete", account_id, command)
        self.assertEqual(200, status)
        self.assertEqual("DELETED", receipt["result"])
        replacement = {"id": account_id, "username": "replacement-" + uuid.uuid4().hex,
                       "enabled": True}
        self.admin("POST", "/partialImport", {"ifResourceExists": "FAIL", "users": [replacement]})
        status, repeated = self.maintenance("delete", account_id, command)
        self.assertEqual((200, receipt), (status, repeated))
        self.assertEqual(replacement["username"], self.admin("GET", "/users/" + account_id)["username"])

    def test_stale_target_state_refuses_delete_after_installer_profile_change(self):
        account_id, create = self.committed()
        target = self.target(account_id, create)
        status, before = self.maintenance("read", account_id, {"target": target})
        self.assertEqual(200, status)
        self.admin("PUT", "/users/" + account_id, {"firstName": "new installer name"})
        command = {"target": target, "operationId": str(uuid.uuid4()),
                   "expectedState": before["state"], "change": {}}
        self.assertEqual(409, self.maintenance("delete", account_id, command, expected_status=409)[0])
        self.assertEqual("new installer name", self.admin("GET", "/users/" + account_id)["firstName"])

    def test_other_four_actors_and_mismatched_proofs_cannot_read_target(self):
        account_id, create = self.committed()
        body = {"target": self.target(account_id, create)}
        for actor in ["SETUP", "ACCOUNT_CREATE", "MAIL", "RUNTIME"]:
            self.assertEqual(403, self.maintenance("read", account_id, body, actor=actor, expected_status=403)[0])
        for changed in [{"purpose": "OTP"}, {"aud": "oriso-otp"},
                        {"method": "PUT"}, {"target": "realm/foreign/account/" + account_id},
                        {"payloadDigest": "0" * 64}, {"exp": int(time.time()) - 1}]:
            self.assertEqual(403, self.maintenance("read", account_id, body, changes=changed, expected_status=403)[0])

    def test_foreign_tenant_and_pending_or_technical_target_deny(self):
        account_id, create = self.committed()
        target = self.target(account_id, create)
        target["tenantId"] = "999"
        self.assertEqual(403, self.maintenance("read", account_id, {"target": target}, expected_status=403)[0])
        target = self.target(SUBJECTS["ACCOUNT_ADMIN"], create)
        self.assertEqual(403, self.maintenance("read", SUBJECTS["ACCOUNT_ADMIN"], {"target": target}, expected_status=403)[0])
        attempt, pending = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, pending)
        self.assertEqual(201, status)
        self.assertEqual(403, self.maintenance("read", opened["accountId"],
            {"target": self.target(opened["accountId"], pending)}, expected_status=403)[0])


if __name__ == "__main__":
    unittest.main()
