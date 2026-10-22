#!/usr/bin/env python3
"""One finite native SPI tracer; actor/claim are fixture inputs, not final User authority proof."""
import base64
from collections import Counter
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import unittest
from urllib.parse import quote
import uuid
import lifecycle_fixture as native

OBSERVATIONS = {
    "fixtureClaimOnly": True, "fiveActorsExact": False, "adminNoDirectGrant": False,
    "adminCannotQueryUsers": False, "ordinaryPasswordLogin": False,
    "sourceOtpExecutionsPreserved": False, "nativeRouterSelected": False,
    "commandMacValid": False, "nativeVersionPinned": False, "magicStatus": 0,
}


def proof(body, realm_id):
    now = int(time.time())
    claims = {
        "iss": "userservice", "aud": "oriso-session-exchange", "purpose": "SESSION_EXCHANGE",
        "operation": "session.magic-link.exchange", "method": "POST", "actor": "ACCOUNT_ADMIN",
        "realm": native.REALM,
        "target": "realm/" + realm_id + "/magic-link/" + body["workflowId"],
        "taskClient": "backend-account-admin", "taskSubject": native.SUBJECTS["ACCOUNT_ADMIN"],
        "payloadDigest": native.mac("magic-link-command/v1", body),
        "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 30,
    }
    encoded = base64.urlsafe_b64encode(native.canonical(claims)).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(
        native.CONTEXT_KEY, ("magic-link-proof/v1\n" + encoded).encode(), hashlib.sha256
    ).digest()).decode().rstrip("=")
    return encoded + "." + signature


class SessionExchangeNative(native.LifecycleFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Strict outer driver owns all Docker resources and the finite readiness deadline.
        cls.base = os.environ["S1_NATIVE_BASE"]
        cls.installer = os.environ["S1_INSTALLER_BEARER"]

    def setUp(self):
        source = json.loads((Path(__file__).resolve().parents[3] / "realm.json").read_text())
        aliases = {"direct-grant-2fa"}
        flows = source["authenticationFlows"]
        changed = True
        while changed:
            changed = False
            for flow in flows:
                if flow["alias"] in aliases:
                    for step in flow.get("authenticationExecutions", []):
                        alias = step.get("flowAlias")
                        if alias and alias not in aliases:
                            aliases.add(alias)
                            changed = True
        selected = [flow for flow in flows if flow["alias"] in aliases]
        self.assertEqual(aliases, {flow["alias"] for flow in selected})
        self.assertTrue(any(step.get("authenticator") == "email-authenticator"
                            for flow in selected for step in flow.get("authenticationExecutions", [])))
        self.assertTrue(any(step.get("authenticator") == "direct-grant-validate-otp"
                            for flow in selected for step in flow.get("authenticationExecutions", [])))
        original = native.call
        imported = []
        def import_only(base, method, path, body=None, token=None, form=False, proof=None):
            if method == "POST" and path == "/admin/realms":
                self.assertFalse(imported)
                imported.append(True)
                body = {**body, "authenticationFlows": selected,
                        "authenticatorConfig": source.get("authenticatorConfig", []),
                        "directGrantFlow": "direct-grant-2fa"}
            return original(base, method, path, body, token, form, proof)
        native.call = import_only
        try:
            super().setUp()
        finally:
            native.call = original
        self.assertEqual([True], imported)
        self.expected_executions = Counter((step["authenticator"], step["requirement"])
            for flow in selected for step in flow.get("authenticationExecutions", [])
            if step.get("authenticator"))
        actual = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
        self.assertEqual(self.expected_executions, Counter((step["providerId"],step["requirement"])
            for step in actual if step.get("providerId") and not step.get("authenticationFlow")))
        OBSERVATIONS["sourceOtpExecutionsPreserved"] = True

    def test_checked_claim_enters_native_session_path(self):
        status, server = native.call(self.base, "GET", "/admin/serverinfo", token=self.installer)
        self.assertEqual(200,status)
        self.assertEqual("26.6.3",server["systemInfo"]["version"])
        OBSERVATIONS["nativeVersionPinned"] = True
        self.assertEqual(5, len(native.ACTORS))
        OBSERVATIONS["fiveActorsExact"] = True
        admin_client = self.admin("GET", "/clients/" + self.client_ids["ACCOUNT_ADMIN"])
        self.assertIs(False, admin_client["directAccessGrantsEnabled"])
        OBSERVATIONS["adminNoDirectGrant"] = True
        actor = self.token("ACCOUNT_ADMIN")
        status, _ = native.call(self.base, "GET", "/admin/realms/" + native.REALM + "/users", token=actor)
        self.assertEqual(403, status)
        OBSERVATIONS["adminCannotQueryUsers"] = True
        self.admin("POST", "/clients", {
            "clientId": "app", "enabled": True, "publicClient": True,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False, "fullScopeAllowed": False,
            "defaultClientScopes": [], "optionalClientScopes": [], "protocol": "openid-connect",
        })
        username = "s1-native-" + uuid.uuid4().hex
        password = "synthetic-s1-password-" + uuid.uuid4().hex
        self.admin("POST", "/users", {
            "username": username, "enabled": True,
            "attributes": {"tenantId": ["7"]}, "groups": ["/human-roles/user"],
            "credentials": [{"type": "password", "temporary": False, "value": password}],
        })
        target = self.admin("GET", "/users?username=" + quote(username) + "&exact=true")[0]
        self.assertEqual(["7"], target["attributes"]["tenantId"])
        token_path = "/realms/" + native.REALM + "/protocol/openid-connect/token"
        status, ordinary = native.call(self.base, "POST", token_path, {
            "client_id": "app", "grant_type": "password", "username": username,
            "password": password}, form=True)
        self.assertEqual(200, status)
        self.assertTrue(ordinary.get("access_token"))
        OBSERVATIONS["ordinaryPasswordLogin"] = True
        self.admin("DELETE", "/users/" + target["id"] + "/sessions")
        self.admin("POST", "/authentication/flows/direct-grant-2fa/executions/execution",
                   {"provider": "oriso-claimed-magic-link"})
        steps = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
        router = next(step for step in steps if step.get("providerId") == "oriso-claimed-magic-link")
        self.admin("PUT", "/authentication/flows/direct-grant-2fa/executions",
                   {**router, "requirement": "REQUIRED", "priority": -1})
        for _ in range(len(steps)):
            steps = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
            if steps[0].get("providerId") == "oriso-claimed-magic-link":
                break
            self.admin("POST", "/authentication/executions/" + router["id"] + "/raise-priority")
        steps = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
        self.assertEqual("oriso-claimed-magic-link", steps[0]["providerId"])
        self.assertEqual(self.expected_executions, Counter((step["providerId"],step["requirement"])
            for step in steps if step.get("providerId") and not step.get("authenticationFlow")
            and step["providerId"] != "oriso-claimed-magic-link"))
        workflow = str(uuid.uuid4())
        body = {"version": 1, "workflowId": workflow, "targetUserId": target["id"],
                "tenantId": 7, "clientId": "app", "expiresAt": int(time.time()) + 900,
                "claimDigest": native.mac("magic-link-capability/v1", {
                    "workflowId": workflow, "token": uuid.uuid4().hex + uuid.uuid4().hex})}
        signed = proof(body, self.realm_id)
        encoded, signature = signed.split(".")
        self.assertTrue(hmac.compare_digest(
            base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
            hmac.new(native.CONTEXT_KEY, ("magic-link-proof/v1\n" + encoded).encode(), hashlib.sha256).digest()))
        OBSERVATIONS["commandMacValid"] = True
        status, reply = native.call(self.base, "POST", token_path, {
            "client_id": "app", "grant_type": "password",
            "oriso_magic_command": native.canonical(body).decode()}, actor, True, signed)
        OBSERVATIONS["magicStatus"] = status
        OBSERVATIONS["nativeRouterSelected"] = (
            isinstance(reply, dict) and reply.get("error_description") == "Claimed Magic Link session unavailable")
        self.assertEqual(200, status, "Checked native claimed-session path must issue a native session")
        self.assertTrue(reply.get("access_token"))
