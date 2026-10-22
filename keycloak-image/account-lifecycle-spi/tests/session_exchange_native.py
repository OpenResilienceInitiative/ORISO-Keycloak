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
from maintenance_human_fixture import HumanMaintenanceFixture

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
        self.source_app = next(client for client in source["clients"] if client["clientId"] == "app")
        source_scope_names = set(self.source_app["defaultClientScopes"]+self.source_app["optionalClientScopes"])
        source_scopes = [scope for scope in source["clientScopes"] if scope["name"] in source_scope_names]
        self.assertEqual(source_scope_names,{scope["name"] for scope in source_scopes})
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
                body = {**body, "clientScopes": source_scopes, "authenticationFlows": selected,
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
        # Authentication-relevant app configuration comes from the exact current realm source.
        app_fields = ("clientId","enabled","publicClient","standardFlowEnabled",
                      "directAccessGrantsEnabled","serviceAccountsEnabled","fullScopeAllowed",
                      "defaultClientScopes","optionalClientScopes","protocol","consentRequired",
                      "authenticationFlowBindingOverrides","attributes")
        app = {key:self.source_app[key] for key in app_fields}
        self.admin("POST", "/clients", app)
        current_app = self.admin("GET", "/clients?clientId=app")[0]
        for field in app_fields:
            expected,actual = app[field],current_app[field]
            if field == "attributes":
                # Native derived metadata is not an app authentication setting.
                actual = {key:actual.get(key) for key in expected}
            if field in {"defaultClientScopes","optionalClientScopes"}:
                expected,actual = set(expected),set(actual)
            self.assertEqual(expected,actual)
        # This setup matches HumanMaintenanceFixture's proven managed-profile preparation.
        profile = self.admin("GET", "/users/profile")
        tenant_attribute = {
            "name": "tenantId", "multivalued": False,
            "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
            "validations": {"pattern": {"pattern": "0|[1-9][0-9]{0,18}"}},
        }
        self.assertFalse(any(item["name"] == "tenantId" for item in profile["attributes"]))
        profile["attributes"].append(tenant_attribute)
        if not any(item["name"] == "locale" for item in profile["attributes"]):
            profile["attributes"].append({
                "name": "locale", "multivalued": False,
                "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]},
                "validations": {"pattern": {"pattern": "de|fr|it"}},
            })
        self.admin("PUT", "/users/profile", profile)
        current_profile = self.admin("GET", "/users/profile")
        current_tenant = [item for item in current_profile["attributes"] if item["name"] == "tenantId"]
        self.assertEqual(1,len(current_tenant))
        for field,value in tenant_attribute.items():
            self.assertEqual(value,current_tenant[0][field])
        # Reuse the already-GREEN native create/commit helpers, not an ad hoc admin-created user.
        human_profile = HumanMaintenanceFixture.reviewed_human_profile()
        attempt,creation = str(uuid.uuid4()),self.creation(kind=human_profile["kind"],group=human_profile["group"])
        status,opened = self.request("create",attempt,creation)
        self.assertEqual(201,status)
        status,committed = self.request("commit",attempt,self.finish(creation,opened))
        self.assertEqual(200,status)
        self.assertEqual("COMMITTED",committed["state"])
        target = self.admin("GET", "/users/"+opened["accountId"])
        account = creation["account"]
        for field in ("username","email","firstName","lastName"):
            self.assertEqual(account[field],target[field])
        self.assertTrue(target["enabled"])
        self.assertIsNone(target.get("serviceAccountClientLink"))
        self.assertFalse(target.get("requiredActions"))
        self.assertEqual([creation["identity"]["scope"]["tenantId"]],target["attributes"]["tenantId"])
        current_roles = self.admin("GET", "/users/"+target["id"]+"/role-mappings/realm/composite")
        self.assertEqual(set(human_profile["roles"]),{role["name"] for role in current_roles})
        groups = self.admin("GET", "/users/"+target["id"]+"/groups")
        self.assertEqual({self.group_id("/human-roles/"+human_profile["group"])},{group["id"] for group in groups})
        username,password = account["username"],account["password"]
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
                "tenantId": int(creation["identity"]["scope"]["tenantId"]), "clientId": "app", "expiresAt": int(time.time()) + 900,
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
